/*
 * PM-SCR-242: ns_run() ignored the result of sethostname(2) in the new
 * UTS namespace (CWE-252) and went on to run the script with the host's
 * hostname. It must fail closed, like the mount(2) before it.
 *
 * sandbox_ns.c is compiled in with sethostname() replaced by a stub that
 * fails with EPERM. The rest of sandbox_ns.c's callees are stubs too:
 * The fake sethostname() records that it was called, so a child that
 * fails earlier (id maps, mounts, rlimits, AppArmor) fails the test, and
 * sandbox_script_root() records that ns_run() got past sethostname().
 * Needs unprivileged user namespaces: "--probe" exits 77 without them
 * (or with NS_SETHOSTNAME_NO_USERNS set) and the .test file skips.
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fake_sethostname(const char *name, size_t len);
#define sethostname fake_sethostname
#include "../../sandbox_ns.c"
#undef sethostname

static int marker[2] = { -1, -1 };

static int
fake_sethostname(const char *name, size_t len)
{
	(void)name;
	(void)len;
	(void)!write(marker[1], "H", 1);
	errno = EPERM;
	return (-1);
}

int sandbox_script_private_tmp;
int honeyd_sandbox_scripts;
void cmd_droppriv(uid_t uid, gid_t gid) { (void)uid; (void)gid; }
int sandbox_daemon_child(void) { return (0); }
int sandbox_launcher_seccomp(void) { return (0); }
int sandbox_state_argv(char **argv, int max, char *ports, size_t plen)
{ (void)argv; (void)max; (void)ports; (void)plen; return (0); }
int sandbox_state_parse(int argc, char **argv)
{ (void)argc; (void)argv; return (0); }
void sandbox_script(char * const argv[]) { (void)argv; }

int
sandbox_script_root(char * const argv[])
{
	(void)argv;
	/* past sethostname(): tell the test, then stop before any exec */
	(void)!write(marker[1], "R", 1);
	return (-1);
}

int
main(int argc, char **argv)
{
	struct { struct ns_req r; char s[32]; } req;
	char c, seen[8];
	pid_t pid;
	int status, devnull, called = 0, reached = 0;
	ssize_t n, j;

	if (argc > 1 && strcmp(argv[1], "--probe") == 0) {
		if (getenv("NS_SETHOSTNAME_NO_USERNS") != NULL)
			return (77);
		/* the same namespaces ns_run() asks for, in a child */
		if ((pid = fork()) == 0)
			_exit(unshare(CLONE_NEWUSER | CLONE_NEWNS |
			    CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS |
			    CLONE_NEWNET) == 0 ? 0 : 1);
		if (pid == -1 || waitpid(pid, &status, 0) == -1 ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			return (77);
		return (0);
	}

	if (pipe(marker) == -1 || (devnull = open("/dev/null", O_RDWR)) == -1)
		return (2);
	memset(&req, 0, sizeof(req));
	req.r.magic = NS_MAGIC;
	req.r.uid = geteuid();
	req.r.gid = getegid();
	req.r.nofiles = 64;
	strcpy(req.s, "/bin/true");

	if ((pid = fork()) == -1)
		return (2);
	if (pid == 0) {
		close(marker[0]);
		ns_run(&req.r, req.s, devnull, devnull, 1);
		_exit(0);
	}
	close(marker[1]);
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;
	(void)c;
	while ((n = read(marker[0], seen, sizeof(seen))) > 0)
		for (j = 0; j < n; j++) {
			called |= seen[j] == 'H';
			reached |= seen[j] == 'R';
		}
	if (!called) {
		fprintf(stderr, "FAIL: ns_run failed before sethostname "
		    "(status %#x)\n", status);
		return (1);
	}
	if (reached) {
		fprintf(stderr, "FAIL: script set up after sethostname "
		    "failed\n");
		return (1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_FAILURE) {
		fprintf(stderr, "FAIL: ns_run did not exit with failure "
		    "(status %#x)\n", status);
		return (1);
	}
	printf("ns_sethostname: ok\n");
	return (0);
}
