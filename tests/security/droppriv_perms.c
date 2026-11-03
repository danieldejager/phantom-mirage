/*
 * PM-SCR-115: cmd_droppriv() only noted a setgroups() failure and went
 * on, so a subsystem could keep its supplementary groups. Run as non
 * root, setgroups() fails with EPERM and cmd_droppriv() must exit.
 *
 * PM-SCR-118: pyextend_webserver_fix_permissions() created graphs/
 * with mode 0722, skipped every regular file (st_mode & S_IFLNK is true
 * for S_IFREG) and followed type tests that matched sockets. It now
 * creates graphs/ 0750, fixes regular files and never acts through a
 * symbolic link.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void cmd_droppriv(uid_t, gid_t);
pid_t __real_fork(void);	/* fork is wrapped by cc_daemon */
void pyextend_webserver_fix_permissions(const char *, uid_t, gid_t);

static int fail;

static void
check_mode(const char *path, mode_t want)
{
	struct stat sb;

	if (lstat(path, &sb) == -1) {
		printf("%s: missing\n", path);
		fail = 1;
		return;
	}
	printf("%s: %04o (want %04o)\n", strrchr(path, '/') + 1,
	    (unsigned)(sb.st_mode & 07777), (unsigned)want);
	if ((sb.st_mode & 07777) != want)
		fail = 1;
}

int
main(void)
{
	char root[] = "/tmp/pm-fixpermXXXXXX", p[256], out[256];
	int status, fd;
	pid_t pid;

	/* PM-SCR-115 */
	if (geteuid() == 0) {
		printf("droppriv: skipped, needs a non root user\n");
	} else if ((pid = __real_fork()) == 0) {
		cmd_droppriv(getuid(), getgid());
		_exit(0);		/* returned: groups not dropped */
	} else {
		waitpid(pid, &status, 0);
		printf("droppriv as non root: %s\n",
		    WIFEXITED(status) && WEXITSTATUS(status) != 0 ?
		    "aborted" : "continued");
		if (!WIFEXITED(status) || WEXITSTATUS(status) == 0)
			fail = 1;
	}

	/* PM-SCR-118 */
	umask(022);
	if (mkdtemp(root) == NULL)
		return (1);
	snprintf(p, sizeof(p), "%s/page.html", root);
	fd = open(p, O_CREAT|O_WRONLY, 0644);
	close(fd);
	chmod(p, 0666);
	snprintf(p, sizeof(p), "%s/sub", root);
	mkdir(p, 0755);
	chmod(p, 0777);
	snprintf(out, sizeof(out), "%s.outside", root);
	fd = open(out, O_CREAT|O_WRONLY, 0644);
	close(fd);
	chmod(out, 0666);
	snprintf(p, sizeof(p), "%s/sub/link", root);
	if (symlink(out, p) == -1)
		return (1);

	pyextend_webserver_fix_permissions(root, getuid(), getgid());

	snprintf(p, sizeof(p), "%s/graphs", root);
	check_mode(p, 0750);
	snprintf(p, sizeof(p), "%s/page.html", root);
	check_mode(p, 0664);
	snprintf(p, sizeof(p), "%s/sub", root);
	check_mode(p, 0775);
	check_mode(out, 0666);		/* link target untouched */

	snprintf(p, sizeof(p), "rm -rf %s %s", root, out);
	if (system(p) != 0)
		fail = 1;
	if (fail)
		printf("FAIL\n");
	return (fail);
}
