/*
 * PM-SCR-115: cmd_droppriv() only noted a setgroups() failure and went
 * on, so a subsystem could keep its supplementary groups. Run as non
 * root, setgroups() fails with EPERM. If any supplementary group is not
 * the target gid, cmd_droppriv() must exit. If the list is already only
 * that gid (the script child, after the daemon dropped), it must return.
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
#include <grp.h>
#include <pwd.h>

void cmd_droppriv(uid_t, gid_t);
pid_t __real_fork(void);	/* fork is wrapped by cc_daemon */
void pyextend_webserver_fix_permissions(const char *, uid_t, gid_t);

static int fail;

/* 1 when some supplementary group is not gid (or the list cannot be read). */
static int
suppl_dirty(gid_t gid)
{
	gid_t *g;
	int n, i;

	n = getgroups(0, NULL);
	if (n < 0)
		return (1);
	if (n == 0)
		return (0);
	g = calloc((size_t)n, sizeof(*g));
	if (g == NULL)
		return (1);
	if (getgroups(n, g) != n) {
		free(g);
		return (1);
	}
	for (i = 0; i < n; i++) {
		if (g[i] != gid) {
			free(g);
			return (1);
		}
	}
	free(g);
	return (0);
}

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

	/* PM-SCR-115, and the script-child re-entry after a drop */
	if (geteuid() == 0) {
		struct passwd *pw = getpwnam("nobody");
		uid_t uid = pw != NULL ? pw->pw_uid : 65534;
		gid_t gid = pw != NULL ? pw->pw_gid : 65534;
		gid_t extra[2];

		/* Groups already only the target: the second drop returns. */
		if ((pid = __real_fork()) == 0) {
			if (setgroups(1, &gid) == -1 ||
			    setresgid(gid, gid, gid) == -1 ||
			    setresuid(uid, uid, uid) == -1)
				_exit(2);
			cmd_droppriv(uid, gid);
			_exit(0);
		}
		waitpid(pid, &status, 0);
		printf("droppriv re-entry: %s\n",
		    WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
		    "continued" : "aborted");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			fail = 1;

		/* An extra supplementary group that setgroups cannot clear. */
		extra[0] = gid;
		extra[1] = gid == 0 ? 1 : 0;
		if ((pid = __real_fork()) == 0) {
			if (setgroups(2, extra) == -1 ||
			    setresgid(gid, gid, gid) == -1 ||
			    setresuid(uid, uid, uid) == -1)
				_exit(2);
			cmd_droppriv(uid, gid);
			_exit(0);		/* returned: extra group kept */
		}
		waitpid(pid, &status, 0);
		printf("droppriv extra group: %s\n",
		    WIFEXITED(status) && WEXITSTATUS(status) != 0 ?
		    "aborted" : "continued");
		if (!WIFEXITED(status) || WEXITSTATUS(status) == 0)
			fail = 1;
	} else if ((pid = __real_fork()) == 0) {
		cmd_droppriv(getuid(), getgid());
		_exit(0);
	} else {
		int dirty = suppl_dirty(getgid());

		waitpid(pid, &status, 0);
		printf("droppriv as non root (extra groups=%d): %s\n", dirty,
		    WIFEXITED(status) && WEXITSTATUS(status) != 0 ?
		    "aborted" : "continued");
		if (!WIFEXITED(status))
			fail = 1;
		else if (dirty && WEXITSTATUS(status) == 0)
			fail = 1;
		else if (!dirty && WEXITSTATUS(status) != 0)
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
