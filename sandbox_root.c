/*
 * Copyright (c) 2026 Daniel de Jager
 * All rights reserved.
 *
 * --sandbox-scripts: a minimal read-only root for each script (#16).
 *
 * Called by the launcher (sandbox_ns.c) in the script's pid 1, inside
 * its new user and mount namespaces, before Landlock, the seccomp
 * filters and the exec.  A tmpfs on /tmp becomes the new root; into it
 * go read-only bind mounts of only what scripts need:
 *
 *   /usr/bin /usr/sbin /usr/lib* (interpreters, tools, libraries, the
 *   Python stdlib), /usr/share/perl* (Perl modules), the top-level
 *   bin/sbin/lib* symlinks or dirs, the data dir, the working directory
 *   and the directory of every absolute path in argv (the script dir),
 *   /etc/ld.so.cache and /etc/alternatives,
 *
 * plus a synthetic /etc/{passwd,group,hosts}, /dev/{null,zero,random,
 * urandom}, a fresh /proc when the kernel allows it, a private /tmp and
 * the --sandbox-allow-write dirs (read-write). Then pivot_root(2) and the
 * old root is detached: no host /etc, /home, /root, /var or /run.
 *
 * Licensed under the GNU General Public License, version 2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "sandbox.h"

#ifdef __linux__
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

#define NR	"/tmp"		/* where the new root is built */

static int
rt_mkdirs(const char *path)	/* mkdir -p NR/path */
{
	char p[PATH_MAX];
	size_t i;

	if (snprintf(p, sizeof(p), NR "%s", path) >= (int)sizeof(p))
		return (-1);
	for (i = strlen(NR) + 1; p[i] != '\0'; i++)
		if (p[i] == '/') {
			p[i] = '\0';
			if (mkdir(p, 0755) == -1 && errno != EEXIST)
				return (-1);
			p[i] = '/';
		}
	if (mkdir(p, 0755) == -1 && errno != EEXIST)
		return (-1);
	return (0);
}

static int
rt_touch(const char *path)
{
	char p[PATH_MAX], *s;
	int fd;

	snprintf(p, sizeof(p), "%s", path);
	if ((s = strrchr(p, '/')) != NULL && s != p) {
		*s = '\0';
		if (rt_mkdirs(p) == -1)
			return (-1);
	}
	snprintf(p, sizeof(p), NR "%s", path);
	if ((fd = open(p, O_WRONLY | O_CREAT | O_CLOEXEC, 0644)) == -1)
		return (-1);
	close(fd);
	return (0);
}

static int
rt_file(const char *path, const char *content)
{
	char p[PATH_MAX];
	int fd;
	size_t l = strlen(content);

	snprintf(p, sizeof(p), NR "%s", path);
	if ((fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		    0644)) == -1)
		return (-1);
	if (write(fd, content, l) != (ssize_t)l) {
		close(fd);
		return (-1);
	}
	return (close(fd));
}

/*
 * Bind src at the same path in the new root. Missing sources are
 * skipped. Read-only unless rw; the flags the source mount already has
 * (and that a user namespace may not clear) are kept.
 */
static int
rt_bind_at(const char *src, const char *path, int rw)
{
	char dst[PATH_MAX];
	struct stat st;
	struct statvfs sv;
	unsigned long fl = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV;

	if (stat(src, &st) == -1)
		return (0);
	if (snprintf(dst, sizeof(dst), NR "%s", path) >= (int)sizeof(dst))
		return (-1);
	if (S_ISDIR(st.st_mode)) {
		if (rt_mkdirs(path) == -1)
			return (-1);
	} else if (rt_touch(path) == -1)
		return (-1);
	if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) == -1)
		return (-1);
	if (statvfs(src, &sv) == 0) {
		if (sv.f_flag & ST_NOEXEC)
			fl |= MS_NOEXEC;
		if (sv.f_flag & ST_RDONLY)
			rw = 0;
	}
	if (!rw)
		fl |= MS_RDONLY;
	return (mount(NULL, dst, NULL, fl, NULL));
}

static int
rt_bind(const char *src, int rw)
{
	return (rt_bind_at(src, src, rw));
}

/* bin, lib, ...: a symlink like the host's (merged /usr), or a bind */
static int
rt_top(const char *path)
{
	char p[PATH_MAX], l[PATH_MAX];
	ssize_t n;

	if ((n = readlink(path, l, sizeof(l) - 1)) >= 0) {
		l[n] = '\0';
		snprintf(p, sizeof(p), NR "%s", path);
		return (symlink(l, p) == -1 && errno != EEXIST ? -1 : 0);
	}
	return (rt_bind(path, 0));
}

/* bind a device node (the tmpfs of a user namespace is nodev) */
static int
rt_dev(const char *path)
{
	char dst[PATH_MAX];

	if (rt_touch(path) == -1)
		return (-1);
	snprintf(dst, sizeof(dst), NR "%s", path);
	return (mount(path, dst, NULL, MS_BIND, NULL));
}

int
sandbox_script_root(char * const argv[])
{
	static const char *ro[] = {
		"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32",
		"/usr/lib64", "/usr/libx32", "/usr/libexec",
		"/usr/share/perl", "/usr/share/perl5",
		"/etc/ld.so.cache", "/etc/alternatives",
		PATH_HONEYDDATA, NULL
	};
	static const char *top[] = {
		"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", NULL
	};
	static const char *dev[] = {
		"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", NULL
	};
	const char * const *wp;
	char cwd[PATH_MAX], dir[PATH_MAX], buf[512], *s;
	int i, nw, havecwd;
	const char *what = "tmpfs";

#define TRY(x, w) do { what = (w); if ((x) == -1) goto fail; } while (0)
	havecwd = getcwd(cwd, sizeof(cwd)) != NULL;
	TRY(mount("tmpfs", NR, "tmpfs", MS_NOSUID | MS_NODEV,
	    "mode=0755,size=4m"), "tmpfs root");
	for (i = 0; ro[i] != NULL; i++)
		TRY(rt_bind(ro[i], 0), ro[i]);
	for (i = 0; top[i] != NULL; i++)
		TRY(rt_top(top[i]), top[i]);
	/* the script dir(s) and the working directory (relative paths) */
	for (i = 0; argv != NULL && argv[i] != NULL; i++) {
		struct stat st;

		if (argv[i][0] != '/' || stat(argv[i], &st) == -1 ||
		    !S_ISREG(st.st_mode))
			continue;
		snprintf(dir, sizeof(dir), "%s", argv[i]);
		if ((s = strrchr(dir, '/')) != NULL && s != dir) {
			*s = '\0';
			TRY(rt_bind(dir, 0), dir);
		}
	}
	if (havecwd && strcmp(cwd, "/") != 0 && strncmp(cwd, "/tmp", 4) != 0)
		/* via ".": its parents may not be searchable for us */
		TRY(rt_bind_at(".", cwd, 0), cwd);
	nw = sandbox_write_paths(&wp);
	for (i = 0; i < nw; i++)
		TRY(rt_bind(wp[i], 1), wp[i]);

	TRY(rt_mkdirs("/etc"), "/etc");
	snprintf(buf, sizeof(buf), "root:x:0:0:root:/:/bin/sh\n"
	    "nobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n"
	    "script:x:%u:%u:script:/tmp:/bin/sh\n",
	    (unsigned)getuid(), (unsigned)getgid());
	TRY(rt_file("/etc/passwd", buf), "/etc/passwd");
	snprintf(buf, sizeof(buf), "root:x:0:\nnogroup:x:65534:\n"
	    "script:x:%u:\n", (unsigned)getgid());
	TRY(rt_file("/etc/group", buf), "/etc/group");
	TRY(rt_file("/etc/hosts", "127.0.0.1\tlocalhost\n"
	    "::1\tlocalhost ip6-localhost ip6-loopback\n"), "/etc/hosts");
	TRY(rt_mkdirs("/dev"), "/dev");
	for (i = 0; dev[i] != NULL; i++)
		TRY(rt_dev(dev[i]), dev[i]);
	TRY(rt_mkdirs("/tmp"), "/tmp");
	TRY(mount("tmpfs", NR "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
	    "mode=1777,size=64m"), "private /tmp");
	TRY(rt_mkdirs("/proc"), "/proc");
	/* our own /proc (we are pid 1 of a new PID namespace); refused
	 * where the host's /proc has masked paths, then scripts go without */
	(void)mount("proc", NR "/proc", "proc",
	    MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	TRY(mount(NULL, NR, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID |
	    MS_NODEV, "mode=0755,size=4m"), "read-only root");

	TRY(chdir(NR), "chdir");
	TRY(syscall(SYS_pivot_root, ".", "."), "pivot_root");
	TRY(umount2(".", MNT_DETACH), "detach old root");
	if (!havecwd || chdir(cwd) == -1)
		TRY(chdir("/"), "chdir /");
	return (0);
fail:
	syslog(LOG_ERR, "sandbox: read-only root: %s: %m", what);
	return (-1);
#undef TRY
}
#else
int
sandbox_script_root(char * const argv[])
{
	errno = ENOSYS;
	return (-1);
}
#endif /* __linux__ */
