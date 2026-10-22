/*
 * Copyright (c) 2026 Daniel de Jager
 * All rights reserved.
 *
 * Defence-in-depth process hardening for honeyd (#16).
 * Licensed under the GNU General Public License, version 2.
 */
#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include <sys/types.h>

/* Called by cmd_droppriv() while still privileged: empty the capability
 * bounding and ambient sets so nothing exec'd later can regain caps. */
void sandbox_drop_caps_pre(void);

/* Called by cmd_droppriv() after setres[ug]id(): set no_new_privs and
 * verify that no capabilities and no saved root IDs remain.  Fatal on
 * failure.  Returns 0. */
int sandbox_verify_post(uid_t uid, gid_t gid);

/* Opt-in (--sandbox-scripts): restrict a script/subsystem child just
 * before exec.  argv is the command about to be exec'd; absolute paths in
 * it are allowed read/exec.  Best-effort for features the kernel lacks. */
void sandbox_script(char * const argv[]);

/* --sandbox-allow-write=DIR (repeatable) */
int sandbox_add_write_path(const char *path);
int sandbox_path_broad(const char *path);

extern int honeyd_sandbox_scripts;

/* --sandbox-daemon: seccomp allowlist for the daemon (sandbox_daemon.c) */
int sandbox_daemon(void);

extern int honeyd_sandbox_daemon;

/* --sandbox-daemon: Landlock for the daemon.  Collect the paths and TCP
 * connect ports first (port -1: any), then apply once, before the
 * seccomp filter.  Degrades to a logged warning without Landlock. */
void sandbox_daemon_allow_read(const char *path);
void sandbox_daemon_allow_write(const char *path);
void sandbox_daemon_allow_connect(int port);
int sandbox_daemon_landlock(void);

/* --sandbox-scripts: per-script namespaces (sandbox_ns.c) */
void sandbox_ns_start(void);
void sandbox_ns_exec(const char *execcmd, char * const argv[], uid_t uid,
    gid_t gid, int nofiles);
/* set in a script child that has its own private /tmp */
extern int sandbox_script_private_tmp;
/* the daemon's allowlist in a script started by the launcher, quietly */
int sandbox_daemon_child(void);
int sandbox_launcher_seccomp(void);
int sandbox_write_paths(const char * const **);
int sandbox_script_root(char * const argv[]);

/* the exec'd launcher (PATH_HONEYDLIB/pm-script-ns): its main(), and
 * passing the sandbox settings to it */
#define SANDBOX_LAUNCHER	"pm-script-ns"
int sandbox_ns_main(int argc, char **argv);
int sandbox_state_argv(char **argv, int max, char *ports, size_t plen);
int sandbox_state_parse(int argc, char **argv);

#endif /* _SANDBOX_H_ */
