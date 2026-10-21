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

extern int honeyd_sandbox_scripts;

#endif /* _SANDBOX_H_ */
