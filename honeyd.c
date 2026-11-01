/*
 * Copyright (c) 2002, 2003, 2004, 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <pcap.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <assert.h>

#undef timeout_pending
#undef timeout_initialized

#include <dnet.h>
#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "personality.h"

struct event_base *libevent_base;
#include "xprobe_assoc.h"
#include "ipfrag.h"
#include "router.h"
#include "network.h"
#include "tcp.h"
#include "udp.h"
#include "hooks.h"
#include "pool.h"
#include "plugins_config.h"
#include "plugins.h"
#include "interface.h"
#include "arp.h"
#include "gre.h"
#include "log.h"
#include "osfp.h"
#include "parser.h"
#include "ui.h"
#include "ethernet.h"
#include "tagging.h"
#include "stats.h"
#include "dhcpclient.h"
#include "rrdtool.h"
#include "histogram.h"
#include "util.h"
#include "personality.h"

#ifdef HAVE_PYTHON
#include <Python.h>
#include "pyextend.h"
#include "pydataprocessing.h"
#include "pydatahoneyd.h"
#endif

#include "sandbox.h"
/* Prototypes */
void honeyd_tcp_timeout(int, short, void *);
void honeyd_udp_timeout(int, short, void *);
void honeyd_delay_cb(int, short, void *);
enum forward honeyd_route_packet(struct ip_hdr *, u_int, struct addr *, 
    struct addr *, int *);

void tcp_retrans_timeout(int, short, void *);
void icmp_error_send(struct template *, struct addr *, uint8_t, uint8_t,
    struct ip_hdr *, struct spoof);

struct tree tcpcons;
struct conlru tcplru;
struct tree udpcons;
struct conlru udplru;

struct spoof no_spoof;	/* spoof settings for default packet processing */

struct config config = {
	NULL,
	PATH_HONEYDDATA "/nmap-os-db",
	PATH_HONEYDDATA "/xprobe2.conf",
	PATH_HONEYDDATA "/nmap.assoc",
	PATH_HONEYDDATA "/pf.os",
	PATH_HONEYDDATA "/nmap-mac-prefixes"//add the install path for the file
};

struct stats_network stats_network = {
	0,	/* input bytes */
	0	/* output bytes */
};

SPLAY_PROTOTYPE(tree, tuple, node, conhdr_compare);
SPLAY_GENERATE(tree, tuple, node, conhdr_compare);

struct rrdtool_drv	*honeyd_rrd_drv;
struct rrdtool_db	*honeyd_traffic_db;
FILE				*honeyd_servicefp;
struct timeval		honeyd_uptime;
static FILE			*honeyd_logfp;
static ip_t			*honeyd_ip;
struct pool			*pool_pkt;
struct pool			*pool_delay;
rand_t				*honeyd_rand;
int					honeyd_sig;
int					honeyd_nconnects;
int					honeyd_nudp;	/* live UDP flows on udplru */
uint32_t				honeyd_udp_evicted;	/* UDP flows evicted at the cap */
int					honeyd_nchildren;
int					honeyd_ttl = HONEYD_DFL_TTL;
struct tcp_con		honeyd_tmp;
int					honeyd_show_include_dir;
int					honeyd_show_data_dir;
int					honeyd_show_version;
int					honeyd_show_usage;
int					honeyd_debug;
uid_t				honeyd_uid = 32767;
gid_t				honeyd_gid = 32767;
char				*templateDump = NULL;
int					honeyd_needsroot;	/* Need different IDs */
int					honeyd_disable_webserver = 0;
int					honeyd_ignore_parse_errors = 0;
int					honeyd_verify_config = 0;
int					honeyd_webserver_fix_permissions = 0;
char				*honeyd_webserver_address = "127.0.0.1";
int					honeyd_webserver_port = 80;
char				*honeyd_webserver_root = PATH_HONEYDDATA \
						"/webserver/htdocs";
char				*honeyd_rrdtool_path = PATH_RRDTOOL;

/* can be used by unittests to do bad stuff */
void (*honeyd_delay_callback)(int, short, void *) = honeyd_delay_cb;

static char		*logfile = NULL;	/* Log file names */
static char		*jsonlogfile = NULL;	/* JSON Lines log, "-" = stdout */
static long		heartbeat_secs = 0;	/* --heartbeat, 0 = off (#30) */
static struct timeval	honeyd_start_tv;
static uint64_t		honeyd_pkts_in, honeyd_pkts_out;
static char		*servicelog = NULL;

/*
 * TODO: There is a patch on the Google Code page, Issue 12, that purports to be a performance
 *       enhancement when using honeyd as a proxy to send data through an SSH daemon. However,
 *		 there are some parts of the patch that are now incompatible with the DataSoft honeyd
 *		 structure. I will put a note about this in the git commits, and possibly a ticket
 *		 for it if we suspect we'll be using honeyd in this fashion.
 */

/*
 * TODO: There is another patch, Issue 13, which solves about 4 issues total on the Google Code
 * 		 page for honeyd. It is rather large, so I'm merely writing this to remind myself what
 * 		 should be done next time I'm here. I may need to pass this off to someone else, however
 * 		 given that this honeyd is modified a bit and I may not know how to resolve everything.
 */

/*
 * TODO: Issue 20 is rather large, and I don't know if we'd need to functionality that it would
 * 		 provide, but I'm not familiar enough with honeyd to be comfortable with putting it in myself.
 */

static struct option honeyd_long_opts[] = {
	{"include-dir", 0, &honeyd_show_include_dir, 1},
	{"data-dir",    0, &honeyd_show_data_dir, 1},
	{"version",     0, &honeyd_show_version, 1},
	{"help",        0, &honeyd_show_usage, 1},
	{"webserver-address", required_argument, NULL, 'A'},
	{"webserver-port", required_argument, NULL, 'W'},
	{"webserver-root", required_argument, NULL, 'X'},
	{"rrdtool-path", required_argument, NULL, 'Y'},
	{"disable-webserver", 0, &honeyd_disable_webserver, 1},
	{"verify-config", 0, &honeyd_verify_config, 1},
	{"ignore-parse-errors", 0, &honeyd_ignore_parse_errors, 1},
	{"fix-webserver-permissions", 0, &honeyd_webserver_fix_permissions, 1},
	{"mac-address",0,0,1},
	{"json-log", required_argument, NULL, 'J'},
	{"sensor-id", required_argument, NULL, 'I'},
	{"heartbeat", required_argument, NULL, 'H'},
	{"sandbox-scripts", 0, &honeyd_sandbox_scripts, 1},
	{"sandbox-daemon", 0, &honeyd_sandbox_daemon, 1},
	{"sandbox-allow-write", required_argument, NULL, 'S'},
	{"sandbox-script-net", required_argument, NULL, 'N'},
	{"stats-password-file", required_argument, NULL, 'K'},
	{0, 0, 0, 0}
};

static void
honeyd_heartbeat_cb(evutil_socket_t fd, short which, void *arg)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	honeyd_json_heartbeat(now.tv_sec - honeyd_start_tv.tv_sec,
	    honeyd_pkts_in, honeyd_pkts_out, honeyd_json_connections);
}

void
usage(void)
{
	fprintf(stderr,
	    "Usage: phantom-mirage [OPTIONS] [net ...]\n\n"
	    "where options include:\n"
	    "  -d                     Do not daemonize, be verbose.\n"
	    "  -P                     Enable polling mode.\n"
	    "  -l logfile             Log packets and connections to logfile.\n"
	    "  -s logfile             Logs service status output to logfile.\n"
	    "  --json-log=FILE        Also write JSON Lines events to FILE\n"
	    "                         (\"-\" for stdout); see docs/json-log.md.\n"
	    "  --sensor-id=STR        sensor_id in JSON events (default hostname).\n"
	    "  --heartbeat=SECONDS    Write a JSON heartbeat event every SECONDS.\n"
	    "  --sandbox-scripts      Run scripts and subsystems under Landlock +\n"
	    "                         seccomp (Linux); see docs/sandboxing.md.\n"
	    "  --sandbox-daemon       Confine the daemon itself to a seccomp syscall\n"
	    "                         allowlist after the privilege drop (Linux\n"
	    "                         x86_64/arm64); see docs/sandboxing.md.\n"
	    "  --sandbox-allow-write=DIR\n"
	    "                         Let sandboxed scripts write below DIR.\n"
        "  -t ipFile              Dumps currently used DHCP IP addresses to ipFile\n"
	    "  -i interface           Listen on interface.\n"
	    "  -p file                Read nmap-style fingerprints from file.\n"
	    "  -x file                Read xprobe-style fingerprints from file.\n"
	    "  -a assocfile           Read nmap-xprobe associations from file.\n"
	    "  -0 osfingerprints      Read pf-style OS fingerprints from file.\n"
	    "  -u uid		  Set the uid the daemon should run as.\n"
	    "  -g gid		  Set the gid the daemon should run as.\n"
		"  -m file				  Read nmap-mac-prefixes from file. \n"
	    "  -f configfile          Read configuration from file.\n"
	    "  -c host:port:name      Reports stats to collector.\n"
	    "  --stats-password-file=FILE\n"
	    "                         Read the -c password from FILE (mode 0600,\n"
	    "                         owned by the running user, not a symlink).\n"
	    "  -c host:port:name:pass Deprecated: password on the command line.\n"
	    "  --webserver-address=address Address on which webserver listens.\n"
	    "  --webserver-port=port  Port on which webserver listens.\n"
	    "  --webserver-root=path  Root of document tree.\n"
	    "  --fix-webserver-permissions Change ownership and permissions.\n"
	    "  --rrdtool-path=path    Path to rrdtool.\n"
	    "  --disable-webserver    Disables internal webserver\n"
	    "  --verify-config        Verify configuration file then exit.\n"
	    "  -V, --version          Print program version and exit.\n"
	    "  -h, --help             Print this message and exit.\n"
	    "\n"
	    "For plugin development:\n"
	    "  --include-dir          Prints out header files directory and exits.\n"
	    "  --data-dir             Prints out data/plug-in directory and exits.\n");
	
	exit(EXIT_FAILURE);
}

/* XXX ches debug */
void
print_spoof(char *msg, struct spoof s) {
	char buf2[100], buf3[100];

	if (s.new_src.addr_type == ADDR_TYPE_NONE)
		strlcpy(buf2, "**no addr**", sizeof(buf2));
	else
		addr_ntop(&s.new_src, buf2, sizeof(buf2));

	if (s.new_dst.addr_type == ADDR_TYPE_NONE)
		strlcpy(buf3, "**no addr**", sizeof(buf3));
	else
		addr_ntop(&s.new_dst, buf3, sizeof(buf3));
}

/*
 * Populates a new tcp_con structure, which holds the state of a TCP connection
 * 		con    : connection structure to populate
 * 		ip     : IP header of the initial packet
 * 		tcp    : TCP header of the initial packet
 * 		local  : source of this connection, INITIATED_BY_EXTERNAL or INITIATED_BY_SUBSYSTEM
 */
void
honeyd_settcp(struct tcp_con *con, const struct interface *iface, const struct ip_hdr *ip, const struct tcp_hdr *tcp,
    int local)
{
	struct tuple *hdr = &con->conhdr;

	memset(hdr, 0, sizeof(struct tuple));
	hdr->ip_src = ip->ip_src;
	hdr->ip_dst = ip->ip_dst;
	hdr->iface = iface;
	hdr->sport = ntohs(tcp->th_sport);
	hdr->dport = ntohs(tcp->th_dport);
	hdr->type = SOCK_STREAM;
	hdr->local = local;
	con->rcv_flags = tcp->th_flags;
	con->cmd.pfd = -1;
	con->cmd.perrfd = -1;
}

/*
 * Populates a new udp_con structure, which holds the state of a UDP connection
 * 		con    : connection structure to populate
 * 		ip     : IP header of the initial packet
 * 		tcp    : TCP header of the initial packet
 * 		local  : source of this connection, INITIATED_BY_EXTERNAL or INITIATED_BY_SUBSYSTEM
 */
void
honeyd_setudp(struct udp_con *con, const struct ip_hdr *ip, const struct udp_hdr *udp,
    int local)
{
	struct tuple *hdr = &con->conhdr;

	memset(hdr, 0, sizeof(struct tuple));
	hdr->ip_src = ip->ip_src;
	hdr->ip_dst = ip->ip_dst;
	hdr->iface = NULL;
	hdr->sport = ntohs(udp->uh_sport);
	hdr->dport = ntohs(udp->uh_dport);
	hdr->type = SOCK_DGRAM;
	hdr->local = local;
	con->softerrors = 0;
	con->cmd.pfd = -1;
	con->cmd.perrfd = -1;

	TAILQ_INIT(&con->incoming);
}

struct tuple *
tuple_find(struct tree *root, struct tuple *key)
{
	return SPLAY_FIND(tree, root, key);
}

/*
 * Iterate over all connection objects.
 */

int
tuple_iterate(struct conlru *head, int (*f)(struct tuple *, void *), void *arg)
{
	struct tuple *conhdr;

	TAILQ_FOREACH(conhdr, head, next) {
		if ((*f)(conhdr, arg) == -1)
			return (-1);
	}

	return (0);
}

#define HONEYD_OPTSTRING	"VPTdc:i:p:x:a:u:g:f:t:l:s:0:R:m:h?"

static void
syslog_init(int argc, char *argv[])
{
	int options, i;
	char buf[MAXPATHLEN];

#ifdef LOG_PERROR
	options = LOG_PERROR|LOG_PID|LOG_CONS;
#else
	options = LOG_PID|LOG_CONS;
#endif
	openlog("phantom-mirage", options, LOG_DAEMON);	

	/* Create a string containing all the command line
	 * arguments and pass it to syslog:
	 */

	buf[0] = '\0';
	for (i = 1; i < argc; i++) {
		char arg[MAXPATHLEN];

		if (i > 1 && strlcat(buf, " ", sizeof(buf)) >= sizeof(buf))
			break;
		/* Never log a stats password given with -c */
		stats_redact_arg(argv, i, HONEYD_OPTSTRING, arg, sizeof(arg));
		if (strlcat(buf, arg, sizeof(buf)) >= sizeof(buf))
			break;
	}

	syslog(LOG_NOTICE, "started with %s", buf);
}

/*
 * Update traffic statistics for honeyd.
 */

void
honeyd_rrd_cb(int fd, short what, void *unused)
{
	static int count;
	char line[1024];

	snprintf(line, sizeof(line), "%f:%f",
	    (double)count_get_minute(stats_network.input_bytes)/60.0, 
	    (double)count_get_minute(stats_network.output_bytes)/60.0);

	rrdtool_db_update(honeyd_traffic_db, NULL, line);

	/* Create a graph every five minutes */
	if (count++ % 5 == 0) {
		char filename[1024], defs[1536];

		snprintf(defs, sizeof(defs),
		    "DEF:inoctets=%s/graphs/honeyd_traffic.rrd:input:AVERAGE "
		    "DEF:outoctets=%s/graphs/honeyd_traffic.rrd:output:AVERAGE "
		    "AREA:inoctets#00FF00:\"In traffic\" "
		    "LINE1:outoctets#0000FF:\"Out traffic\"",
		    honeyd_webserver_root, honeyd_webserver_root);
		struct timeval tv;

		/* Hourly graph */
		timerclear(&tv);
		tv.tv_sec = -7200;

		snprintf(filename, sizeof(filename),
		    "%s/graphs/traffic_hourly.gif", honeyd_webserver_root);

		rrdtool_graph(honeyd_traffic_db, filename, &tv, NULL, defs);

		/* Daily graph */
		timerclear(&tv);
		tv.tv_sec = -86400;

		snprintf(filename, sizeof(filename),
		    "%s/graphs/traffic_daily.gif", honeyd_webserver_root);

		rrdtool_graph(honeyd_traffic_db, filename, &tv, NULL, defs);
	}
}

void
honeyd_rrd_start(const char *rrdtool_path)
{
	/* Initialize our traffic stats for rrdtool */
	static char honeyd_traffic_filename[1024];

	snprintf(honeyd_traffic_filename, sizeof(honeyd_traffic_filename),
	    "%s/graphs/honeyd_traffic.rrd", honeyd_webserver_root);
	if (access(rrdtool_path, X_OK) == -1) {
		syslog(LOG_NOTICE, "%s: %s not available; no traffic graphs",
		    __func__, rrdtool_path);
		return;
	}
	if ((honeyd_rrd_drv = rrdtool_init(rrdtool_path)) == NULL)
	{
		syslog(LOG_ERR, "%s: cannot start rrdtool", __func__);
		exit(EXIT_FAILURE);
	}
	if ((honeyd_traffic_db = rrdtool_db_start(honeyd_rrd_drv, 
		 honeyd_traffic_filename, 60)) == NULL)
	{
		syslog(LOG_ERR, "%s: cannot create rrd db(database): %s", __func__, honeyd_traffic_filename);
		exit(EXIT_FAILURE);
	}

	rrdtool_db_datasource(honeyd_traffic_db,
	    "input", "GAUGE", 600);
	rrdtool_db_datasource(honeyd_traffic_db,
	    "output", "GAUGE", 600);

	rrdtool_db_commit(honeyd_traffic_db);

	/* Start the periodic traffic update timer */
	struct timeval tv;
	timerclear(&tv);
	tv.tv_sec = 60;
	struct event *ev = event_new(libevent_base, -1, EV_PERSIST, honeyd_rrd_cb, NULL);
	evtimer_add(ev, &tv);
}

/*
 * Initializes data structures pertaining to the daemon
 */

/*
 * Make sure a per-user directory exists, is a real directory (not a
 * symlink) and belongs to uid/gid. New directories are created 0700.
 * With "own" set (honeyd's own directory) an existing directory is also
 * chowned to uid/gid and its permissions are only ever tightened: group
 * write and all "other" access are removed, nothing is added. Without it
 * (a shared parent like ~/.config) an existing directory is left alone.
 * "path" must not end in '/', or O_NOFOLLOW would not apply.
 * Returns 0 on success.
 */
static int
honeyd_user_dir(const char *path, uid_t uid, gid_t gid, int own)
{
	struct stat st;
	mode_t mode;
	int fd, created = 0;

	if (mkdir(path, S_IRWXU) == 0)
		created = 1;
	else if (errno != EEXIST) {
		syslog(LOG_ERR, "%s: mkdir %s: %m", __func__, path);
		return (-1);
	}

	/* O_NOFOLLOW: never chown/chmod through a planted symlink as root */
	fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1) {
		syslog(LOG_ERR, "%s: open %s: %m", __func__, path);
		return (-1);
	}
	if (fstat(fd, &st) == -1) {
		syslog(LOG_ERR, "%s: fstat %s: %m", __func__, path);
		close(fd);
		return (-1);
	}

	if (!own && !created) {
		close(fd);
		return (0);
	}

	if ((st.st_uid != uid || st.st_gid != gid) &&
	    fchown(fd, uid, gid) == -1)
		syslog(LOG_WARNING, "%s: chown %s: %m", __func__, path);

	mode = st.st_mode & 07777 & ~(S_IWGRP | S_IRWXO);
	if (mode != (st.st_mode & 07777) && fchmod(fd, mode) == -1)
		syslog(LOG_WARNING, "%s: chmod %s: %m", __func__, path);

	close(fd);
	return (0);
}

void
honeyd_init(void)
{
	struct rlimit rl;
	struct passwd *pwd;

	/* Record our start time */
	gettimeofday(&honeyd_uptime, NULL);

	/* Find the correct ids for nobody, if the uid was not set in the
         * command line */
	if ( honeyd_uid == 32767 && (pwd = getpwnam("nobody")) != NULL) {
		honeyd_uid = pwd->pw_uid;
	}
	if ( honeyd_gid == 32767 && (pwd = getpwnam("nobody")) != NULL) {
		honeyd_gid = pwd->pw_gid;
	}

	/* Initalize ongoing connection state */
	SPLAY_INIT(&tcpcons);
	TAILQ_INIT(&tcplru);
	SPLAY_INIT(&udpcons);
	TAILQ_INIT(&udplru);

	memset(&honeyd_tmp, 0, sizeof(honeyd_tmp));

	/* Raising file descriptor limits */
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		/* Linux does not seem to like this */
		if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		{
			syslog(LOG_ERR, "getrlimit: NOFILE, failed at getting the files resources limit due to file not existing");
			exit(EXIT_FAILURE);
		}
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		{
			syslog(LOG_ERR, "setrlimit: NOFILE, failed to set resource limit due to file not existing");
			exit(EXIT_FAILURE);
		}
	}
#ifdef RLIMIT_NPROC
	if (getrlimit(RLIMIT_NPROC, &rl) == -1)
	{
		syslog(LOG_ERR, "getrlimit: NPROC, failed at getting the process' resource limit due to process not running");
		exit(EXIT_FAILURE);
	}
	rl.rlim_max = rl.rlim_max/2;
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &rl) == -1)
	{
		syslog(LOG_ERR, "setrlimit: NPROC, failed at setting the process' resource limit due to process not running");
		exit(EXIT_FAILURE);
	}
#endif

	stats_network.input_bytes = count_new();
	stats_network.output_bytes = count_new();

	//set environment variable for scripts to use
	char *sudo_user = getenv("SUDO_USER");
	int uid = 0;
	gid_t gid = 0;
	char *home_path = NULL;
	struct passwd *pass = NULL;

	//Try getting the "SUDO_USER".
	//If it doesn't exist (not running with sudo), then just default to using the current user
	if(sudo_user != NULL)
	{
		pass = getpwnam(sudo_user);
	}
	if(pass == NULL)
	{
		pass = getpwuid(getuid());
		if(pass == NULL)
		{
			syslog(LOG_ERR, "%s: Cannot find a valid user to run as, is your system okay?!",  __func__);
			exit(EXIT_FAILURE);
		}
	}
	uid = pass->pw_uid;
	gid = pass->pw_gid;
	home_path = pass->pw_dir;

	char config_suffix[] = "/.config";
	char honeyd_suffix[] = "/phantom-mirage/";
	char *full_path = malloc(strlen(home_path) + strlen(config_suffix) + strlen(honeyd_suffix) + 1);
	strcpy(full_path, home_path);
	strcat(full_path, config_suffix);

	/* ~/.config: create if missing (0700, owned by the user); an
	 * existing one is left untouched. */
	honeyd_user_dir(full_path, uid, gid, 0);

	strcat(full_path, honeyd_suffix);
	/* ~/.config/phantom-mirage: owned by the invoking user, 0700 when new,
	 * existing permissions only tightened. Drop the trailing '/' for
	 * the check so a symlink is not followed. */
	full_path[strlen(full_path) - 1] = '\0';
	honeyd_user_dir(full_path, uid, gid, 1);
	full_path[strlen(full_path)] = '/';

	if(setenv("PHANTOM_MIRAGE_HOME", full_path, 1) ||
	    setenv("HONEYD_HOME", full_path, 1))	/* legacy name */
	{
		perror("Error: Could not set environment variable PHANTOM_MIRAGE_HOME");
	}
	free(full_path);
}

/*
 * Look up PHANTOM_MIRAGE_<suffix>; fall back to the deprecated
 * HONEYD_<suffix> with a warning.
 */
char *
pm_getenv(const char *suffix)
{
	char name[64];
	char *value;

	snprintf(name, sizeof(name), "PHANTOM_MIRAGE_%s", suffix);
	if ((value = getenv(name)) != NULL)
		return (value);
	snprintf(name, sizeof(name), "HONEYD_%s", suffix);
	if ((value = getenv(name)) != NULL)
		fprintf(stderr, "phantom-mirage: warning: %s is deprecated, "
		    "use PHANTOM_MIRAGE_%s\n", name, suffix);
	return (value);
}

#ifdef HAVE_PYTHON
static int
honeyd_is_webserver_enabled(void)
{
	if (honeyd_webserver_port <= 0)
		return 0;
	if (honeyd_disable_webserver)
		return 0;

	return (1);
}
#endif

/*
 * Pid file: PIDFILE lives in the root-owned 0700 control socket dir, so
 * after the privilege drop the daemon can neither unlink it nor reopen it
 * by name.  It is created as root (0644, root-owned) and the descriptor
 * is kept: on exit we unlink it if we can (still root), otherwise
 * truncate it through the descriptor, which needs no access to the dir
 * and is allowed by Landlock (the fd predates the ruleset).  At start-up
 * an empty pid file, or one naming a dead process or something that is
 * not phantom-mirage, is stale and replaced; under systemd,
 * RuntimeDirectory= removes the dir (and the file) when the unit stops.
 */
static int honeyd_pidfd = -1;
static pid_t honeyd_pidfile_pid = -1;

static int
honeyd_pid_is_us(pid_t pid)
{
	char path[64], a[64] = "", b[64] = "";
	FILE *fp;

	if (pid <= 0 || pid == getpid())
		return (0);
	if (kill(pid, 0) == -1 && errno != EPERM)
		return (0);
	snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
	if ((fp = fopen(path, "r")) == NULL)
		return (1);	/* no /proc: assume it is a live daemon */
	if (fgets(a, sizeof(a), fp) == NULL)
		a[0] = '\0';
	fclose(fp);
	if ((fp = fopen("/proc/self/comm", "r")) != NULL) {
		if (fgets(b, sizeof(b), fp) == NULL)
			b[0] = '\0';
		fclose(fp);
	}
	return (strcmp(a, b) == 0);
}

/* Before ui_init(), so a second instance can't replace the socket */
static void
honeyd_pidfile_check(void)
{
	char buf[32];
	ssize_t n;
	long pid;
	int fd;

	if ((fd = open(PIDFILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) != -1) {
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		buf[n > 0 ? n : 0] = '\0';
		pid = strtol(buf, NULL, 10);
		if (honeyd_pid_is_us((pid_t)pid)) {
			syslog(LOG_ERR, "%s: already running as pid %ld",
			    PIDFILE, pid);
			exit(EXIT_FAILURE);
		}
		if (n > 0)
			syslog(LOG_NOTICE, "%s: replacing stale pid file "
			    "(pid %ld is not running)", PIDFILE, pid);
	}
}

static void
honeyd_pidfile_open(void)
{
	int fd;

	if (mkdir(PIDDIR, 0700) == -1 && errno != EEXIST) {
		syslog(LOG_ERR, "mkdir %s: %m", PIDDIR);
		exit(EXIT_FAILURE);
	}
	/* Never write through a planted file or link: always a new file */
	unlink(PIDFILE);
	fd = open(PIDFILE, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0644);
	if (fd == -1) {
		syslog(LOG_ERR, "open %s: %m", PIDFILE);
		exit(EXIT_FAILURE);
	}
	fchmod(fd, 0644);
	honeyd_pidfd = fd;
}

static void
honeyd_pidfile_write(void)
{
	char buf[32];
	int len;

	honeyd_pidfile_pid = getpid();
	len = snprintf(buf, sizeof(buf), "%ld\n", (long)honeyd_pidfile_pid);
	if (write(honeyd_pidfd, buf, len) != len)
		syslog(LOG_WARNING, "write %s: %m", PIDFILE);
}

static void
honeyd_pidfile_remove(void)
{
	/* only the daemon itself, never a forked child */
	if (honeyd_pidfd == -1 || getpid() != honeyd_pidfile_pid)
		return;
	if (unlink(PIDFILE) == -1 && ftruncate(honeyd_pidfd, 0) == -1)
		syslog(LOG_WARNING, "cannot remove or truncate %s: %m",
		    PIDFILE);
	close(honeyd_pidfd);
	honeyd_pidfd = -1;
}

void
honeyd_exit(int status)
{
	honeyd_logend(honeyd_logfp);
	honeyd_logend(honeyd_servicefp);
	honeyd_json_close();

	template_free_all(TEMPLATE_FREE_DEALLOCATE);

	interface_close_all();

	rand_close(honeyd_rand);
	ip_close(honeyd_ip);
	honeyd_pidfile_remove();
	closelog();

#ifdef HAVE_PYTHON
	if (honeyd_is_webserver_enabled())
		pyextend_webserver_exit();
	pyextend_exit();
#endif
	exit(status);
}

/* Encapsulate a packet into Ethernet */
void
honeyd_ether_send_cb(struct arp_req *req, int success, void *arg)
{

	if((req == NULL) || (arg == NULL))
	{
		syslog(LOG_WARNING, "%s: invalid packet to encapsulate",  __func__);
		return;
	}

	u_char pkt[HONEYD_MTU + 40]; /* XXX - Enough? */
	struct interface *inter = req->inter;
	struct ip_hdr *ip = arg;
	u_int len, iplen = ntohs(ip->ip_len);

	/*
	 * The ARP request failed: req->ha is still the broadcast MAC.
	 * Drop the queued packet; it is freed once below.
	 */
	if (!success)
		goto out;

	eth_pack_hdr(pkt,
	    req->ha.addr_eth,				/* destination */
	    req->src_ha.addr_eth,			/* source */
	    ETH_TYPE_IP);
	
	len = ETH_HDR_LEN + iplen;
	if (sizeof(pkt) < len) {
		syslog(LOG_WARNING, "%s: IP packet is larger than buffer: %d",
		    __func__, len);
		goto out;
	}

	if(inter != NULL)
	{
		memcpy(pkt + ETH_HDR_LEN, ip, iplen);
		if (eth_send(inter->if_eth, pkt, len) != len)
		{
			syslog(LOG_ERR, "%s: couldn't send packet size %d: %m",
				__func__, len);
		}
		else
		{
			count_increment(stats_network.output_bytes, iplen);
		}
	}

 out:
	pool_free(pool_pkt, ip);
}

/*
 * Delivers an IP packet to a specific interface.
 * Generates ARP request if necessary.
 */
void
honeyd_send_ethernet(struct interface *inter,
    struct addr *src_pa, struct addr *src_ha,
    struct addr *dst_pa, struct ip_hdr *ip, u_int iplen)
{
	struct arp_req *req;

	ip_checksum(ip, iplen);

	// If we haven't done an ARP request yet
	if ((req = arp_find(dst_pa)) == NULL) {
		arp_request(inter, src_pa, src_ha, dst_pa, honeyd_ether_send_cb,ip);

	// If the ARP request finished with success
	} else if (req->cnt == ARP_REQUEST_SUCESS) {
		/*
		 * The source MAC of the original requestor does not help
		 * us here, but we can overwrite it with the MAC of this
		 * honeypot without causing any harm.
		 */
		req->src_ha = *src_ha;
		honeyd_ether_send_cb(req, 1, ip);

	// We couldn't figure out how to deliver this
	} else {
		/* 
		 * Fall through in case that this packet needs
		 * to be dropped.
		 */
		pool_free(pool_pkt, ip);
	}
}

/*
 * Makes sure that we end up owning the memory referenced by
 * the delay descriptor.  We either tell to not free the
 * memory or just make our own copy.
 */

struct ip_hdr *
honeyd_delay_own_memory(struct delay *delay, struct ip_hdr *ip, u_int iplen)
{
	/* If we are not supposed to free the buffer then we do not own it */
	if (!(delay->flags & DELAY_FREEPKT)) {
		void *tmp = pool_alloc(pool_pkt);

		memcpy(tmp, ip, iplen);
		ip = tmp;
	} else {
		/* 
		 * We are handling the memory ourselves: if we
		 * delegate the memory to the ARP handler, it will get
		 * freed later.
		 */
		delay->flags &= ~DELAY_FREEPKT;
	}
		
	return (ip);
}

/*
 * This function delivers the actual packet to the network.
 * It supports internal delivery, external delivery via ip_send
 * and external delivery via ethernet encapsulation.
 *
 * This function handles the following cases:
 * - TTL is 0: send ICMP time exceeded in transit message
 * - External: Packet is delivered to the real network
 * - Tunnel: Packet is GRE encapsulated and sent to a remote location
 * - Ethernet: A physical machine has been integrate into the virtual
 *	routing topology and we need to ethernet encapsulate the packet.
 * - Arp: The destination machine is configured to be on the physical link,
 *    so arp for it and ethernet encapsulate the packet.
 * - Everything else:  The packet is delivered internally after potential
 *    fragment reassembly.
 *
 * It needs to unreference the passed template value.
 */

static __inline void
honeyd_send_normally(struct ip_hdr *ip, u_int iplen)
{
	ip_checksum(ip, iplen);

	if (ip_send(honeyd_ip, ip, iplen) != iplen) {
		int level = LOG_ERR;
		if (errno == EHOSTDOWN || errno == EHOSTUNREACH)
			level = LOG_DEBUG;
		syslog(level, "couldn't send packet: %m");
	} else {
		count_increment(stats_network.output_bytes, iplen);
	}
}

void
honeyd_delay_cb(int fd, short which, void *arg)
{
	struct delay *delay = arg;
	struct ip_hdr *ip = delay->ip;
	struct template *tmpl = delay->tmpl;
	u_int iplen = delay->iplen;

	if (!ip->ip_ttl) {
		/* Fix up TTL */
		ip->ip_ttl++;
		ip_checksum(ip, ip->ip_hl << 2);
		icmp_error_send(tmpl, &delay->src,
		    ICMP_TIMEXCEED, ICMP_TIMEXCEED_INTRANS, ip, delay->spoof);
	} else if (delay->flags & DELAY_UNREACH) {
		/* Fix up TTL */
		ip->ip_ttl++;
		ip_checksum(ip, ip->ip_hl << 2);
		icmp_error_send(tmpl, &delay->src,
		    ICMP_UNREACH, ICMP_UNREACH_NET, ip, delay->spoof);
	} else if (delay->flags & DELAY_EXTERNAL) {
		struct addr dst;
		addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ip->ip_dst, IP_ADDR_LEN);

		struct interface* inter = interface_find_responsible(&dst);

		// Check if the destination is the broadcast address and skip ARP if so
		if (inter != NULL && ip->ip_dst == inter->subnetBcastAddress)
		{
			honeyd_send_normally(ip, iplen);
		/* This is the source template */
		} else if (tmpl != NULL && tmpl->ethernet_addr != NULL && tmpl->inter != NULL &&
		    inter == tmpl->inter)
		{
			struct addr src;
		
			/* To do ARP, we need to know all this information */
			addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS,
			    &ip->ip_src, IP_ADDR_LEN);

			ip = honeyd_delay_own_memory(delay, ip, iplen);

			/* This function computes the IP checksum for us */
			honeyd_send_ethernet(tmpl->inter,
			    &src, tmpl->ethernet_addr,
			    &dst, ip, iplen);
		} else {
			honeyd_send_normally(ip, iplen);
		}
	} else if (delay->flags & DELAY_TUNNEL) {
		ip_checksum(ip, iplen);

		if (gre_encapsulate(honeyd_ip, &delay->src, &delay->dst,
			ip, iplen) == -1)
			syslog(LOG_ERR, "couldn't GRE encapsulate packet: %m");
		else
			count_increment(stats_network.output_bytes, iplen);
	} else if ((delay->flags & DELAY_ETHERNET) &&
	    (tmpl == NULL || tmpl->inter == NULL)) {
		/* External delivery needs the template's interface */
		syslog(LOG_ERR, "%s: no interface for external delivery",
		    __func__);
	} else if (delay->flags & DELAY_ETHERNET) {
		extern struct network *reverse;
		struct interface *inter = tmpl->inter;
		struct router *router;
		struct addr addr;

		/*
		 * If a physical honeypot has been integrated into the
		 * virtual routing topology, we need to find the
		 * corresponding router.
		 */
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ip->ip_dst, IP_ADDR_LEN);
		router = network_lookup(reverse, &addr);
		if (router == NULL){
			syslog(LOG_ERR, "%s: bad configuration", __func__);
			exit(EXIT_FAILURE);
		}
		/* 
		 * If we are routing for an external sender, then we
		 * might have to copy the packet into an allocated
		 * buffer.
		 */
		
		ip = honeyd_delay_own_memory(delay, ip, iplen);

		/* This function computes the IP checksum for us */
		honeyd_send_ethernet(inter,
		    &router->addr, &inter->if_ent.intf_link_addr,
		    &addr, ip, iplen);
	} else {
		struct addr addr;
		uint16_t ipoff;

		template_free(tmpl);

		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS,
		    &ip->ip_dst, IP_ADDR_LEN);

		/* Internal delivery */
		tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);
		tmpl = template_ref(tmpl);

		/* Check for fragmentation */
		ipoff = ntohs(ip->ip_off);
		if ((ipoff & IP_OFFMASK) || (ipoff & IP_MF)) {
			struct ip_hdr *nip;
			u_short niplen;

			if (ip_fragment(tmpl, ip, iplen, &nip, &niplen) == 0)
				honeyd_dispatch(tmpl, delay->iface, nip, niplen);
		} else
			honeyd_dispatch(tmpl, delay->iface, ip, iplen);
	}

	if (delay->flags & DELAY_FREEPKT)
		pool_free(pool_pkt, ip);
	template_free(tmpl);

	if (delay->flags & DELAY_NEEDFREE) {
		/* Only a delayed packet owns a timer */
		event_free(delay->timeout);
		pool_free(pool_delay, delay);
	}
}

/*
 * Delays a packet for a specified amount of ms to simulate routing delay.
 * Host is used for the router that might generate a XCEED message.
 */

void
honeyd_delay_packet(struct template *tmpl, const struct interface* iface, struct ip_hdr *ip, u_int iplen,
    const struct addr *src, const struct addr *dst, int ms, int flags,
    struct spoof spoof)
{
	struct delay *delay, tmp_delay;
	struct timeval tv;

	if (ms) {
		delay = pool_alloc(pool_delay);
		flags |= DELAY_NEEDFREE;

		/* 
		 * If the IP packet is not allocated separately, we
		 * need to allocate it here.
		 */
		if ((flags & DELAY_FREEPKT) == 0) {
			void *tmp;

			if (iplen < HONEYD_MTU)
				tmp = pool_alloc(pool_pkt);
			else
				tmp = pool_alloc_size(pool_pkt, iplen);

			memcpy(tmp, ip, iplen);
			ip = tmp;

			flags |= DELAY_FREEPKT;
		}
	} else {
		memset(&tmp_delay, 0, sizeof(tmp_delay));
		delay = &tmp_delay;
	}
 	delay->ip = ip;
	delay->iplen = iplen;
	delay->iface = iface;

	if (src != NULL)
		delay->src = *src;
	if (dst != NULL)
		delay->dst = *dst;
	delay->tmpl = template_ref(tmpl);
	delay->flags = flags;
	delay->spoof = spoof;

	if (ms) {
		delay->timeout = evtimer_new(libevent_base, honeyd_delay_callback, delay);
		if (delay->timeout == NULL) {
			/*
			 * CWE-476/CWE-252: drop the packet. Free what the
			 * callback would have freed: our packet copy (or the
			 * caller's packet handed to us with DELAY_FREEPKT),
			 * the template reference and the delay record.
			 */
			syslog(LOG_ERR, "%s: evtimer_new failed, packet dropped",
			    __func__);
			if (delay->flags & DELAY_FREEPKT)
				pool_free(pool_pkt, delay->ip);
			template_free(delay->tmpl);
			pool_free(pool_delay, delay);
			return;
		}
		timerclear(&tv);
		tv.tv_sec = ms / 1000;
		tv.tv_usec = (ms % 1000) * 1000;
		evtimer_add(delay->timeout, &tv);
	} else
		honeyd_delay_callback(-1, EV_TIMEOUT, delay);
}

/*
 * This function allows us to deliver packets to virtual hosts as well
 * as to external hosts.  If virtual routing topologies are enabled,
 * characteristics like packet loss, latency and ttl decrements are
 * taken into consideration.
 */

void
honeyd_ip_send(u_char *pkt, u_int iplen, struct spoof spoof)
{
	struct template *tmpl = NULL;
	struct ip_hdr *ip = (struct ip_hdr *)pkt;
	enum forward res = FW_EXTERNAL;
	int delay = 0, flags = 0;
	struct addr addr, src;

	print_spoof("honeyd_ip_send", spoof);
	honeyd_pkts_out++;

	if (iplen > HONEYD_MTU) {
		u_short off = ntohs(ip->ip_off);
		if ((off & IP_DF) == 0)
			ip_send_fragments(HONEYD_MTU, ip, iplen, spoof);
		goto drop;
	}
	if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
		ip->ip_dst = spoof.new_dst.addr_ip;
	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	/* Find the template for the external address */
	tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);
	if ((tmpl != NULL) && (tmpl->flags & TEMPLATE_EXTERNAL))
		flags |= DELAY_ETHERNET;

	/* But all sending decisions are really based on the source template */
	tmpl = template_find_best(addr_ntoa(&src), ip, iplen);

	if (router_used) {
		extern struct network *reverse;
		struct router *router;

		router = network_lookup(reverse, &src);
		if (router == NULL) {
			syslog(LOG_NOTICE, "No reverse routing map for %s",
			    addr_ntoa(&src));
			goto drop;
		}

		/* 
		 * If the router itself is sending the packet, the first
		 * routing table lookup does not decrease the ttl.
		 */
		if (addr_cmp(&src, &router->addr) == 0)
			ip->ip_ttl++; /* XXX - Ugly hack */

		if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
			ip->ip_src = spoof.new_src.addr_ip;
		res = honeyd_route_packet(ip, iplen, &router->addr, &addr,
		    &delay);
		if (res == FW_DROP)
			goto drop;
	}

	/* Remember that the packet buffer has to be freed at the end */
	flags |= DELAY_FREEPKT;
	if (res == FW_EXTERNAL)
		flags |= DELAY_EXTERNAL;
	
	if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
		ip->ip_src = spoof.new_src.addr_ip;
	if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
		ip->ip_dst = spoof.new_dst.addr_ip;

	/* Delay the packet if necessary, otherwise deliver it directly */
	honeyd_delay_packet(tmpl, NULL, ip, iplen, NULL, NULL, delay, flags, spoof);
	return;

 drop:
	/* Deallocate the packet */
	pool_free(pool_pkt, pkt);
}

static void
connection_insert(struct tree *tree, struct conlru *head, struct tuple *hdr)
{
	SPLAY_INSERT(tree, tree, hdr);
	TAILQ_INSERT_HEAD(head, hdr, next);
}

static void
connection_remove(struct tree *tree, struct conlru *head, struct tuple *hdr)
{
	SPLAY_REMOVE(tree, tree, hdr);
	TAILQ_REMOVE(head, hdr, next);

	evtimer_del(hdr->timeout);
}

/* Called when a connection received data and has not been idle */

static void
connection_update(struct conlru *head, struct tuple *hdr)
{
	TAILQ_REMOVE(head, hdr, next);
	TAILQ_INSERT_HEAD(head, hdr, next);

	generic_timeout(hdr->timeout, HONEYD_IDLE_TIMEOUT);
}

/* Transforms the second variable into an absolute path, unless it is already one */

void
determine_path(char *abspath, char **input)
{
	char *buffer = NULL;
	size_t len;
	if (*input[0] != '/') {
		len = strlen(abspath) + strlen(*input) + 2;
		if ((buffer = malloc(len)) == NULL) {
			syslog(LOG_ERR, "%s: malloc", __func__);
			exit(EXIT_FAILURE);
		}
		snprintf(buffer, len, "%s/%s", abspath, *input);
		*input = buffer;
	}
}

/*
 * Returns a malloc'd "<dir>/<name>" path.
 */
static char *
honeyd_data_path(const char *dir, const char *name)
{
	size_t len = strlen(dir) + strlen(name) + 2;
	char *p = malloc(len);
	if (p == NULL) {
		syslog(LOG_ERR, "%s: malloc", __func__);
		exit(EXIT_FAILURE);
	}
	snprintf(p, len, "%s/%s", dir, name);
	return (p);
}

/*
 * Make sure a required data file is readable; otherwise fail with an
 * error that names the file and the option that overrides it.
 */
static void
honeyd_check_data_file(const char *path, const char *what, const char *flag)
{
	if (access(path, R_OK) == 0)
		return;
	fprintf(stderr, "ERROR: cannot open %s file %s: %s\n"
	    "       (use %s to specify its location)\n",
	    what, path, strerror(errno), flag);
	syslog(LOG_ERR, "cannot open %s file %s: %s (use %s)",
	    what, path, strerror(errno), flag);
	exit(EXIT_FAILURE);
}

/*
 * Flow limits. "option honeyd max_template_flows N" caps the references
 * on one template (default TEMPLATE_MAX_REFCNT); "option honeyd
 * max_source_flows N" caps the concurrent flows initiated by one source
 * address (default HONEYD_MAX_SOURCE_FLOWS). A value below 1 keeps the
 * default.
 */
uint32_t
honeyd_flow_option(const char *name, uint32_t def)
{
	const struct honeyd_plugin_cfg *cfg;

	cfg = plugins_config_find_item("honeyd", name, HD_CONFIG_INT);
	if (cfg == NULL || cfg->cfg_int < 1)
		return (def);
	return ((uint32_t)cfg->cfg_int);
}

/*
 * Like honeyd_flow_option(), but 0 turns the limit off (returned as 0)
 * and only a missing or negative value keeps the default.
 */
uint32_t
honeyd_limit_option(const char *name, uint32_t def)
{
	const struct honeyd_plugin_cfg *cfg;

	cfg = plugins_config_find_item("honeyd", name, HD_CONFIG_INT);
	if (cfg == NULL || cfg->cfg_int < 0)
		return (def);
	return ((uint32_t)cfg->cfg_int);
}

uint32_t
template_max_refcnt(void)
{
	return (honeyd_flow_option("max_template_flows",
		TEMPLATE_MAX_REFCNT));
}

/*
 * Concurrent flows per source address. An entry exists only while its
 * source has at least one counted flow and is freed when the count
 * drops to zero, so the tree never holds more entries than there are
 * live flows.
 */
struct srcflow {
	SPLAY_ENTRY(srcflow) node;
	ip_addr_t addr;
	uint32_t nflows;
};

static int
srcflow_compare(struct srcflow *a, struct srcflow *b)
{
	if (a->addr < b->addr)
		return (-1);
	return (a->addr > b->addr);
}

SPLAY_HEAD(srcflowtree, srcflow) srcflows = SPLAY_INITIALIZER(&srcflows);
SPLAY_PROTOTYPE(srcflowtree, srcflow, node, srcflow_compare);
SPLAY_GENERATE(srcflowtree, srcflow, node, srcflow_compare);

static struct srcflow *
srcflow_find(ip_addr_t addr)
{
	struct srcflow tmp;

	tmp.addr = addr;
	return (SPLAY_FIND(srcflowtree, &srcflows, &tmp));
}

/* Number of counted flows from this source */
uint32_t
honeyd_source_flows(ip_addr_t addr)
{
	struct srcflow *sf = srcflow_find(addr);

	return (sf != NULL ? sf->nflows : 0);
}

/* True if a new flow from this source must be refused */
static int
honeyd_source_full(ip_addr_t addr)
{
	return (honeyd_source_flows(addr) >= honeyd_flow_option(
		    "max_source_flows", HONEYD_MAX_SOURCE_FLOWS));
}

/* Count a new flow against its source; on failure it is not counted */
static void
honeyd_source_take(struct tuple *hdr)
{
	struct srcflow *sf = srcflow_find(hdr->ip_src);

	if (sf == NULL) {
		if ((sf = calloc(1, sizeof(*sf))) == NULL)
			return;
		sf->addr = hdr->ip_src;
		SPLAY_INSERT(srcflowtree, &srcflows, sf);
	}
	sf->nflows++;
	hdr->srccounted = 1;
}

static void
honeyd_source_release(struct tuple *hdr)
{
	struct srcflow *sf;

	if (!hdr->srccounted)
		return;
	hdr->srccounted = 0;
	if ((sf = srcflow_find(hdr->ip_src)) == NULL)
		return;
	if (--sf->nflows == 0) {
		SPLAY_REMOVE(srcflowtree, &srcflows, sf);
		free(sf);
	}
}

struct tcp_con *
tcp_new(const struct interface* iface, struct ip_hdr *ip, struct tcp_hdr *tcp, int local)
{
	struct tcp_con *con;

	if (honeyd_nconnects >= HONEYD_MAX_CONNECTS) {
		/* 
		 * We seem to be in an overload situation - remove the
		 * oldest connection available.
		 */
		con = (struct tcp_con *)TAILQ_LAST(&tcplru, conlru);
		tcp_free(con);
	}

	if ((con = calloc(1, sizeof(struct tcp_con))) == NULL) {
		syslog(LOG_WARNING, "calloc: %m");
		return (NULL);
	}

	honeyd_settcp(con, NULL, ip, tcp, local);
	con->conhdr.iface = iface;

	/*
	 * CWE-476/CWE-252: make both timers before the connection is
	 * counted or inserted; on failure free what was made and drop.
	 */
	con->conhdr.timeout = evtimer_new(libevent_base, honeyd_tcp_timeout, con);
	con->retrans_timeout = evtimer_new(libevent_base, tcp_retrans_timeout, con);
	if (con->conhdr.timeout == NULL || con->retrans_timeout == NULL) {
		syslog(LOG_ERR, "%s: evtimer_new failed", __func__);
		if (con->conhdr.timeout != NULL)
			event_free(con->conhdr.timeout);
		if (con->retrans_timeout != NULL)
			event_free(con->retrans_timeout);
		free(con);
		return (NULL);
	}

	honeyd_nconnects++;

	connection_insert(&tcpcons, &tcplru, &con->conhdr);

	honeyd_log_flownew(honeyd_logfp, IP_PROTO_TCP, &con->conhdr);
	return (con);
}

void
tcp_free(struct tcp_con *con)
{
	struct port *port = con->port;
	struct port_encapsulate *pending = con->conhdr.pending;

	if (pending != NULL)
		port_encapsulation_free(pending);

	if (port != NULL)
		port_free(port->subtmpl, port);

	connection_remove(&tcpcons, &tcplru, &con->conhdr);
	honeyd_source_release(&con->conhdr);

	hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr,
	    NULL, 0);
	honeyd_log_flowend(honeyd_logfp, IP_PROTO_TCP, &con->conhdr);

	event_free(con->retrans_timeout);
	event_free(con->conhdr.timeout);

	if (con->cmd_pfd != -1)
		cmd_free(&con->cmd);
	if (con->payload != NULL)
		free(con->payload);
	if (con->readbuf != NULL)
		free(con->readbuf);
	if (con->tmpl != NULL)
		template_free(con->tmpl);

	honeyd_nconnects--;
	free(con);
}

void
tcp_retrans_timeout(int fd, short event, void *arg)
{
	struct tcp_con *con = arg;

	/* Restart transmitting from the last acknowledged segment */
	con->poff = 0;

	con->retrans_time *= 2;
	/* Upper bound on the retransmit time */
	if (con->retrans_time >= 60) {
		tcp_free(con);
		return;
	}

	switch (con->state) {
	case TCP_STATE_SYN_SENT:
		con->snd_una--;
		tcp_send(con, TH_SYN, NULL, 0);
		con->snd_una++;
		
		generic_timeout(con->retrans_timeout, con->retrans_time);
		break;

	case TCP_STATE_SYN_RECEIVED:
		con->snd_una--;
		tcp_send(con, TH_SYN|TH_ACK, NULL, 0);
		con->snd_una++;
		
		generic_timeout(con->retrans_timeout, con->retrans_time);
		break;

	default:
		/* Will reschedule retransmit timeout if needed */
		tcp_senddata(con, TH_ACK);
		break;
	}
}

/*
 * PM-SCR-139: global cap on UDP flow state. "option honeyd max_udp_flows N"
 * sets it (default HONEYD_MAX_UDP). At the cap the least recently used
 * flow, the tail of udplru, is freed through udp_free() like the idle
 * timer does; no ICMP is sent for it. Called before the new flow is
 * inserted, so the flow being created is never the one evicted.
 */
static void
udp_make_room(void)
{
	static time_t lastlog;
	static uint32_t lastcount;
	struct udp_con *old;
	uint32_t max = honeyd_flow_option("max_udp_flows", HONEYD_MAX_UDP);
	time_t now;

	while ((uint32_t)honeyd_nudp >= max &&
	    (old = (struct udp_con *)TAILQ_LAST(&udplru, conlru)) != NULL) {
		honeyd_udp_evicted++;
		udp_free(old);
	}

	now = time(NULL);
	if (honeyd_udp_evicted != lastcount && now != lastlog) {
		syslog(LOG_DEBUG, "UDP flow cap %u reached: %u flows evicted",
		    max, honeyd_udp_evicted);
		lastlog = now;
		lastcount = honeyd_udp_evicted;
	}
}

static void
udp_insert(struct udp_con *con)
{
	connection_insert(&udpcons, &udplru, &con->conhdr);
	honeyd_nudp++;
}

/* Move a UDP flow to the head of udplru on every packet in either direction */
static void
udp_lru_update(struct udp_con *con)
{
	TAILQ_REMOVE(&udplru, &con->conhdr, next);
	TAILQ_INSERT_HEAD(&udplru, &con->conhdr, next);
}

struct udp_con *
udp_new(struct ip_hdr *ip, struct udp_hdr *udp, int local)
{
	struct udp_con *con;

	/* Allocate first so a failure at the cap cannot evict a flow */
	if ((con = calloc(1, sizeof(struct udp_con))) == NULL) {
			syslog(LOG_WARNING, "calloc: %m");
			return (NULL);
	}

	honeyd_setudp(con, ip, udp, local);

	/* Create the idle timer before the flow is listed or counted */
	con->conhdr.timeout = evtimer_new(libevent_base, honeyd_udp_timeout, con);
	if (con->conhdr.timeout == NULL) {
		syslog(LOG_ERR, "%s: evtimer_new failed", __func__);
		free(con);
		return (NULL);
	}

	/* The new flow is not on udplru yet, so it is never the one evicted */
	udp_make_room();
	udp_insert(con);

	honeyd_log_flownew(honeyd_logfp, IP_PROTO_UDP, &con->conhdr);

	return (con);
}

void
udp_free(struct udp_con *con)
{
	struct conbuffer *buf;
	struct port *port = con->port;
	struct port_encapsulate *pending = con->conhdr.pending;

	if (pending != NULL)
		port_encapsulation_free(pending);

	if (port != NULL)
		port_free(port->subtmpl, port);

	connection_remove(&udpcons, &udplru, &con->conhdr);
	honeyd_nudp--;
	honeyd_source_release(&con->conhdr);

	hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr,
	    NULL, 0);
	honeyd_log_flowend(honeyd_logfp, IP_PROTO_UDP, &con->conhdr);

	while ((buf = TAILQ_FIRST(&con->incoming)) != NULL) {
		TAILQ_REMOVE(&con->incoming, buf, next);
		free(buf->buf);
		free(buf);
	}

	if (con->cmd_pfd != -1)
		cmd_free(&con->cmd);
	if (con->tmpl != NULL)
		template_free(con->tmpl);

	event_free(con->conhdr.timeout);
	free(con);
}

void
honeyd_tcp_timeout(int fd, short event, void *arg)
{
	struct tcp_con *con = arg;

	syslog(LOG_DEBUG, "Expiring TCP %s (%p) in state %d",
	    honeyd_contoa(&con->conhdr), con, con->state);

	tcp_free(con);
}

void
honeyd_udp_timeout(int fd, short event, void *arg)
{
	struct udp_con *con = arg;

	syslog(LOG_DEBUG, "Expiring UDP %s (%p)",
	    honeyd_contoa(&con->conhdr), con);

	udp_free(con);
}

struct action *
honeyd_protocol(struct template *tmpl, int proto)
{
	switch (proto) {
	case IP_PROTO_TCP:
		return (&tmpl->tcp);
	case IP_PROTO_UDP:
		return (&tmpl->udp);
	case IP_PROTO_ICMP:
		return (&tmpl->icmp);
	default:
		return (NULL);
	}
}

/* Specifies if we should drop the packet or not */
int
honeyd_block(struct template *tmpl, int proto, int number)
{
	struct port *port;
	struct action *action;

	if (tmpl == NULL)
		return (0);

	port = port_find(tmpl, proto, number);
	if (port == NULL)
		action = honeyd_protocol(tmpl, proto);
	else
		action = &port->action;

	return (action->status == PORT_FILTERED);
}

void
honeyd_varexpand(struct tcp_con *con, char *line, u_int linesize)
{
	char asc[32], *p;
	struct addr src, dst;

	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &con->con_ipdst, IP_ADDR_LEN);
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &con->con_ipsrc, IP_ADDR_LEN);

	/* Do some simple replacements */
	p = addr_ntoa(&src);
        while (strrpl(line, linesize, "$ipsrc", p) != NULL)
                ;
	p = addr_ntoa(&dst);
        while (strrpl(line, linesize, "$ipdst", p) != NULL)
                ;
	p = honeyd_logdate();
        while (strrpl(line, linesize, "$date", p) != NULL)
                ;
	snprintf(asc, sizeof(asc), "%d", con->con_sport);
        while (strrpl(line, linesize, "$sport", asc) != NULL)
                ;
	snprintf(asc, sizeof(asc), "%d", con->con_dport);
        while (strrpl(line, linesize, "$dport", asc) != NULL)
                ;
}

/*
 * Returns the configuration of a particular port by looking
 * at the default template of connections.
 */

struct action *
honeyd_port(struct template *tmpl, int proto, u_short number)
{
	struct port *port;
	struct action *action;
	
	if (tmpl == NULL)
		return (NULL);

	port = port_find(tmpl, proto, number);
	if (port == NULL)
		action = honeyd_protocol(tmpl, proto);
	else
		action = &port->action;

	return (action);
}

/* 
 * Create a proxy connection, either use precomputed addrinfo or
 * generate correct address information.
 */

int
proxy_connect(struct tuple *hdr, struct command *cmd, struct addrinfo *ai,
    char *line, void *arg)
{
	int res;

	/* Check if the address has been resolved for us already */
	if (ai == NULL) {
		char *name, *strport = line;
		u_short nport;

		name = strsep(&strport, ":");
		if (strport == NULL || (nport = atoi(strport)) == 0)
			return (-1);

		if ((ai = cmd_proxy_getinfo(name, hdr->type, nport)) == NULL)
			return (-1);
		res = cmd_proxy_connect(hdr, cmd, ai, arg);
		freeaddrinfo(ai);
	} else
		res = cmd_proxy_connect(hdr, cmd, ai, arg);

	return (res);
}

/* Cleans up receive and send buffers if cmd does not start */

void
tcp_connectfail(struct tcp_con *con)
{
	if (con->payload) {
		free(con->payload);
		con->payload = NULL;
	}
	if (con->readbuf) {
		free(con->readbuf);
		con->readbuf = NULL;
	}
}

/* Sets up buffers for a fully connected TCP connection */

int
tcp_setupconnect(struct tcp_con *con)
{
	struct tuple *hdr = &con->conhdr;

	/* Allocate buffers */
	if ((con->payload = malloc(TCP_DEFAULT_SIZE)) == NULL) {
		syslog(LOG_WARNING, "malloc %s: %m", honeyd_contoa(hdr));
		goto err;
	}
	if ((con->readbuf = malloc(TCP_DEFAULT_SIZE)) == NULL) {
		syslog(LOG_WARNING, "malloc %s: %m", honeyd_contoa(hdr));
		goto err;
	}
	con->psize = TCP_DEFAULT_SIZE;
	con->rsize = TCP_DEFAULT_SIZE;

	return (0);

 err:
	tcp_connectfail(con);

	return (-1);
}

/*
 * Returns CMD_FORK_CAP if a TCP flow must be reset because the script
 * process cap refused it, otherwise 0.
 */
int
generic_connect(struct template *tmpl, struct tuple *hdr,
    struct command *cmd, void *con)
{
	char line[512], command[512];
	char *argv[32], *p, *p2;
	struct action *action = NULL;
	struct port *port;
	int proto = 0;
	int i;

	if (hdr->type == SOCK_STREAM)
		proto = IP_PROTO_TCP;
	else
		proto = IP_PROTO_UDP;
	
	if (tmpl == NULL)
		goto out;

	if ((port = port_find(tmpl, proto, hdr->dport)) == NULL) {
		/* We need to use the default action for the protocol */
		action = proto == IP_PROTO_TCP ? &tmpl->tcp : &tmpl->udp;
	} else
		action = &port->action;

	if (action->status == PORT_OPEN) {
		if (action->action == NULL || strlen(action->action) == 0)
			goto out;
	}

	if (proto == IP_PROTO_TCP && tcp_setupconnect(con) == -1)
		goto out;

	/* Connect to the already started sub system */
	if (action->status == PORT_SUBSYSTEM) {
		if (cmd_subsystem_schedule_connect(hdr, cmd, port, con) == -1)
			goto out;
		return (0);
	} else if (action->status == PORT_PYTHON) {
#ifdef HAVE_PYTHON		
		if (pyextend_connection_start(hdr, cmd, con,
			action->action_extend) == -1)
			goto out;
		return (0);
#endif
	}

	/* 3-way handshake has been completed */
	if (proto == IP_PROTO_TCP && action->status == PORT_RESERVED) {
		if (cmd_subsystem_localconnect(hdr, cmd, port, con) == -1)
			goto err;
		return (0);
	}

	if (action->status == PORT_OPEN || action->aitop == NULL) {
		assert(action->action != NULL && strlen(action->action));
		strlcpy(line, action->action, sizeof(line));
		honeyd_varexpand(con, line, sizeof(line));
		/* Copy for print out */
		strlcpy(command, line, sizeof(line));
	}

	/* Setup a proxy connection, no need to fork a new process */
	if (action->status == PORT_PROXY) {
		int res;

		res = proxy_connect(hdr, cmd, action->aitop, line, con);
		if (res == -1)
			goto out;
		return (0);
	}

	/* Create arguments */
	p2 = line;
	for (i = 0; i < sizeof(argv)/sizeof(char *) - 1; i++) {
		if ((p = strsep(&p2, " ")) == NULL)
			break;
		if (strlen(p) == 0) {
			i--;
			continue;
		}

		argv[i] = p;
	}

	argv[i] = NULL;

	if ((i = cmd_fork(hdr, cmd, tmpl, argv[0], argv, con)) != 0) {
		/* At the cap: cmd_fork logged it (rate limited). TCP gets a
		 * RST from the caller; UDP data is dropped without ICMP and
		 * the flow retries on a later datagram. */
		if (i == CMD_FORK_CAP)
			return (CMD_FORK_CAP);
		syslog(LOG_WARNING, "script %s: %m", honeyd_contoa(hdr));
		goto err;
	}

	syslog(LOG_DEBUG, "Connection established: %s %s <-> %s",
	    proto == IP_PROTO_TCP ? "tcp" : "udp",
	    honeyd_contoa(hdr), command);
	return (0);

 err:
	if (proto == IP_PROTO_TCP)
		tcp_connectfail(con);
 out:
	syslog(LOG_DEBUG, "Connection established: %s %s",
	    proto == IP_PROTO_TCP ? "tcp" : "udp",
	    honeyd_contoa(hdr));
	return (0);
}

int
tcp_send(struct tcp_con *con, uint8_t flags, u_char *payload, u_int len)
{
	u_char *pkt;
	struct tcp_hdr *tcp;
	u_int iplen;
	int window = 16000;
	int dontfragment = 0;
	struct tcp_options options = {0, NULL};
	struct tcp_option mss_option;
	uint16_t id = rand_uint16(honeyd_rand);
	struct spoof spoof;
	struct template *tmpl = con->tmpl;

	if (con->window)
		window = con->window;

	/*
	 * The TCP personality will always set snd_una for us if necessary.
	 * snd_una maybe 0 on RST segments.
	 * Copies TCP options data into input options struct
	 */
	if (tcp_personality(con, &flags, &window, &dontfragment, &id, &options) == -1)
	{
		/* 
		 * If we do not match a personality and sent a reset
		 * segment then we do not want to include options.
		 */
		if (flags & TH_RST)
		{
			options.count = 0;
			options.options = NULL;
			window = con->window;
		}
		else if (flags & TH_SYN)
		{
			/*
			 * CWE-476/CWE-252/CWE-401: the MSS option was an
			 * unchecked malloc() written at once and never
			 * freed. tcp_personality_options() only reads it
			 * before we return, so keep it on the stack.
			 */
			memset(&mss_option, 0, sizeof(mss_option));
			mss_option.opt_type = 'M';
			mss_option.value = 0;
			options.count = 1;
			options.options = &mss_option;
		}
	}

	/* Empty flags indicates packet drop */
	if (flags == 0)
		return (0);

	if (con->flags & TCP_TARPIT)
		window = 5;

	if ((flags & TH_SYN) && !con->window)
		con->window = window;

	/* Simple window tracking
	if (window && con->rlen)
	{
		window -= con->rlen;
		if (window < 0)
			window = 0;
	}*/

	pkt = pool_alloc(pool_pkt);
	int ttl = honeyd_ttl;

	tcp = (struct tcp_hdr *)(pkt + IP_HDR_LEN);

	tcp_pack_hdr(tcp,
	    con->con_dport, con->con_sport,
	    con->snd_una, con->rcv_next, flags, window, 0);

	if((tmpl != NULL) && (tmpl->person != NULL))
	{
		struct personate * pers;
		if((pers = tcp_personality_test(con, con->tmpl->person, flags)) != NULL)
		{
			switch(pers->q)
			{
				case NONE:
					break;
				case RESERVED:
					tcp->th_x2 = 1;
					break;
				case URGENT:
					tcp->th_urp = rand_uint16(honeyd_rand);
					break;
				case BOTH:
					tcp->th_x2 = 1;
					tcp->th_urp = rand_uint16(honeyd_rand);
					break;
			}
			if((pers->ttl == pers->ttl_guess) && (pers->ttl_max != pers->ttl_min))
			{
				pers->ttl = pers->ttl_min + rand_uint32(honeyd_rand)%(pers->ttl_max - pers->ttl_min);
				pers->ttl_guess = pers->ttl+1;
			}
			ttl = pers->ttl;
		}
	}

	/* ET - options is non-NULL if a personality was found.  If a
         * personality was found, it means that this packet is a response
         * to an NMAP TCP test (not a Sequence number test, a weird flags test).
 	 * Therefore if options is not empty, you have to add the options to
         * the response otherwise the reply packet will not have the complete
         * personality.  Of the seven NMAP TCP tests, only a couple may
         * return a packet with the SYN flag.  I needed to remove the
         * requirement of the SYN flag so that the other NMAP TCP tests would
         * have the personality TCP options. */

	if (options.count != 0)
		tcp_personality_options(con, tcp, &options);

	iplen = IP_HDR_LEN + (tcp->th_off << 2) + len;

	if (tmpl != NULL)
		spoof = tmpl->spoof;
	else
		spoof = no_spoof;

	/* Src and Dst are reversed both for ip and tcp */
	ip_pack_hdr(pkt, 0, iplen, id,
	    dontfragment ? IP_DF : 0, ttl,
	    IP_PROTO_TCP, con->con_ipdst, con->con_ipsrc);

	if (len > 0)
		memcpy(pkt + IP_HDR_LEN + (tcp->th_off << 2), payload, len);

	hooks_dispatch(IP_PROTO_TCP, HD_OUTGOING, &con->conhdr,
	    pkt, iplen);

	honeyd_ip_send(pkt, iplen, spoof);

	return (len);
}

void
tcp_senddata(struct tcp_con *con, uint8_t flags)
{
	int space, sent;
	int needretrans = 0;

	do {
		space = TCP_MAX_INFLIGHT - TCP_BYTESINFLIGHT(con);
		if (space > TCP_MAX_SEND)
			space = TCP_MAX_SEND;
		else
			flags |= TH_PUSH;
		if (con->plen - con->poff < space)
			space = con->plen - con->poff;

		/* Reduce the amount of data that we can send */
		if (space && (con->flags & TCP_TARPIT))
			space = 1;

		if (con->sentfin && !con->finacked)
			flags |= TH_FIN;
		if (con->plen > space)
			flags &= ~TH_FIN;

		/*
		 * If we do not ack new data, and have nothing to send,
		 * and do not need to send a FIN, stop sending.
		 */
		if (space == 0 && con->last_acked == con->rcv_next &&
		    !(flags & TH_FIN))
			break;

		con->snd_una += con->poff;
		sent = tcp_send(con, flags, con->payload + con->poff, space);
		con->snd_una -= con->poff;
		con->poff += sent;

		/* Statistics */
		con->conhdr.sent += space;

		if (flags & TH_ACK)
			con->last_acked = con->rcv_next;

		if (con->flags & TCP_TARPIT)
			break;

	} while (sent && !con->dupacks);

	/* 
	 * We need to retransmit if we still have outstanding data or
	 * our FIN did not get acked.
	 */
	needretrans = con->poff || (con->sentfin && !con->finacked);

	if (needretrans && !evtimer_pending(con->retrans_timeout, NULL)) {
		if (!con->retrans_time)
			con->retrans_time = 1;
		generic_timeout(con->retrans_timeout, con->retrans_time);
	}
}

void
tcp_sendfin(struct tcp_con *con)
{
	con->sentfin = 1;
	tcp_senddata(con, TH_ACK);
	switch (con->state) {
	case TCP_STATE_ESTABLISHED:
		con->state = TCP_STATE_FIN_WAIT_1;
		break;
	case TCP_STATE_CLOSE_WAIT:
		con->state = TCP_STATE_CLOSING;
		break;
	}
}

void
icmp_send(struct template *tmpl,
    u_char *pkt, uint8_t tos, u_int iplen, uint16_t df, uint8_t ttl,
    int proto, ip_addr_t src, ip_addr_t dst, struct spoof spoof)
{
	struct ip_hdr ip;
	uint16_t ipid;

	/* Fake up IP hdr */
	ip.ip_src = dst;
	ip.ip_dst = src;
	ip.ip_hl = sizeof(ip) >> 2;
	ip.ip_len = 0;

	if (tmpl != NULL)
		ip_personality(tmpl, &ipid, ICMP);
	else
		ipid = rand_uint16(honeyd_rand);
	ip_pack_hdr(pkt, tos, iplen, ipid, df ? IP_DF: 0, ttl,
	    IP_PROTO_ICMP, src, dst);

	honeyd_ip_send(pkt, iplen, spoof);
}

void
icmp_error_send(struct template *tmpl, struct addr *addr,
    uint8_t type, uint8_t code, struct ip_hdr *rip, struct spoof spoof)
{
	u_char *pkt;
	u_int iplen;
	u_int voidword = 0;
	uint8_t tos = 0, df = 0, ttl = honeyd_ttl;
	int quotelen, riplen;

	quotelen = 40;

	/*
	 * Received length, read before the personality can rewrite
	 * ip_len (RIPL). Callers have checked it against the capture.
	 */
	riplen = ntohs(rip->ip_len);

	if (!icmp_error_personality(tmpl, addr, rip, &df, &tos, &quotelen, &ttl))
		return;

	/* IPL comes from the fingerprint file: bound it (PM-SCR-006) */
	if (quotelen < 0)
		quotelen = 0;
	if (riplen < quotelen)
		quotelen = riplen;
	if (quotelen > HONEYD_MTU - IP_HDR_LEN - ICMP_HDR_LEN - 4)
		quotelen = HONEYD_MTU - IP_HDR_LEN - ICMP_HDR_LEN - 4;

	iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4 + quotelen;

	pkt = pool_alloc(pool_pkt);

	if (tmpl != NULL && tmpl->person != NULL)
	{
		if(type == ICMP_UNREACH && code == ICMP_UNREACH_PORT && tmpl->person->udptest.un)
		{
			voidword = tmpl->person->udptest.un;
		}
	}

	icmp_pack_hdr_quote(pkt + IP_HDR_LEN, type, code, voidword, rip, quotelen);
	icmp_send(tmpl, pkt, tos, iplen, df ? IP_DF: 0, ttl,
	    IP_PROTO_ICMP, addr->addr_ip, rip->ip_src, spoof);
}

/*
 * icmp_echo_reply
 * rip should be the ip_header pointing to an actual raw
 * packet (has payload in it so icmp can be extracted)
 *
 * This function changes the IP and ICMP header data (i.e.
 * the ICMP packet and its IP header) to match the OS you want.
 *
 * The code, ipid, tos, offset, and ttl parameters should 
 * probably move inside this function so that the icmp_personality 
 * can have control over them.
 * 
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
	if (!icmp_personality(addr, rip, &ICMP_STRUCT)
		return;
 *
 * param rip The raw ip packet in IP header form
 * param code ICMP Header REPLY echo code, OS dependent, 0 or !0
 * param ipid IP Header id, 0 or !0(RANDOM)
 * param tos IP Header type of service, 0 or !0(0xc0)
 * param offset IP Header DF bit and offset, 0 or 1(IP_DF)
 * param ttl IP header time to live, <65, <129, or <256
 * param payload ICMP Echo request payload, should not be null, use by
 * 		ping programs to determine RTT
 * param len Length of the payload to return
 */

void
icmp_echo_reply(struct template *tmpl,
    struct ip_hdr *rip, uint8_t code, uint8_t tos,
    uint16_t offset, uint8_t ttl, u_char *payload, u_int len, struct spoof spoof)
{
	u_char *pkt;
	u_int iplen;
	struct icmp_msg_echo *icmp_echo;
       
	icmp_echo = (struct icmp_msg_echo *) ((u_char *)rip + (rip->ip_hl << 2) + ICMP_HDR_LEN);

	iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4 + len;

	if (iplen < HONEYD_MTU)
		pkt = pool_alloc(pool_pkt);
	else
		pkt = pool_alloc_size(pool_pkt, iplen);

	icmp_pack_hdr_echo(pkt + IP_HDR_LEN, ICMP_ECHOREPLY,
		code, ntohs(icmp_echo->icmp_id), ntohs(icmp_echo->icmp_seq),
		payload, len);

	icmp_send(tmpl, pkt, tos, iplen, offset, ttl,
	    IP_PROTO_ICMP, rip->ip_dst, rip->ip_src, spoof);
}

/*
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
	if (!icmp_personality(addr, rip, &ICMP_STRUCT)
		return;
		
 * ICMP_TIMESTAMP REPLY, 
 *
 * param rip The raw ip packet in IP header form
 * param icmp_rip icmp timestamp message, includes the
 * 	icmp header.
 * param ttl Time to live of the emulated OS (<65, <129, <256)
 */ 
void
icmp_timestamp_reply(struct template *tmpl, struct ip_hdr *rip,
    struct icmp_msg_timestamp* icmp_rip, uint8_t ttl, struct spoof spoof)
{
	u_char *pkt;
	u_int iplen;
	struct icmp_msg_timestamp icmp_time;
	uint8_t padding = 6;
	struct timeval tv;
	uint32_t milliseconds;

	pkt = pool_alloc(pool_pkt);
	/* Pool slots are reused: never send stale bytes as padding */
	memset(pkt, 0, IP_HDR_LEN + ICMP_HDR_LEN + 16 + padding);

	/* Milliseconds since midnight UTC, as RFC 792 asks (PM-SCR-141) */
	gettimeofday(&tv, NULL);
	milliseconds = (uint32_t)((tv.tv_sec % 86400) * 1000 +
	    tv.tv_usec / 1000);

	icmp_time.hdr.icmp_type = ICMP_TSTAMPREPLY,
	icmp_time.hdr.icmp_code = 0;
	icmp_time.icmp_id = icmp_rip->icmp_id;
	icmp_time.icmp_seq = icmp_rip->icmp_seq;

	/* For now just do the following */
	icmp_time.icmp_ts_orig = icmp_rip->icmp_ts_orig;
	icmp_time.icmp_ts_rx = htonl(milliseconds);
	icmp_time.icmp_ts_tx = htonl(milliseconds);
		
	iplen = IP_HDR_LEN + ICMP_HDR_LEN + 16 + padding; 
	/* 6 bytes of 0 at the end, why? RedHat and Windows have 6 bytes of
	 * padding to this type of message. I don't know yet why they do this.
	 */
	
	memcpy(pkt + IP_HDR_LEN, &icmp_time, sizeof(icmp_time));
	icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl,
	    IP_PROTO_ICMP, rip->ip_dst, rip->ip_src, spoof);
}

/*
 * ICMP_MASK_REPLY.

 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
	if (!icmp_personality(addr, rip, &ICMP_STRUCT)
		return;
	
 * param rip The raw ip packet in IP header form
 * param idseq id and seq of the icmp header, should be same
 * 	from the mask request icmp header.
 * param ttl time to live of OS simulated (<65, <129, or <255)
 * param mask mask of the emulated OS (i.e. 255.255.0.0)
 */ 
void
icmp_mask_reply(struct template *tmpl, struct ip_hdr *rip, 
	struct icmp_msg_idseq *idseq, uint8_t ttl, uint32_t addrmask, struct spoof spoof)
{
	u_char *pkt;
	u_int iplen;
	struct icmp_mesg_mask mask;
	
	pkt = pool_alloc(pool_pkt);

	iplen = IP_HDR_LEN + ICMP_HDR_LEN + 8; 

	mask.hdr.icmp_type = ICMP_MASKREPLY;
	mask.hdr.icmp_code = ICMP_CODE_NONE;
	
	mask.icmp_id = idseq->icmp_id;
	mask.icmp_seq = idseq->icmp_seq;
	mask.icmp_mask = htonl(addrmask);
	
	memcpy(pkt + IP_HDR_LEN, &mask, sizeof(mask));
	icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl,
	    IP_PROTO_ICMP, rip->ip_dst, rip->ip_src, spoof);
}

/*
 * We should create a structure that includes all possible ICMP
 * fields and just pass in that structure into icmp_personality
 * function and have a flag to indicate what ICMP message it is
 * and what parameters need to set to what value depend on the
 * OS we need to emulate.
 * e.g.
	if (!icmp_personality(addr, rip, &ICMP_STRUCT)
		return;
		
 * ICMP_INFO_REPLY
 *
 * param rip The raw ip packet in IP header form
 * param idseq id and seq of the icmp header, should be same
 * 	from the info request icmp header.
 * param ttl Time to live of the emulated OS (<65, <129, <256)
 */ 
void
icmp_info_reply(struct template *tmpl, struct ip_hdr *rip, 
		struct icmp_msg_idseq *idseq, uint8_t ttl, struct spoof spoof)
{
	u_char *pkt;
	u_int iplen;
	struct icmp_msg_inforeply inforeply;
	
	pkt = pool_alloc(pool_pkt);

	iplen = IP_HDR_LEN + ICMP_HDR_LEN + 4; 

	inforeply.hdr.icmp_type = ICMP_INFOREPLY;
	inforeply.hdr.icmp_code = ICMP_CODE_NONE;
	
	inforeply.idseq.icmp_id = idseq->icmp_id;
	inforeply.idseq.icmp_seq = idseq->icmp_seq;
	
	memcpy(pkt + IP_HDR_LEN, &inforeply, sizeof(inforeply));
	icmp_send(tmpl, pkt, rip->ip_tos, iplen, rip->ip_off, ttl,
	    IP_PROTO_ICMP, rip->ip_dst, rip->ip_src, spoof);
}

void
tcp_do_options(struct tcp_con *con, struct tcp_hdr *tcp, int isonsyn)
{
	u_char *p, *end;

	p = (u_char *)(tcp + 1);
	end = (u_char *)tcp + (tcp->th_off << 2);

	while (p < end) {
		struct tcp_opt opt, *tmp = (struct tcp_opt *)p;

		if (tmp->opt_type == TCP_OPT_NOP) {
			p++;
			continue;
		} else if (tmp->opt_type == TCP_OPT_EOL)
			break;

		/* Need the length byte before we can trust it */
		if (p + 2 > end)
			break;
		if (p + tmp->opt_len > end)
			break;

		memcpy(&opt, tmp, tmp->opt_len);
		switch (opt.opt_type) {
		case TCP_OPT_MSS:
			if (!isonsyn) {
				con->mss = ntohs(opt.opt_data.mss);
			}
			break;
		case TCP_OPT_WSCALE:
			if (!isonsyn) {
				con->sawwscale = 1;
			}
			break;
		case TCP_OPT_TIMESTAMP:
			con->sawtimestamp = 1;
			con->echotimestamp = opt.opt_data.timestamp[0];
			break;
		default:
			break;
		}

		p += opt.opt_len;
		if (opt.opt_len < 1)
			break;
	}
}

void
generic_timeout(struct event *ev, int seconds)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = seconds;
	evtimer_add(ev, &tv);
}

/* Checks that the sequence number is where we expect it to be */
#define TCP_CHECK_SEQ_OR_ACK	do { \
		int has_ack = tcp->th_flags & TH_ACK; \
		if (tcp->th_flags & TH_RST) { \
			if (th_seq != con->rcv_next) \
				goto drop; \
			goto close; \
		} \
		if (!has_ack) \
			goto drop; \
		if (TCP_SEQ_LT(th_ack, con->snd_una -1)) { \
			/* we used to drop only RST packets, now we drop everything */ \
				goto drop; \
		}\
		/* Don't accept out of order data */ \
		if (TCP_SEQ_GT(th_seq, con->rcv_next)) { \
			if (has_ack) \
				tcp_send(con, TH_ACK, NULL, 0); \
			goto drop; \
		} \
} while(0)

#define TCP_RECV_SEND_DATA	do { \
		/* Find new data: doff contains already acked data */ \
		dlen = ntohs(ip->ip_len) - (ip->ip_hl * 4) -(tcp->th_off * 4);\
		doff = con->rcv_next - th_seq; \
		if (doff > dlen ||(doff == dlen && (tiflags & TH_FIN) == 0)) {\
			/* Need to ACK this segments */ \
			tiflags &= ~TH_FIN; \
			doff = dlen; \
		} \
		dlen -= doff; \
\
		con->conhdr.received += dlen; \
\
		if (con->plen || con->cmd_pfd > 0) { \
			int ackinc = 0; \
			dlen = tcp_add_readbuf(con, data + doff, dlen); \
\
			acked = th_ack - con->snd_una; \
			if (acked > con->plen) { \
				if (con->sentfin && acked == con->plen + 1){ \
					con->finacked = 1; \
					ackinc = 1; \
				} \
				acked = con->plen; \
			} \
			tcp_drain_payload(con, acked); \
			acked += ackinc; \
			if (con->cmd_pfd == -1 && con->plen <= TCP_MAX_SEND) \
				con->sentfin = 1; \
		} else if (con->cmd_pfd == -1) { \
			tcp_add_readbuf(con, data + doff, dlen); \
		} \
		if (con->sentfin) { \
			if (th_ack == con->snd_una + 1) { \
				acked = 1; \
				con->finacked = 1; \
			} \
		} \
		if (acked == 0 && con->poff) { \
			con->dupacks++; \
			if (con->dupacks >= 3) { \
				con->dupacks = 3; \
				con->poff = 0; \
			} \
		} else if (acked) { \
			con->retrans_time = 0; \
			evtimer_del(con->retrans_timeout); \
			con->dupacks=0; \
		} \
} while (0)

void
tcp_recv_cb(struct template *tmpl, const struct interface* iface, u_char *pkt, u_short pktlen)
{
	char *comment = NULL;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	struct tcp_con *con;
	struct action *action;
	uint32_t th_seq, th_ack;
	uint32_t acked = 0;
	uint16_t th_sum;
	u_char *data;
	u_int dlen, doff;
	uint8_t tiflags, flags;

	ip = (struct ip_hdr *)pkt;
	if (pktlen < (ip->ip_hl << 2) + TCP_HDR_LEN)
		return;

	tcp = (struct tcp_hdr *)(pkt + (ip->ip_hl << 2));
	/* The data offset must cover the header and stay inside the packet */
	if (tcp->th_off < (TCP_HDR_LEN >> 2) ||
	    pktlen < (ip->ip_hl << 2) + (tcp->th_off << 2))
		return;
	data = (u_char *)(pkt + (ip->ip_hl*4) + (tcp->th_off*4));

	/* 
	 * Check if we have a real connection header for this connection, so
	 * that we can look at potential flags like local origination.
	 */
	honeyd_settcp(&honeyd_tmp, iface, ip, tcp, INITIATED_BY_EXTERNAL);
	con = (struct tcp_con *)SPLAY_FIND(tree, &tcpcons, &honeyd_tmp.conhdr);

	hooks_dispatch(ip->ip_p, HD_INCOMING, 
	    con != NULL ? &con->conhdr : &honeyd_tmp.conhdr, pkt, pktlen);
	
	if (honeyd_block(tmpl, IP_PROTO_TCP, ntohs(tcp->th_dport)))
		goto justlog;

	/* Check the checksum the brutal way, until libdnet supports */
	th_sum = tcp->th_sum;
	ip_checksum(ip, pktlen);
	if (th_sum != tcp->th_sum)
		goto justlog;

	action = honeyd_port(tmpl, IP_PROTO_TCP, ntohs(tcp->th_dport));
	honeyd_tmp.state = action == NULL || PORT_ISOPEN(action) ? 
	    TCP_STATE_LISTEN : TCP_STATE_CLOSED;

	tiflags = tcp->th_flags;

	if (con == NULL) {
		if (honeyd_tmp.state != TCP_STATE_LISTEN)
			goto kill;
		if ((tiflags & TH_SYN) == 0) 
			goto kill;

		if (tiflags & ~TH_SYN &
		    (TH_FIN|TH_RST|TH_PUSH|TH_ACK|TH_URG)) {
			int win = 0, df = 0;
			uint16_t id;

			flags = TH_SYN|TH_ACK;
			if (tiflags & (TH_FIN|TH_RST))
				comment = " {Honeyd Scanner?}";

			/* 
			 * Some stacks might reply to a packet like
			 * this.  So, check the personalities and see
			 * what the flags say.
			 */
			if (tcp_personality(&honeyd_tmp,
				&flags, &win, &df, &id, NULL) == -1) {
				/* 
				 * These flags normally cause a termination,
				 * so drop or reset the connection as we did
				 * not match a fingerprint.
				 */
				if (tiflags & (TH_RST|TH_ACK))
					goto kill;
				tiflags &= ~TH_FIN;
			}

			/* Just drop the packet */
			if (flags & TH_RST)
				goto kill;
		}

		syslog(LOG_DEBUG, "Connection request: tcp %s",
		    honeyd_contoa(&honeyd_tmp.conhdr));

		/* Check if we should drop this SYN packet */
		if (tmpl != NULL && tmpl->drop_synrate) {
			uint16_t value;
			value = rand_uint16(honeyd_rand) % (100*100);
			if (value < tmpl->drop_synrate)
				goto justlog;
		}

		/* Refuse the flow if the template has too many references */
		if (template_ref_full(tmpl)) {
			syslog(LOG_WARNING, "Too many flows for template: tcp %s",
			    honeyd_contoa(&honeyd_tmp.conhdr));
			goto kill;
		}

		/* Refuse the flow if its source has too many flows */
		if (honeyd_source_full(ip->ip_src)) {
			syslog(LOG_WARNING, "Too many flows from source: tcp %s",
			    honeyd_contoa(&honeyd_tmp.conhdr));
			goto kill;
		}

		/* Out of memory is dealt with by killing the connection */
		if ((con = tcp_new(iface, ip, tcp, INITIATED_BY_EXTERNAL)) == NULL) {
			goto kill;
		}
		honeyd_source_take(&con->conhdr);
		con->rcv_flags = tiflags;

		/* Check if this connection is a tar pit */
		if (action != NULL && (action->flags & PORT_TARPIT))
			con->flags |= TCP_TARPIT;

		tcp_do_options(con, tcp, 1);

		con->tmpl = template_ref(tmpl);
		con->rcv_next = ntohl(tcp->th_seq) + 1;
		con->snd_una = ntohl(tcp->th_ack) + 1;
		con->recv_window = ntohs(tcp->th_win);
		con->nmap_opt = *(uint8_t*)(data-1);

		con->state = TCP_STATE_LISTEN;
		tcp_send(con, TH_SYN|TH_ACK, NULL, 0);

		con->snd_una++;
		con->state = TCP_STATE_SYN_RECEIVED;

		generic_timeout(con->conhdr.timeout, HONEYD_SYN_WAIT);

		/* Get initial value from personality */
		con->retrans_time = 3;
		generic_timeout(con->retrans_timeout, con->retrans_time);

		return;
	}

	/*
	 * Subsystems can remove ports on the fly - even when parts of the
	 * 3-way handshake are in progress already.
	 */

	if (action != NULL) {
		switch (action->status) {
		case PORT_CLOSED:
			goto dropwithreset;
		case PORT_FILTERED:
			goto drop;
		default:
			break;
		}
	}

	th_seq = ntohl(tcp->th_seq);
	th_ack = ntohl(tcp->th_ack);

	con->rcv_flags = tiflags;

	switch (con->state)
	{
		case TCP_STATE_SYN_SENT:
			if (tiflags & TH_RST)
				goto close;
			if (!(tiflags & TH_SYN))
				goto drop;
			if (!(tiflags & TH_ACK))
				goto drop;

			/* No simultaneous open allowed */
			if (th_ack != con->snd_una - 1)
				goto dropwithreset;

			tcp_do_options(con, tcp, 0);

			con->rcv_next = th_seq + 1;
			tcp_send(con, TH_ACK, NULL, 0);

			con->state = TCP_STATE_ESTABLISHED;
			if (generic_connect(tmpl, &con->conhdr, &con->cmd,
				con) == CMD_FORK_CAP)
				goto dropwithreset;
			break;

		case TCP_STATE_SYN_RECEIVED:
			if (tiflags & TH_ACK) {
				if (tiflags & TH_SYN)
					goto dropwithreset;
				if (th_ack != (con->snd_una))
					goto dropwithreset;
			}
			if (tiflags & TH_SYN) {
				if (th_seq != con->rcv_next)
					goto dropwithreset;
				con->snd_una--;
				tcp_send(con, TH_SYN|TH_ACK, NULL,0);
				con->snd_una++;
				return;
			}

			if (tiflags & TH_RST)
				goto close;
			if (!(tiflags & TH_ACK))
				goto drop;

			tcp_do_options(con, tcp, 0);

			/* Clear retransmit timeout */
			con->retrans_time = 0;
			evtimer_del(con->retrans_timeout);

			connection_update(&tcplru, &con->conhdr);

			con->state = TCP_STATE_ESTABLISHED;
			if (generic_connect(tmpl, &con->conhdr, &con->cmd,
				con) == CMD_FORK_CAP)
				goto dropwithreset;
			break;

		case TCP_STATE_ESTABLISHED:
			TCP_CHECK_SEQ_OR_ACK;

			TCP_RECV_SEND_DATA;

			tcp_do_options(con, tcp, 0);

			connection_update(&tcplru, &con->conhdr);

			if ((tiflags & TH_FIN) && !(con->flags & TCP_TARPIT))
			{
				if (con->cmd_pfd > 0)
				{
					if (con->rlen == 0)
					{
						/*
						 * If we already transmitted all data,
						 * we can completely shutdown the write
						 * part of the connection.
						 */
						shutdown(con->cmd_pfd, SHUT_WR);
					}
					else
					{
						/*
						 * If we still have data to write to
						 * our child process, we need to delay
						 * the shutdown until later.
						 */
						con->cmd.fdgotfin = 1;
					}
				}
				else
				{
					con->sentfin = 1;
				}
				con->state = TCP_STATE_CLOSE_WAIT;
				dlen++;
			}

			con->rcv_next += dlen;
			con->snd_una += acked;
			if (con->sentfin) {
				tcp_sendfin(con);
			} else
				tcp_senddata(con, TH_ACK);
			break;

		case TCP_STATE_CLOSE_WAIT:
			TCP_CHECK_SEQ_OR_ACK;

			TCP_RECV_SEND_DATA;

			tcp_do_options(con, tcp, 0);

			connection_update(&tcplru, &con->conhdr);

			if (dlen)
				goto dropwithreset;
			con->snd_una += acked;
			tcp_senddata(con, TH_ACK);
			if (con->sentfin)
				con->state = TCP_STATE_CLOSING;

			break;

		case TCP_STATE_CLOSING:
			TCP_CHECK_SEQ_OR_ACK;

			TCP_RECV_SEND_DATA;

			tcp_do_options(con, tcp, 0);

			connection_update(&tcplru, &con->conhdr);

			con->snd_una += acked;
			if (con->finacked)
				goto closed;
			tcp_senddata(con, TH_ACK);
			break;

		case TCP_STATE_FIN_WAIT_1:
			TCP_CHECK_SEQ_OR_ACK;

			TCP_RECV_SEND_DATA;

			tcp_do_options(con, tcp, 0);

			if ((tiflags & TH_FIN) && !(con->flags & TCP_TARPIT)) {
				con->state = TCP_STATE_CLOSING;
				generic_timeout(con->conhdr.timeout, HONEYD_CLOSE_WAIT);
				dlen++;
			} else {
				connection_update(&tcplru, &con->conhdr);
			}

			con->rcv_next += dlen;
			con->snd_una += acked;
			tcp_senddata(con, TH_ACK);
			break;
	}

	return;

 kill:
	honeyd_log_probe(honeyd_logfp, IP_PROTO_TCP, &honeyd_tmp.conhdr,
	    pktlen, tcp->th_flags, comment);

	/* Do not kill on reset */
	if (tiflags & TH_RST)
		return;

	syslog(LOG_DEBUG, "Killing %s connection: tcp %s",
	    (tcp->th_flags & TH_SYN) ? "attempted" : "unknown",
	    honeyd_contoa(&honeyd_tmp.conhdr));

	/* Fake connection element */
	honeyd_tmp.rcv_next = ntohl(tcp->th_seq) + 1;
	honeyd_tmp.snd_una = ntohl(tcp->th_ack) +1;
	honeyd_tmp.tmpl = tmpl;
	honeyd_tmp.rcv_flags = tiflags;

	/* 
	 * The TCP personality matches, all the sequence numbers are
	 * going to be taken care off via the Nmap fingerprint,
	 * otherwise, we are going to fill in reasonable defaults.
	 */
	if (tcp_personality_match(&honeyd_tmp, flags))
	{
		honeyd_tmp.rcv_next = ntohl(tcp->th_seq) + 1;
		honeyd_tmp.snd_una = ntohl(tcp->th_ack)+1;
	}
	else if (tiflags & TH_ACK)
	{
		flags = TH_RST;
		honeyd_tmp.rcv_next = 0;
		honeyd_tmp.snd_una = ntohl(tcp->th_ack)+1;
	}
	else
	{
		flags = TH_RST | TH_ACK;
		honeyd_tmp.rcv_next = ntohl(tcp->th_seq)+1;
		honeyd_tmp.snd_una = 0;
	}

	/* 
	 * Even though options processing does not make any sense on 
	 * RST segment, some stacks apparently do it anyway.
	 */
	tcp_do_options(&honeyd_tmp, tcp, 1);

	tcp_send(&honeyd_tmp, flags, NULL, 0);
	return;

 close:
	if (tiflags & TH_RST) {
		syslog(LOG_DEBUG, "Connection dropped by reset: tcp %s",
		    honeyd_contoa(&con->conhdr));
	}
	goto free;

 dropwithreset:
	syslog(LOG_DEBUG, "Connection dropped with reset: tcp %s",
	    honeyd_contoa(&con->conhdr));
	if ((tiflags & TH_RST) == 0)
		tcp_send(con, TH_RST|TH_ACK, NULL, 0);
 free:
	tcp_free(con);
	return;
 closed:
	syslog(LOG_DEBUG, "Connection closed: tcp %s",
	    honeyd_contoa(&con->conhdr));
	/* Forget about this connection */
	tcp_free(con);
 drop:
	return;

 justlog:
	honeyd_settcp(&honeyd_tmp, iface, ip, tcp, INITIATED_BY_EXTERNAL);
	honeyd_log_probe(honeyd_logfp, IP_PROTO_TCP,&honeyd_tmp.conhdr,
	    pktlen, tcp->th_flags, comment);
}

int
udp_send(struct udp_con *con, u_char *payload, u_int len)
{
	u_char *pkt;
	struct udp_hdr *udp;
	u_int iplen;
	uint16_t id = rand_uint16(honeyd_rand);
	int dontfragment = 0;
	struct spoof spoof;
	struct template *tmpl = con->tmpl;
	uint8_t ttl = honeyd_ttl;

	/* Statistics */
	con->conhdr.sent += len;

	ip_personality(tmpl, &id, TCP_CLOSED);

	/*
	 * A flow may have no template, and a template may have no
	 * personality: use the default TTL then, as the TCP and ICMP reply
	 * paths do (CWE-476).
	 */
	if (tmpl != NULL && tmpl->person != NULL)
		ttl = tmpl->person->udptest.ttl;

	pkt = pool_alloc(pool_pkt);

	udp = (struct udp_hdr *)(pkt + IP_HDR_LEN);
	udp_pack_hdr(udp, con->con_dport, con->con_sport, UDP_HDR_LEN + len);

	iplen = IP_HDR_LEN + UDP_HDR_LEN + len;

	/* Src and Dst are reversed both for ip and tcp */
	ip_pack_hdr(pkt, 0, iplen, id,
	    dontfragment ? IP_DF : 0, ttl,
	    IP_PROTO_UDP, con->con_ipdst, con->con_ipsrc);

	memcpy(pkt + IP_HDR_LEN + UDP_HDR_LEN, payload, len);

 	if (tmpl)
 		spoof = tmpl->spoof;
 	else
 		spoof = no_spoof;

	ip_checksum(pkt, iplen);
	
	hooks_dispatch(IP_PROTO_UDP, HD_OUTGOING, &con->conhdr,
	    pkt, iplen);

	honeyd_ip_send(pkt, iplen, spoof);

	generic_timeout(con->conhdr.timeout, HONEYD_UDP_WAIT);
	udp_lru_update(con);

	return (len);
}

struct packet_wrapper {
	const struct interface* iface;
	u_char *pkt;
	u_short pktlen;
	u_char unicast;
};

int
handle_udp_packet(struct template *tmpl, void *wrapper)
{
	u_char *pkt;
	u_short pktlen;
	struct udp_con *con, honeyd_udp;
	struct addr addr;
	struct spoof spoof;
	char unicast;
	char isBroadcast = 0;
	int i;
	
	uint16_t uh_sum;
	u_char *data;
	u_int dlen;
	u_short portnum;

	struct packet_wrapper *pwrapper = (struct packet_wrapper*)wrapper;
	pkt = pwrapper->pkt;
	pktlen = pwrapper->pktlen;
	unicast = pwrapper->unicast;

	struct ip_hdr *ip = NULL;
	struct udp_hdr *udp;
	ip = (struct ip_hdr *)pkt;
	udp = (struct udp_hdr *)(pkt + (ip->ip_hl << 2));

	if (pktlen < (ip->ip_hl << 2) + UDP_HDR_LEN)
		return 0;

	ip_addr_t templateIp;
	int res = inet_pton(AF_INET, tmpl->name, &(templateIp));

	/* Check the packet checksum, if no uh_sum is set, we ignore it */
	uh_sum = udp->uh_sum;
	ip_checksum(ip, pktlen);
	if ((uh_sum && uh_sum != udp->uh_sum))
		goto justlog;

	if (!unicast) {
		/* If this isn't a template for a real honeypot instance, return */
		if (res != 1)
			return 0;

		/* Is it to the global broadcast address? */
		if (ip->ip_dst == 0xFFFFFFFF) {
			isBroadcast = 1;
		/* Is it MDNS multicast address? */
		} else if (ip->ip_dst == 0xFB0000E0) {
			isBroadcast = 1;
		/* Is it to the honeypot interface's subnet broadcast address? */
		} else if (tmpl->inter != NULL &&
			ip->ip_dst == tmpl->inter->subnetBcastAddress) {
			isBroadcast = 1;
		} else {
			isBroadcast = 0;
		}

		if (!isBroadcast)
			return 0;

		// If it's broadcast, was it a broadcast packet on our interface?
		if (pwrapper->iface != tmpl->inter)
			return 0;
	}


	/*
	 * Check if we have a real connection header for this connection, so
	 * that we can look at potential flags like local origination.
	 */
	honeyd_setudp(&honeyd_udp, ip, udp, INITIATED_BY_EXTERNAL);
	if (!unicast && isBroadcast)
		honeyd_udp.conhdr.ip_dst = templateIp;
	con = (struct udp_con *)SPLAY_FIND(tree, &udpcons, &honeyd_udp.conhdr);

	hooks_dispatch(ip->ip_p, HD_INCOMING,
		con != NULL ? &con->conhdr : &honeyd_udp.conhdr, pkt, pktlen);

	data = (u_char *)(pkt + (ip->ip_hl*4) + UDP_HDR_LEN);
	dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - UDP_HDR_LEN;
	if (dlen != (ntohs(udp->uh_ulen) - UDP_HDR_LEN))
		return 0;

	portnum = ntohs(udp->uh_dport);
	if (honeyd_block(tmpl, IP_PROTO_UDP, portnum))
		goto justlog;

	if (con == NULL) {
		struct action *action;
		action = honeyd_port(tmpl, IP_PROTO_UDP, portnum);

		/* Send unreachable on closed port */
		if (action == NULL || !PORT_ISOPEN(action)) {
			if (unicast) {
				syslog(LOG_DEBUG, "Connection to closed port: udp %s",
						honeyd_contoa(&honeyd_udp.conhdr));
				goto closed;
			} else {
				return 0;
			}
		}

		/* Otherwise create a new udp connection */
		syslog(LOG_DEBUG, "Connection: udp %s",
			honeyd_contoa(&honeyd_udp.conhdr));

		/* Refuse the flow if the template has too many references */
		if (template_ref_full(tmpl)) {
			syslog(LOG_WARNING, "Too many flows for template: udp %s",
			    honeyd_contoa(&honeyd_udp.conhdr));
			if (unicast)
				goto closed;
			else
				return 0;
		}

		/* Refuse the flow if its source has too many flows */
		if (honeyd_source_full(ip->ip_src)) {
			syslog(LOG_WARNING, "Too many flows from source: udp %s",
			    honeyd_contoa(&honeyd_udp.conhdr));
			if (unicast)
				goto closed;
			else
				return 0;
		}

		/*
		 * PM-SCR-160: allocate before making room under the UDP flow
		 * cap, so a failed allocation never evicts a live flow. Out of
		 * memory drops the packet quietly, without an ICMP error.
		 */
		if ((con = calloc(1, sizeof(struct udp_con))) == NULL) {
			syslog(LOG_ERR, "%s: calloc: %m", __func__);
			return 0;
		}
		honeyd_setudp(con, ip, udp, INITIATED_BY_EXTERNAL);

		if (!unicast && isBroadcast)
			con->conhdr.ip_dst = templateIp;

		/*
		 * PM-SCR-159: create the idle timer before the flow is listed,
		 * counted or takes a source reference, so a failure leaves
		 * nothing to undo but the allocation.
		 */
		con->conhdr.timeout = evtimer_new(libevent_base, honeyd_udp_timeout, con);
		if (con->conhdr.timeout == NULL) {
			syslog(LOG_ERR, "%s: evtimer_new failed", __func__);
			free(con);
			return 0;
		}

		/* The new flow is not on udplru yet, so it is never evicted */
		udp_make_room();
		udp_insert(con);
		honeyd_source_take(&con->conhdr);
		honeyd_log_flownew(honeyd_logfp, IP_PROTO_UDP, &con->conhdr);

		con->tmpl = template_ref(tmpl);
		con->script_refused = generic_connect(tmpl, &con->conhdr,
		    &con->cmd, con) == CMD_FORK_CAP;
	} else if (con->script_refused && cmd_script_room(&con->conhdr)) {
		/* Refused at the script cap before (PM-SCR-222): once there
		 * is room, a later datagram starts the script */
		con->script_refused = generic_connect(con->tmpl, &con->conhdr,
		    &con->cmd, con) == CMD_FORK_CAP;
	}

	/* Keep this state active */
	generic_timeout(con->conhdr.timeout, HONEYD_UDP_WAIT);
	udp_lru_update(con);
	con->softerrors = 0;

	/* Statistics */
	con->conhdr.received += dlen;

	/* Add the data to the incoming buffers */
	udp_add_readbuf(con, data, dlen);
	return 0;

 closed:
	honeyd_log_probe(honeyd_logfp, IP_PROTO_UDP, &honeyd_udp.conhdr,
		pktlen, 0, NULL);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

	/*
	 * compute possible spoofed source for this error response to a UDP packet
	 */
	if (tmpl)
		spoof = tmpl->spoof;
	else
		spoof = no_spoof;
	// compute_spoof(&spoof, tmpl, &tmpl->spoof, ip->ip_src, ip->ip_dst);
	print_spoof("udp_recv_cb after", spoof);

	icmp_error_send(tmpl, &addr, ICMP_UNREACH, ICMP_UNREACH_PORT, ip, spoof);
	return 0;

 justlog:
	honeyd_setudp(&honeyd_udp, ip, udp, INITIATED_BY_EXTERNAL);
	if (!unicast && isBroadcast)
		honeyd_udp.conhdr.ip_dst = templateIp;
	honeyd_log_probe(honeyd_logfp, IP_PROTO_UDP, &honeyd_udp.conhdr,
		pktlen, 0, NULL);
	return 0;
}


void
udp_recv_cb(struct template *tmpl, const struct interface* iface, u_char *pkt, u_short pktlen)
{
	struct ip_hdr *ip = NULL;
	ip = (struct ip_hdr *)pkt;

	if (pktlen < (ip->ip_hl << 2) + UDP_HDR_LEN)
		return;

	struct packet_wrapper wrapper;
	wrapper.iface = iface;
	wrapper.pkt = pkt;
	wrapper.pktlen = pktlen;

	// Send the packet to all of the templates and let handle_udp_packet
	// figure out if it's a match to a subnet
	if (tmpl == NULL || !strcmp("default", tmpl->name))  {
		wrapper.unicast = 0;
		template_iterate(&handle_udp_packet, (void*)&wrapper);
	} else {
		wrapper.unicast = 1;
		handle_udp_packet(tmpl, (void*)&wrapper);
	}
}

void
icmp_recv_cb(struct template *tmpl, u_char *pkt, u_short pktlen)
{
	struct ip_hdr *ip = NULL;
	struct icmp_hdr *icmp;
	struct icmp_msg_quote *icmp_quote;
	struct ip_hdr *rip, tmpip;
	struct udp_hdr *udp, tmpudp;
	struct udp_con *con, honeyd_udp;
	/* YM - ICMP Messages */
	struct icmp_msg_echo *icmp_echo;
	struct icmp_msg_timestamp *icmp_tstamp;
	struct icmp_msg_idseq *icmp_idseq;
	struct xp_fingerprint *xp_print = NULL;  /* JVR */
	struct personate_ie *nmap_print = NULL;
	struct tuple icmphdr;
	struct addr src, dst;
	struct spoof spoof;
	char asrc[100], adst[100];
	char osrc[100], odst[100];
	char ssrc[100], sdst[100];
	u_char *dat;
	uint16_t cksum;
	int dlen;

	ip = (struct ip_hdr *)pkt;

	if (pktlen < (ip->ip_hl << 2) + ICMP_HDR_LEN)
		return;

	icmp = (struct icmp_hdr *)(pkt + (ip->ip_hl << 2));

	icmphdr.local = 0;
	icmphdr.ip_src = ip->ip_src;
	icmphdr.ip_dst = ip->ip_dst;
	icmphdr.type = SOCK_RAW;
	icmphdr.sport = icmp->icmp_type; /* XXX - horrible cludge */
	icmphdr.dport = icmp->icmp_code;
	honeyd_log_probe(honeyd_logfp, IP_PROTO_ICMP, &icmphdr, pktlen, 0, NULL);

	/* We can block ICMP, too */
	if (tmpl && (tmpl->icmp.status == PORT_FILTERED || tmpl->icmp.status == PORT_CLOSED))
		return;

	if (tmpl != NULL && tmpl->person != NULL)
		xp_print = tmpl->person->xp_fprint;
	if (tmpl != NULL && tmpl->person != NULL)
		nmap_print = &tmpl->person->ie_test;

	/* Without xprobe or nmap fingerprint, we understand only ECHO and UNREACH */
	if ((xp_print == NULL) && (nmap_print == NULL))
	{
		if ((icmp->icmp_type != ICMP_ECHO) && !
				((icmp->icmp_type == ICMP_UNREACH) && (icmp->icmp_code == ICMP_UNREACH_PORT)))
		{
			return;
		}
	}

	cksum = icmp->icmp_cksum;
	ip_checksum(ip, pktlen);
	if (cksum != icmp->icmp_cksum)
		return;

	dlen = pktlen - (ip->ip_hl << 2) - ICMP_HDR_LEN;
	dlen -= 4;

	if (dlen < 0)
		return;

	/* AscII representation of original addresses */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	addr_ntop(&src, osrc, sizeof(osrc));
	addr_ntop(&dst, odst, sizeof(odst));

	if (tmpl)
		spoof = tmpl->spoof;
	else
		spoof = no_spoof;

	addr_ntop(&spoof.new_src, ssrc, sizeof(ssrc));
	addr_ntop(&spoof.new_dst, sdst, sizeof(sdst));

	if (spoof.new_src.addr_type != ADDR_TYPE_NONE)
		snprintf(adst, sizeof(adst), "%s (was %s)", ssrc, odst);
	else
		snprintf(adst, sizeof(adst), "%s", odst);

	if (spoof.new_dst.addr_type != ADDR_TYPE_NONE)
		snprintf(asrc, sizeof(asrc), "%s (was %s)", sdst, osrc);
	else
		snprintf(asrc, sizeof(asrc), "%s", osrc);

	switch (icmp->icmp_type)
	{
		case ICMP_ECHO:
		{
			icmp_echo = (struct icmp_msg_echo *)(icmp + 1);
			dat = (u_char *)(icmp_echo + 1);

			syslog(LOG_DEBUG, "Sending ICMP Echo Reply: %s -> %s",
				adst, asrc);

			if(((icmp->icmp_code == 9) && (ip->ip_tos == 0)) || ((icmp->icmp_code == 0) && (ip->ip_tos == 4)))
			{
				//If we don't have an icmp personality, just quit (no response, aka filtered/closed)
				if(nmap_print == NULL)
				{
					return;
				}

				if(nmap_print->response)
				{
					uint8_t code = 0;
					switch(nmap_print->replyCode)
					{
						case 'Z':
						{
							code = 0;
							break;
						}
						case 'S':
						{
							code = icmp->icmp_code;
							break;
						}
						//This case is just something thats not the others not sure what to use here
							//but it doesn't occur currently in the nmap db
						case 'O':
						{
							code = 7;
							break;
						}
						case 'N':
						{
							code = nmap_print->replyVal;
							break;
						}
					}
					uint16_t offset = 0;
					//for case N, df bit = 0, so do nothing
					switch(nmap_print->dfi_test)
					{
						//echos DF of probe
						case 'S':
							//16384 is an empty offset field with the DF bit set to 1
							//Create empty offset field with the DF bit of the probe.
							offset = (ntohs(ip->ip_off) & 16384);
							break;

						//DF bit is set in this case;
						case 'Y':
							offset = 16384;
							break;

						//DF Bit is toggled
						case 'O':
							//49151 is the inverse of an empty offset field with the DF bit set to 1
							// we mask all but the DF bit to 1, the inverse is an empty offset field
							// with the DF bit toggled.
							offset = ~(ntohs(ip->ip_off) | 49151);
							break;
					}
					if((nmap_print->ttl == nmap_print->ttl_guess) && (nmap_print->ttl_max != nmap_print->ttl_min))
					{
						extern rand_t *honeyd_rand;
						nmap_print->ttl = nmap_print->ttl_min + rand_uint32(honeyd_rand)%(nmap_print->ttl_max - nmap_print->ttl_min);
						nmap_print->ttl_guess = nmap_print->ttl+1;
					}
					//In this first probe the TOS is zero so we just set it to 0 as well
					icmp_echo_reply(tmpl, ip, code, 0, offset, nmap_print->ttl, dat, dlen, spoof);
				}
				break;
			}

			if (xp_print)
			{
				/* ym: Use our own icmp echo reply function */
				icmp_echo_reply(tmpl, ip, xp_print->flags.icmp_echo_code,
					xp_print->flags.icmp_echo_tos_bits ? ip->ip_tos : 0,
					xp_print->flags.icmp_echo_df_bit ? IP_DF : 0,
					xp_print->ttl_vals.icmp_echo_reply_ttl.ttl_val,
					dat, dlen, spoof);
			}
			else
			{
				icmp_echo_reply(tmpl, ip, ICMP_CODE_NONE, 0, 0, honeyd_ttl, dat, dlen, spoof);
			}
			break;
		}
		case ICMP_UNREACH:
		{
			/* Only port unreachable at the moment */
			icmp_quote = (struct icmp_msg_quote *)(icmp + 1);
			rip = (struct ip_hdr *)(&icmp_quote->icmp_ip);

			/* The quoted IP and UDP headers must be present */
			if (dlen < IP_HDR_LEN)
				break;
			if ((rip->ip_hl << 2) < IP_HDR_LEN ||
			    dlen < (rip->ip_hl << 2) + UDP_HDR_LEN)
				break;

			if (rip->ip_p != IP_PROTO_UDP)
				break;

			udp = (struct udp_hdr *)((u_char *)rip + (rip->ip_hl<<2));
			tmpip.ip_src = rip->ip_dst;
			tmpip.ip_dst = rip->ip_src;
			tmpudp.uh_sport = udp->uh_dport;
			tmpudp.uh_dport = udp->uh_sport;
			honeyd_setudp(&honeyd_udp, &tmpip, &tmpudp, INITIATED_BY_EXTERNAL);

			/* Find matching state */
			con = (struct udp_con *)SPLAY_FIND(tree, &udpcons,
				&honeyd_udp.conhdr);
			if (con == NULL)
				break;

			con->softerrors++;
			syslog(LOG_DEBUG,
				"Received port unreachable: %s -> %s: errors %d",
				asrc, adst, con->softerrors);
			if (con->softerrors >= HONEYD_MAX_SOFTERRS)
				udp_free(con);

			break;

		}
		/* YM: Add ICMP Timestamp reply capability */
		case ICMP_TSTAMP:
		{
				/* Sometimes xp_print can be null here... probably shouldn't be, this is just a quick fix */
				if (xp_print == NULL)
					return;

				/* Three timestamps follow id and seq (PM-SCR-002) */
				if (dlen < 12)
					return;

			/* Happens only if xp_print != NULL */
				if (xp_print->flags.icmp_timestamp_reply)
				{
					icmp_tstamp = (struct icmp_msg_timestamp *)
						((u_char*)pkt + (ip->ip_hl << 2));

					syslog(LOG_DEBUG, "Sending ICMP Timestamp Reply: %s -> %s", adst, asrc);

					icmp_timestamp_reply(tmpl, ip, icmp_tstamp,
						xp_print->ttl_vals.icmp_timestamp_reply_ttl.ttl_val, spoof);
				}
				break;
		}
		/* YM: Added ICMP Address Mask reply capability */
		case ICMP_MASK:
		{
			/* No xprobe fingerprint: no reply */
				if (xp_print != NULL &&
				    xp_print->flags.icmp_addrmask_reply) {
				icmp_idseq = (struct icmp_msg_idseq *)(icmp + 1);

				syslog(LOG_DEBUG, "Sending ICMP Address Mask Reply: %s -> %s",
					adst, asrc);

				icmp_mask_reply(tmpl, ip, icmp_idseq,
					xp_print->ttl_vals.icmp_addrmask_reply_ttl.ttl_val,
					HONEYD_ADDR_MASK, spoof);
			}
			break;

		}
		/* YM: Added ICMP Information reply capability */
		case ICMP_INFO:
		{
			/* No xprobe fingerprint: no reply */
				if (xp_print != NULL &&
				    xp_print->flags.icmp_info_reply) {
				icmp_idseq = (struct icmp_msg_idseq *)(icmp + 1);

				syslog(LOG_DEBUG, "Sending ICMP Info Reply: %s -> %s",
					adst, asrc);

				icmp_info_reply(tmpl, ip, icmp_idseq,
					xp_print->ttl_vals.icmp_info_reply_ttl.ttl_val, spoof);
			}
			break;
		}
		default:
		{
			break;
		}
	}
}

void
honeyd_dispatch(struct template *tmpl, const struct interface* iface, struct ip_hdr *ip, u_short iplen)
{
	struct tuple iphdr;

	iphdr.ip_src = ip->ip_src;
	iphdr.ip_dst = ip->ip_dst;
	iphdr.type = -1;
	
	/*
	 * We define a hook here for packet interception -- plugins
	 * can use it to do fun stuff with the packets.
	 */

	switch(ip->ip_p) {
	case IP_PROTO_TCP:
		tcp_recv_cb(tmpl, iface, (u_char *)ip, iplen);
		break;
	case IP_PROTO_UDP:
		udp_recv_cb(tmpl, iface, (u_char *)ip, iplen);
		break;
	case IP_PROTO_ICMP:
		hooks_dispatch(ip->ip_p, HD_INCOMING, &iphdr,
		    (u_char *)ip, iplen);
		icmp_recv_cb(tmpl, (u_char *)ip, iplen);
		break;
	default:
		hooks_dispatch(ip->ip_p, HD_INCOMING, &iphdr,
		    (u_char *)ip, iplen);
		honeyd_log_probe(honeyd_logfp, ip->ip_p, &iphdr, iplen, 0, NULL);
		return;
	}
}

/*
 * Given the queue dependent delay time, we can get an estimate of
 * the queue length.  We do a kind of random early drop (RED) between
 * a delay time of low and high in ms.
 */

static __inline int
honeyd_router_drop(struct link_drop *drop, struct timeval *tv)
{
	int msec;
	int low = drop->low;
	int high = drop->high;

	if (high == 0)
		return (0);

	/* See if we fall into the random bracket */
	msec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
	if (msec <= low)
		return (0);
	if (msec >= high)
		return (1);

	msec -= low;

	if (rand_uint16(honeyd_rand) % (high - low) < msec)
		return (1);
	else
		return (0);
}

/* 
 * Follow a packet through the routing table; starting with router gw.
 * Return:
 *	FW_INTERNAL - means that the packet needs to be received internally
 *	FW_EXTERNAL - means that the packet needs to be sent to the wire
 *	FW_DROP - means that the packet has been handled by dropping, etc.
 */

enum forward
honeyd_route_packet(struct ip_hdr *ip, u_int iplen, 
    struct addr *gw, struct addr *addr, int *pdelay)
{
	struct router *r, *lastrouter = NULL;
	struct router_entry *rte = NULL;
	struct link_entry *link = NULL;
	struct template *tmpl;
	struct addr host;
	double packetloss = 1;
	int delay = 0, external = 0;

	host = *gw;
	r = router_find(&host);
	
	while (addr_cmp(&host, addr) != 0 && --ip->ip_ttl) {
		if ((rte = network_lookup(r->routes, addr)) == NULL) {
			if (r->flags & ROUTER_ISENTRY) {
				external = 1;
				break;
			}
		noroute:
			syslog(LOG_DEBUG, "No route to %s", addr_ntoa(addr));
			return (FW_DROP);
		}

		if (rte->gw != NULL && lastrouter == rte->gw)
			goto noroute;

		if (rte->type == ROUTE_TUNNEL)
			break;

		if (rte->type == ROUTE_LINK || rte->type == ROUTE_UNREACH)
			break;

		/* Get the attributes for this link */
		link = rte->link;
		
		if (link->latency)
			delay += link->latency;
		else
			delay += 3;

		if (link->bandwidth) {
			int ms = iplen * link->bandwidth / link->divider;
			struct timeval now, tv;
			gettimeofday(&now, NULL);

			if (timercmp(&now, &link->tv_busy, <)) {
				/* Router is busy for a while */
				timersub(&link->tv_busy, &now, &tv);

				/* Opportunity to drop based on queue length */
				if (honeyd_router_drop(&link->red, &tv))
					return (FW_DROP);

				delay += tv.tv_sec * 1000 + tv.tv_usec / 1000;
			} else {
				/* Router is busy now */
				link->tv_busy = now;
			}

			/* Construct router delay time */
			tv.tv_sec = ms / 1000;
			tv.tv_usec = (ms % 1000) * 1000;

			timeradd(&link->tv_busy, &tv, &link->tv_busy);

			delay += ms;
		}
		if (link->packetloss)
			packetloss *= 1 - ((double)link->packetloss / 10000.0);

		lastrouter = r;
		r = rte->gw;
		host = r->addr;

		// Prevent underflows of ip_ttl
		// TODO: throw error/warning. This shouldn't happen.
		if (addr_cmp(&host, addr) != 0 && ip->ip_ttl == 0)
		{
			ip->ip_ttl = 1;
		}
	}

	/* Calculate the packet loss rate */
	packetloss = (1 - packetloss) * 10000;
	if (rand_uint16(honeyd_rand) % 10000 < packetloss)
		return (FW_DROP);

	/* Send ICMP_TIMEXCEED from router address */
	if (!ip->ip_ttl) {
 		struct spoof spoof = no_spoof;
 		spoof.new_src = host;
 
		syslog(LOG_DEBUG, "TTL exceeded for dst %s at gw %s",
		    addr_ntoa(addr), addr_ntoa(&host));

		/* 
		 * We need to use the template of the host that will
		 * send the ICMP error message.
		 */
		tmpl = template_find_best(addr_ntoa(&host), ip, iplen);
		honeyd_delay_packet(tmpl, NULL, ip, iplen, &host, NULL, delay, 0, spoof);
		return (FW_DROP);
	}

	/* Send ICMP_UNREACH from router address */
	if (rte != NULL && rte->type == ROUTE_UNREACH) {
		syslog(LOG_DEBUG, "dst %s unreachable at gw %s",
		    addr_ntoa(addr), addr_ntoa(&host));

		/* 
		 * We need to use the template of the host that will
		 * send the ICMP error message.
		 */
		tmpl = template_find_best(addr_ntoa(&host), ip, iplen);
		honeyd_delay_packet(tmpl, NULL, ip, iplen, &host, NULL, delay,
		    DELAY_UNREACH, no_spoof);
		return (FW_DROP);
	}

	/* We need to tunnel this packet */
	if (rte != NULL && rte->type == ROUTE_TUNNEL) {
		honeyd_delay_packet(NULL, NULL, ip, iplen,
		    &rte->tunnel_src, &rte->tunnel_dst,
		    delay, DELAY_TUNNEL, no_spoof);
		return (FW_DROP);
	}

	if (!external) {
		struct template *tmpl;

		/* Check if a template specific drop rate applies */
		tmpl = template_find_best(addr_ntoa(addr), ip, iplen);
		if (tmpl != NULL && tmpl->drop_inrate) {
			uint16_t value;
			value = rand_uint16(honeyd_rand) % (100*100);
			if (value < tmpl->drop_inrate)
				return (FW_DROP);
		}
	}

	/* The packet can be received; schedule it */

	*pdelay = delay;
	return (external ? FW_EXTERNAL : FW_INTERNAL);
}

void
honeyd_input(const struct interface *inter, struct ip_hdr *ip, u_short iplen)
{
	extern struct network *reverse;
	struct template *tmpl = NULL;
	struct router *gw;
	struct addr gw_addr;
	struct router_entry *rte;
	enum forward res = FW_INTERNAL;
	int delay = 0, flags = 0;
	struct addr src, addr;

	honeyd_pkts_in++;
	if (inter->if_ent.intf_flags & INTF_FLAG_LOOPBACK)
	{
		/* Override checksum on IP packet to prevent drops */
		ip_checksum(ip, iplen);
	}

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	if (!router_used) {
		/* Check if a template specific drop rate applies */
		tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);
		if (tmpl != NULL && tmpl->drop_inrate) {
			uint16_t value;
			value = rand_uint16(honeyd_rand) % (100*100);
			if (value < tmpl->drop_inrate)
				return;
		}
		if ((tmpl != NULL) && (tmpl->flags & TEMPLATE_EXTERNAL))
			flags |= DELAY_ETHERNET;
		honeyd_delay_packet(tmpl, inter, ip, iplen, NULL, NULL, delay, flags, no_spoof);
		return;
	}

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
	if (ip->ip_p == IP_PROTO_GRE) {
		uint16_t ipoff;

		/* Decapsulate GRE packet if it is legitimate */
		if ((rte = router_find_tunnel(&addr, &src)) == NULL) {
			syslog(LOG_DEBUG, "Unknown GRE packet from %s",
			    addr_ntoa(&src));
			return;
		}

		/* Check for fragment GRE packets */
		ipoff = ntohs(ip->ip_off);
		if ((ipoff & IP_OFFMASK) || (ipoff & IP_MF)) {
			if (ip_fragment(NULL, ip, iplen, &ip, &iplen) == -1)
				return;
			/*
			 * If a packet was reassembled successfully, we can
			 * just continue processing it.  All checks so far
			 * are solely concerned with the IP header.
			 */
		}

		if (gre_decapsulate(ip, iplen, &ip, &iplen) == -1)
			return;

		addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);
		/* Check that the source address is valid */
		if (!addr_contained(&rte->net, &src)) {
			syslog(LOG_INFO,
			    "Bad address %s injected into tunnel %s",
			    addr_ntoa(&src), addr_ntoa(&rte->net));
			return;
		}
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	}

	if ((gw = network_lookup(reverse, &src)) != NULL)
		gw_addr = gw->addr;
	/* Find the correct entry router based on destination IP */
	else if ((gw = network_lookup(entry_routers, &addr)) != NULL)
		gw_addr = gw->addr;
	else {
		/* Pick the first one on the list */
		gw = entry_routers->data;
		gw_addr = gw->addr;
	}

	res = honeyd_route_packet(ip, iplen, &gw_addr, &addr, &delay);
	if (res == FW_DROP)
		return;

	/*
	 * We want to prevent routing loops.  One good heuristic is to
	 * drop all packets that we received from an interface and
	 * that want to be routed out of an interface.  In the case of
	 * ethernet, this is legitimate if we have external hosts
	 * integrated into the routing topology.  In that case, we
	 * send the packet out, if there is a routing loop, we are
	 * going to receive it via loopback and drop it then.
	 */

	if (res == FW_EXTERNAL) {
		if (inter != NULL && inter->if_ent.intf_link_addr.addr_type != 
		    ADDR_TYPE_ETH) {
			syslog(LOG_DEBUG, "No route to %s",
			    addr_ntoa(&addr));
			return;
		} else
			flags |= DELAY_EXTERNAL;
	} else
		tmpl = template_find_best(addr_ntoa(&addr), ip, iplen);

	if ((tmpl != NULL) && (tmpl->flags & TEMPLATE_EXTERNAL))
		flags |= DELAY_ETHERNET;

	/*
	 * Delay the packet if necessary, otherwise deliver it directly.
	 * External delivery needs the template for its interface.
	 */
	honeyd_delay_packet((flags & DELAY_ETHERNET) ? tmpl : NULL, inter,
	    ip, iplen, NULL, NULL, delay, flags, no_spoof);
}

// This is the callback that will be called whenever an external packet is recieved via pcap
void
honeyd_recv_cb(u_char *ag, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	const struct interface *inter = (const struct interface *)ag;
	struct ip_hdr *ip;
	struct addr addr;
	u_short iplen;
	struct eth_hdr *eth = (struct eth_hdr *)pkt;
	int is_etherpkt = 0;

	count_increment(stats_network.input_bytes, pkthdr->caplen);

	/* Check if we can receive arp traffic on this interface */
	if ((router_used || need_arp) &&
	    inter->if_ent.intf_link_addr.addr_type == ADDR_TYPE_ETH) {
		struct arp_req *req;
		struct addr eth_sha;
		
		/* Too short to hold an Ethernet header */
		if (pkthdr->caplen < ETH_HDR_LEN)
			return;

		/* Mark this packet as being delivered via ethernet */
		is_etherpkt = 1;

		/* Ignore our own packets */
		addr_pack(&eth_sha, ADDR_TYPE_ETH, ETH_ADDR_BITS,
		    &eth->eth_src, ETH_ADDR_LEN);
		if ((req = arp_find(&eth_sha)) != NULL &&
		    (req->flags & ARP_INTERNAL))
			return;

		if (ntohs(eth->eth_type) == ETH_TYPE_ARP) {
			arp_recv_cb(ag, pkthdr, pkt);
			return;
		}
	}

	/* Everything below assumes that the packet is IPv4 */
	if (pkthdr->caplen < inter->if_dloff + IP_HDR_LEN)
		return;

	ip = (struct ip_hdr *)(pkt + inter->if_dloff);

	iplen = ntohs(ip->ip_len);
	if (pkthdr->caplen - inter->if_dloff < iplen)
		return;
	if (ip->ip_hl << 2 > iplen)
		return;
	if (ip->ip_hl << 2 < sizeof(struct ip_hdr))
		return;

	/* Check our own address */
	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	if (addr_cmp(&addr, &inter->if_ent.intf_addr) == 0) {
		/* Only accept packets for own address if they are GRE */
		if (!router_used || ip->ip_p != IP_PROTO_GRE)
			return;
	}

	/* Check for a DHCP server response */
	if (is_etherpkt && ip->ip_p == IP_PROTO_UDP) {
		struct udp_hdr *udp;

		udp = (struct udp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
		if (iplen < (ip->ip_hl << 2) + UDP_HDR_LEN)
			goto out;

		if (ntohs(udp->uh_dport) == 68 && ntohs(udp->uh_sport) == 67) {
			dhcp_recv_cb(eth, ip, iplen);
			return;
		}
	}
 out:
	honeyd_input(inter, ip, iplen);
}

void
honeyd_sigchld(int fd, short what, void *arg)
{
	pid_t pid;
	int status;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS)
			syslog(LOG_WARNING, "child %d killed by SIGSYS "
			    "(seccomp: denied syscall)", (int)pid);
		/* Ignore the rrdtool driver for children accounting */
		if (honeyd_rrd_drv != NULL && honeyd_rrd_drv->pid == pid)
			continue;
		/* PM-SCR-152: release its script process slot */
		cmd_script_reaped(pid);
		honeyd_nchildren--;
	}
}

void
honeyd_signal(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "exiting on signal %d", fd);

	// Clear the IP list file if we're using it
	if (templateDump != NULL)
	{
		FILE *fp;
		if ((fp = fopen(templateDump , "w+")) == NULL)
		{
			syslog(LOG_WARNING, "Error opening the DHCP IP address dump file");
		}
			//warn("Error opening the DHCP IP address dump file");
		else
			fclose(fp);
	}

	honeyd_exit(0);
}

void
honeyd_sighup(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "rereading configuration on signal %d", fd);

	template_free_all(TEMPLATE_FREE_REGULAR);
	router_end();
	if (config.config != NULL)
		config_read(config.config);
}

void
honeyd_sigusr(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "rotating log files on signal %d", fd);

	honeyd_logend(honeyd_logfp);
	honeyd_logend(honeyd_servicefp);
	honeyd_json_reopen();

	if (logfile != NULL)
		honeyd_logfp = honeyd_logstart(logfile);
	if (servicelog != NULL)
		honeyd_servicefp = honeyd_logstart(servicelog);
}

/* --sandbox-daemon: what the daemon may still touch once Landlock is on */

static void
sbd_dir(const char *path, int writable)
{
	char buf[1024], *p;

	if (path == NULL || path[0] != '/')
		return;
	strlcpy(buf, path, sizeof(buf));
	if ((p = strrchr(buf, '/')) != NULL)
		*(p == buf ? p + 1 : p) = '\0';
	if (writable && sandbox_path_broad(buf)) {
		/* e.g. -l /tmp/x.log: only that file, never all of /tmp */
		syslog(LOG_WARNING, "sandbox-daemon: %s is in %s; only the file "
		    "itself is writable (use a dedicated directory)", path, buf);
		sandbox_daemon_allow_write(path);
	} else if (writable)
		sandbox_daemon_allow_write(buf);
	else
		sandbox_daemon_allow_read(buf);
}

/* absolute paths in a script / subsystem command line */
static void
sbd_command(const char *cmd)
{
	char buf[1024], *p, *tok;

	if (cmd == NULL)
		return;
	strlcpy(buf, cmd, sizeof(buf));
	for (p = buf; (tok = strsep(&p, " \t\"'")) != NULL; )
		if (tok[0] == '/')
			sandbox_daemon_allow_read(tok);
}

static void
sbd_action(struct action *action)
{
	struct addrinfo *ai;

	if (action->status == PORT_OPEN)
		sbd_command(action->action);
	else if (action->status == PORT_PROXY) {
		if (action->aitop == NULL) {
			sandbox_daemon_allow_connect(-1);
			return;
		}
		for (ai = action->aitop; ai != NULL; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET)
				sandbox_daemon_allow_connect(ntohs(
				    ((struct sockaddr_in *)ai->ai_addr)->sin_port));
			else if (ai->ai_family == AF_INET6)
				sandbox_daemon_allow_connect(ntohs(
				    ((struct sockaddr_in6 *)ai->ai_addr)->sin6_port));
		}
	}
}

static void
honeyd_sandbox_daemon_landlock(const char *datadir, void (*before)(void))
{
	extern struct subsystemqueue subsystems;
	extern char *ui_file;
	struct subsystem *sub;
	char buf[1024], *pp, *p, *tok;

	if (!honeyd_sandbox_daemon) {
		before();
		return;
	}

	/* read-only: config, data and script dirs (libs are in sandbox.c) */
	sbd_dir(config.config, 0);
	sbd_dir(config.pers, 0);
	sbd_dir(config.xprobe, 0);
	sbd_dir(config.assoc, 0);
	sbd_dir(config.osfp, 0);
	sbd_dir(config.nmapMac, 0);
	sandbox_daemon_allow_read(datadir);
	if (getcwd(buf, sizeof(buf)) != NULL)
		sandbox_daemon_allow_read(buf);
	sandbox_daemon_allow_read(honeyd_webserver_root);
	if ((pp = getenv("PYTHONPATH")) != NULL) {
		strlcpy(buf, pp, sizeof(buf));
		for (p = buf; (tok = strsep(&p, ":")) != NULL; )
			sandbox_daemon_allow_read(tok);
	}
	template_action_iterate(sbd_action);
	TAILQ_FOREACH(sub, &subsystems, next)
		sbd_command(sub->cmdstring);

	/* writable: logs, the control socket dir, the status page graphs */
	sbd_dir(logfile, 1);
	sbd_dir(servicelog, 1);
	if (jsonlogfile != NULL && strcmp(jsonlogfile, "-") != 0)
		sbd_dir(jsonlogfile, 1);
	sbd_dir(templateDump, 1);
	sbd_dir(ui_file, 1);
	snprintf(buf, sizeof(buf), "%s/graphs", honeyd_webserver_root);
	sandbox_daemon_allow_write(buf);
	/* honeyd_traffic.rrd lives in the graphs dir too (never /tmp) */

	before();
	sandbox_daemon_landlock();
}

struct _unittest {
	char *name;
	void (*cb)(void);
} unittests[] = {
#ifdef HAVE_PYTHON
	{ "pydataprocessing", pydataprocessing_test },
	{ "pydatahoneyd", pydatahoneyd_test },
#endif
	//{ "rrdtool", rrdtool_test },
	{ "ethernet", ethernet_test },
	{ "interface", interface_test },
	{ "network", network_test },
	{ "template", template_test },
	{ NULL, NULL}
};

void
unittest(void)
{
	struct _unittest *ut;
	fprintf(stderr, "Running unittests ...\n");
	for (ut = unittests; ut->name != NULL; ut++) {
		fprintf(stderr, " ---- %s TEST ---- \n", ut->name);
		(*ut->cb)();
		fprintf(stderr, " ---- %s OK ---- \n", ut->name);
	}
	fprintf(stderr, "All unitests are OK\n");
	exit(0);
}

static int
pm_daemon_main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
	const char *base = strrchr(argv[0], '/');

	/* --sandbox-scripts launcher, exec'd by the daemon (sandbox_ns.c) */
	if (strcmp(base != NULL ? base + 1 : argv[0], SANDBOX_LAUNCHER) == 0)
		return (sandbox_ns_main(argc, argv));
	return (pm_daemon_main(argc, argv));
}

static int
pm_daemon_main(int argc, char *argv[])
{
	extern int interface_dopoll;
	char *dev[HONEYD_MAX_INTERFACES];
	char **orig_argv;
	struct addr stats_dst;
	u_short stats_port = 0;
	char *stats_username = NULL;
	char *stats_password = NULL;
	const char *stats_password_file = NULL;
	int want_unittest = 0;
	int setrand = 0;
	int i, c, orig_argc, ninterfaces = 0;
	char origin_path[1024];
	char *datadir;
	FILE *fp;

	if (getcwd(origin_path, sizeof(origin_path)) == NULL)
	{
		syslog(LOG_ERR, "Could not get run path on system.");
		exit(EXIT_FAILURE);	
	}

	/*
	 * Data directory: PHANTOM_MIRAGE_DATADIR (legacy HONEYD_DATADIR) overrides the compiled-in
	 * PATH_HONEYDDATA.  We only chdir() into it after option parsing,
	 * and a missing directory is not fatal (issue #43).
	 */
	if ((datadir = pm_getenv("DATADIR")) != NULL && *datadir != '\0') {
		config.pers = honeyd_data_path(datadir, "nmap-os-db");
		config.xprobe = honeyd_data_path(datadir, "xprobe2.conf");
		config.assoc = honeyd_data_path(datadir, "nmap.assoc");
		config.osfp = honeyd_data_path(datadir, "pf.os");
		config.nmapMac = honeyd_data_path(datadir, "nmap-mac-prefixes");
		honeyd_webserver_root = honeyd_data_path(datadir,
		    "webserver/htdocs");
	} else
		datadir = PATH_HONEYDDATA;

	fprintf(stderr, PRODUCT_NAME " %s (based on Honeyd)\n"
	    "Honeyd Copyright (c) 2002-2007 Niels Provos\n", VERSION);

	orig_argc = argc;
	orig_argv = argv;
	syslog_init(orig_argc, orig_argv);
	while ((c = getopt_long(argc, argv, HONEYD_OPTSTRING,
				honeyd_long_opts, NULL)) != -1) {
		char *ep;
		switch (c) {
		case 'Y':
			honeyd_rrdtool_path = optarg;
			break;

		case 'A':
			honeyd_webserver_address = optarg;
			break;

		case 'W':
			honeyd_webserver_port = atoi(optarg);
			if (honeyd_webserver_port == 0) {
				fprintf(stderr, "Bad port number: %s\n",
				    optarg);
				usage();
			}
			break;
		case 'X':
			honeyd_webserver_root = optarg;
			break;
		case 'T':
			want_unittest = 1;
			break;
		case 'R':
			/* For regression testing */
			setrand = atoi(optarg);
			break;
		case 'c': {
			char line[1024], *p = line;
			char *address;
			char *strport;
			char *name;
			char *password;

			strlcpy(line, optarg, sizeof(line));

			if ((address = strsep(&p, ":")) == NULL)
				usage();
			if ((strport = strsep(&p, ":")) == NULL)
				usage();
			if ((name = strsep(&p, ":")) == NULL)
				usage();
			/* The password field is optional */
			password = strsep(&p, ":");
			if (p != NULL && *p != '\0')
				usage();

			if (addr_pton(address, &stats_dst) == -1) {
				fprintf(stderr, "Bad destination address %s\n",
				    address);
				usage();
			}
			if ((stats_port = atoi(strport)) == 0) {
				fprintf(stderr, "Bad destination port %s\n",
				    strport);
				usage();
			}

			stats_username = strdup(name);
			if (password != NULL) {
				fprintf(stderr, "Warning: a password in -c is "
				    "deprecated, it is visible to other users; "
				    "use --stats-password-file\n");
				stats_password = strdup(password);
				/* Hide it from the process list too */
				stats_scrub_password(optarg);
			}
		}
			break;
		case 'K':
			stats_password_file = optarg;
			break;
		case 'u':
			honeyd_uid = strtoul(optarg, &ep, 10);
			honeyd_needsroot = -1;
			if (optarg[0] == '\0' || *ep != '\0') {
				fprintf(stderr, "Bad uid %s\n", optarg);
				usage();
			}
			break;
		case 'g':
			honeyd_gid = strtoul(optarg, &ep, 10);
			honeyd_needsroot = -1;
			if (optarg[0] == '\0' || *ep != '\0') {
				fprintf(stderr, "Bad gid %s\n", optarg);
				usage();
			}
			break;
		case 'V':
			honeyd_show_version = 1;
			break;
		case 'P':
			interface_dopoll = 1;
			break;
		case 'd':
			honeyd_debug++;
			break;
		case 'i':
			if (ninterfaces >= HONEYD_MAX_INTERFACES){
				syslog(LOG_ERR, "Too many interfaces specified");
				exit(EXIT_FAILURE);
			}
			dev[ninterfaces++] = optarg;
			break;
		case 'f':
			determine_path(origin_path, &optarg);
			config.config = optarg;
			break;
		case 'l':
			determine_path(origin_path, &optarg);
			logfile = optarg;
			break;
		case 'S':
			if (sandbox_add_write_path(optarg) == -1) {
				fprintf(stderr, "--sandbox-allow-write: need an "
				    "absolute path, not a broad directory like /tmp (max 16)\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'N':
			fprintf(stderr, "--sandbox-script-net has been "
			    "removed: scripts get no network at all (no outbound "
			    "connections, no bind); see docs/sandboxing.md\n");
			exit(EXIT_FAILURE);
		case 'J':
			if (strcmp(optarg, "-") != 0)
				determine_path(origin_path, &optarg);
			jsonlogfile = optarg;
			break;
		case 'I':
			honeyd_json_set_sensor(optarg);
			break;
		case 'H': {
			char *end;
			heartbeat_secs = strtol(optarg, &end, 10);
			if (*optarg == '\0' || *end != '\0' ||
			    heartbeat_secs < 0 || heartbeat_secs > 86400) {
				fprintf(stderr, "bad --heartbeat %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		}
		case 's':
			determine_path(origin_path, &optarg);
			servicelog = optarg;
			break;
		case 't':
			determine_path(origin_path, &optarg);
			templateDump = optarg;
			break;
		case 'x':
			determine_path(origin_path, &optarg);
			config.xprobe = optarg;
			break;
		case 'a':
			determine_path(origin_path, &optarg);
			config.assoc = optarg;
			break;
		case 'p':
			determine_path(origin_path, &optarg);
			config.pers = optarg;
			break;
		case '0':
			determine_path(origin_path, &optarg);
			config.osfp = optarg;
			break;
		case 'm':
			determine_path(origin_path, &optarg);
			config.nmapMac = optarg;
			break;
		case 0:
			/* long option handled -- skip this one. */
			break;
		default:
			usage();
			break;
		}
	}

	if (stats_password_file != NULL) {
		if (stats_username == NULL) {
			fprintf(stderr, "--stats-password-file needs -c "
			    "host:port:name\n");
			exit(EXIT_FAILURE);
		}
		if (stats_password != NULL) {
			fprintf(stderr, "use either a password in -c or "
			    "--stats-password-file, not both\n");
			exit(EXIT_FAILURE);
		}
		if ((stats_password =
			stats_read_password_file(stats_password_file)) == NULL)
			exit(EXIT_FAILURE);
	} else if (stats_username != NULL && stats_password == NULL) {
		fprintf(stderr, "-c needs a password: use "
		    "--stats-password-file\n");
		exit(EXIT_FAILURE);
	}

	if (honeyd_show_version) {
		printf(PRODUCT_NAME " %s (based on Honeyd)\n", VERSION);
		exit(EXIT_SUCCESS);
	}
	if (honeyd_show_usage) {
		usage();
		/* not reached */
	}
	if (honeyd_show_include_dir) {
		printf("%s\n", PATH_HONEYDINCLUDE);
		exit(EXIT_SUCCESS);
	}
	if (honeyd_show_data_dir) {
		printf("%s\n", datadir);
		exit(EXIT_SUCCESS);
	}

	/*
	 * Installed behaviour: run from the data directory.  If it does
	 * not exist (e.g. running from a build tree), stay in the current
	 * directory; the checks below report any default file that is
	 * actually missing.
	 */
	if (chdir(datadir) == -1) {
		fprintf(stderr, "Warning: data directory %s not available (%s); "
		    "staying in %s\n", datadir, strerror(errno), origin_path);
		syslog(LOG_WARNING, "data directory %s not available: %s",
		    datadir, strerror(errno));
	}

	honeyd_check_data_file(config.xprobe, "xprobe2 fingerprint", "-x");
	honeyd_check_data_file(config.assoc, "nmap/xprobe association", "-a");
	honeyd_check_data_file(config.pers, "nmap personality", "-p");
	honeyd_check_data_file(config.osfp, "pf OS fingerprint", "-0");
	honeyd_check_data_file(config.nmapMac, "nmap MAC prefix", "-m");

	argc -= optind;
	argv += optind;

	if ((honeyd_rand = rand_open()) == NULL)
	{
		syslog(LOG_ERR, "rand_open");
		exit(EXIT_FAILURE);
	}
	/* We need reproduceable random numbers for regression testing */
	if (setrand) {
		rand_set(honeyd_rand, &setrand, sizeof(setrand));
		/* rand_normal() and a few subsystems use libc rand() */
		srand(setrand);
	}


	/* disables event methods that don't work for bpf */
	interface_prevent_init();

	/* Initalize libevent */
	libevent_base = event_base_new();

	/* Three priorities - UI connections always get a better priority */
	event_base_priority_init(libevent_base, 3);

	/* Initalize pool allocator */
	pool_pkt = pool_init(HONEYD_MTU);
	pool_delay = pool_init(sizeof(struct delay));

	/* Initialize honeyd's callback hooks */
	hooks_init();

	arp_init();
	interface_initialize(honeyd_recv_cb);
	config_init();
	router_init();
	plugins_config_init();

	if (stats_username != NULL) {
		stats_init();
		stats_init_collect(&stats_dst, stats_port,
		    stats_username, stats_password);
	}

	personality_init();
	xprobe_personality_init();
	associations_init();

	/* Xprobe2 fingerprints */
	if ((fp = fopen(config.xprobe, "r")) == NULL){
		syslog(LOG_ERR, "fopen(%s)", config.xprobe);
		exit(EXIT_FAILURE);
	}
	if (xprobe_personality_parse(fp) == -1){
		syslog(LOG_ERR, "parsing xprobe personality file failed");
		exit(EXIT_FAILURE);
	}
	fclose(fp);
	
	/* Association between xprobe and nmap fingerprints */
	if ((fp = fopen(config.assoc, "r")) == NULL){
		syslog(LOG_ERR, "fopen(%s)", config.assoc);
		exit(EXIT_FAILURE);
	}
	if (parse_associations(fp) == -1){
		syslog(LOG_ERR, "parsing associations file failed");
		exit(EXIT_FAILURE);
	}
	fclose(fp);

	/* Nmap fingerprints */
	if ((fp = fopen(config.pers, "r")) == NULL){
		syslog(LOG_ERR, "fopen(%s)", config.pers);
		exit(EXIT_FAILURE);
	}
	if (personality_parse(fp) == -1){
		syslog(LOG_ERR, "parsing personality file failed");
		exit(EXIT_FAILURE);
	}
	fclose(fp);

	/* PF OS fingerprints */
	if (honeyd_osfp_init(config.osfp) == -1){
		syslog(LOG_ERR, "reading OS fingerprints failed");
		exit(EXIT_FAILURE);
	}

	honeyd_init();
	
	if (want_unittest)
		unittest();

	if ((honeyd_ip = ip_open()) == NULL) {
		/* 
		 * We ignore this error if a user just wants to verify
		 * the configuration - some configs will not load without
		 * this call succeeding.
		 */
		if (!honeyd_verify_config){
			syslog(LOG_ERR, "ip_open");
			exit(EXIT_FAILURE);
		}
	}

	if (honeyd_verify_config) {
		extern int interface_verify_config;
		
		/* Make sure that we do not open interfaces for real */
		interface_verify_config = 1;
	}

#ifdef HAVE_PYTHON
	/* Python support must be started before reading the configuration. */
	pyextend_init();

	/* Start our web server */
	if (!honeyd_verify_config && honeyd_is_webserver_enabled())
		if (pyextend_webserver_init(
			honeyd_webserver_address,
			honeyd_webserver_port,
			honeyd_webserver_root) == -1)
			honeyd_disable_webserver = 1;
#endif
	/* Reads in the ethernet codes and indexes them for use in config */
		//ethernetcode_init();
		//nmap mac addresses are read in here
	//they did enter the -m flag and entered a path for the ethernet codes and indexes
	/* Reads in the ethernet codes and indexes them for use in config */

	fp = fopen(config.nmapMac, "r");
	if (fp != NULL){
		ethernetcode_init(fp);
	}else{
		syslog(LOG_ERR,"Can't open the nmap-mac-address file");
		exit(EXIT_FAILURE);
	}




	/* Initialize the specified interfaces */
	if (ninterfaces == 0)
		interface_init(NULL, argc, argc ? argv : NULL);
	else {
		for (i = 0; i < ninterfaces; i++)
			interface_init(dev[i], argc, argc ? argv : NULL);
	}




	/* Read main configuration file */
	if (config.config != NULL)
		config_read(config.config);

	/* Just verify the configuration - exit with success */
	if (honeyd_verify_config)
	{
		syslog(LOG_ERR, "parsing configuration file successful");
		exit(EXIT_SUCCESS);
	}

	//Start sending DHCP discoveries that have been queue'd up
	dhcp_send_discover();

	/* Under systemd (#16) the unit relaxes RestrictNamespaces= for the
	 * sandbox and expects both flags; say so loudly if one is gone. */
	if (getenv("INVOCATION_ID") != NULL &&
	    (!honeyd_sandbox_daemon || !honeyd_sandbox_scripts)) {
		const char *miss = !honeyd_sandbox_daemon ?
		    (!honeyd_sandbox_scripts ?
			"--sandbox-daemon and --sandbox-scripts" :
			"--sandbox-daemon") : "--sandbox-scripts";
		syslog(LOG_CRIT, "WARNING: running under systemd WITHOUT %s: "
		    "the daemon and/or its scripts are NOT sandboxed. The "
		    "unit's RestrictNamespaces= is relaxed for the sandbox; "
		    "set RestrictNamespaces=yes or restore SANDBOX (see "
		    "docs/sandboxing.md)", miss);
		fprintf(stderr, "phantom-mirage: WARNING: running under "
		    "systemd WITHOUT %s; see docs/sandboxing.md\n", miss);
	}

	/* Refuse to run twice; a stale pid file is fine */
	honeyd_pidfile_check();

	/* Attach the UI interface */
	ui_init();
	
	/*
	 * We must initialize the plugins after the config file
         * has been read, as the plugins may query config settings!
         */
        plugins_init();

	ip_fragment_init();

#ifdef HAVE_PYTHON
	/* Fix permissions of the webserver directories if requested */
	if (honeyd_webserver_fix_permissions)
		pyextend_webserver_fix_permissions(honeyd_webserver_root,
		    honeyd_uid, honeyd_gid);
#endif

	/* Create the pid file as root; see honeyd_pidfile_open() */
	honeyd_pidfile_open();

	/* Start Honeyd in the background if necessary */
	if (!honeyd_debug) {
		setlogmask(LOG_UPTO(LOG_INFO));
		fprintf(stderr, PRODUCT_NAME " starting as background process\n");
		if (daemon(1, 0) < 0) {
			unlink(PIDFILE);
			syslog(LOG_ERR, "daemon");
			exit(EXIT_FAILURE);
		}
	}
	
	honeyd_pidfile_write();

	/* Drop privileges if we do not need them */
	if (honeyd_needsroot <= 0) {
		cmd_droppriv(honeyd_uid, honeyd_gid);

		syslog(LOG_NOTICE,
		    "Demoting process privileges to uid %u, gid %u",
		    honeyd_uid, honeyd_gid);
	} else {
		syslog(LOG_WARNING, "Running with root privileges.");
	}

	/* --sandbox-scripts: the per-script namespace launcher must be
	 * forked before the daemon's own filters (they forbid unshare and
	 * mount), but after the paths for Landlock were collected (#16) */
	honeyd_sandbox_daemon_landlock(datadir, sandbox_ns_start);
	if (sandbox_daemon() == -1) {
		syslog(LOG_ERR, "--sandbox-daemon: cannot install seccomp "
		    "filter: %m");
		exit(EXIT_FAILURE);
	}

	// Clear/create the IP list file if we're using it
	if (templateDump != NULL)
	{
		FILE *fp;
		if ((fp = fopen(templateDump , "w+")) == NULL)
			syslog(LOG_WARNING, "Error opening the DHCP IP address dump file");
			//warn("Error opening the DHCP IP address dump file");
		else
			fclose(fp);
	}

#ifdef HAVE_PYTHON
	/* Verify that the webserver space is setup correctly */
	if (honeyd_is_webserver_enabled())
		pyextend_webserver_verify_setup(honeyd_webserver_root);
	else
		syslog(LOG_INFO, "Internal webserver has been disabled.");
#endif

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("signal");
		return (-1);
	}

	struct event *sigterm_ev, *sigint_ev, *sighup_ev, *sigchld_ev, *sigusr_ev;

	sigterm_ev = evsignal_new(libevent_base, SIGTERM, honeyd_signal, NULL);
	sigint_ev = evsignal_new(libevent_base, SIGINT, honeyd_signal, NULL);
	sighup_ev = evsignal_new(libevent_base, SIGHUP, honeyd_sighup, NULL);
	sigchld_ev = evsignal_new(libevent_base, SIGCHLD, honeyd_sigchld, NULL);
	sigusr_ev = evsignal_new(libevent_base, SIGUSR1, honeyd_sigusr, NULL);

	event_add(sigterm_ev, NULL);
	event_add(sigint_ev, NULL);
	event_add(sighup_ev, NULL);
	event_add(sigchld_ev, NULL);
	event_add(sigusr_ev, NULL);

	/* Start logging via rrd */
	if (honeyd_rrdtool_path != NULL && strlen(honeyd_rrdtool_path))
		honeyd_rrd_start(honeyd_rrdtool_path);

	/* Potential dependency on the timestamp used for rrdtool */
	count_init();

	if (logfile != NULL)
		honeyd_logfp = honeyd_logstart(logfile);
	if (servicelog != NULL)
		honeyd_servicefp = honeyd_logstart(servicelog);
	if (jsonlogfile != NULL && honeyd_json_open(jsonlogfile) == -1) {
		syslog(LOG_ERR, "cannot open JSON log %s", jsonlogfile);
		exit(EXIT_FAILURE);
	}
	gettimeofday(&honeyd_start_tv, NULL);
	if (heartbeat_secs > 0) {
		struct timeval tv = { heartbeat_secs, 0 };
		struct event *hb = event_new(libevent_base, -1, EV_PERSIST,
		    honeyd_heartbeat_cb, NULL);
		if (hb == NULL || event_add(hb, &tv) == -1)
			errx(1, "cannot schedule heartbeat");
	}

	event_base_dispatch(libevent_base);

	syslog(LOG_ERR, "Kqueue does not recognize bpf filedescriptor.");

	return (0);
}

/*
 * Determine if Honeyd should automatically demote the user id it is
 * going to use.
 */

void
honeyd_use_uid(uid_t uid)
{
	if (!honeyd_needsroot && uid != honeyd_uid)
		honeyd_needsroot = 1;
}

void
honeyd_use_gid(gid_t gid)
{
	if (!honeyd_needsroot && gid != honeyd_gid)
		honeyd_needsroot = 1;
}
