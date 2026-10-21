/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dnet.h>
#include <ctype.h>
#include <syslog.h>
#include <netdb.h>
#ifdef HAVE_TIME_H
#include <time.h>
#include <unistd.h>
#endif

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "osfp.h"
#include "log.h"
#include "template.h"
#include "personality.h"

static char *
honeyd_logtuple(const struct tuple *hdr)
{
	static char buf[128];
	char asrc[24], adst[24];
	struct addr src, dst;
	ushort sport, dport;
	
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);

	if (hdr->local) {
		struct addr tmp;

		tmp = src;
		src = dst;
		dst = tmp;
		sport = hdr->dport;
		dport = hdr->sport;
	} else {
		sport = hdr->sport;
		dport = hdr->dport;
	}


	addr_ntop(&src, asrc, sizeof(asrc));
	addr_ntop(&dst, adst, sizeof(adst));

	if (hdr->type == SOCK_STREAM || hdr->type == SOCK_DGRAM)
		snprintf(buf, sizeof(buf), "%s %d %s %d",
		    asrc, sport, adst, dport);
	else if (hdr->type == SOCK_RAW)
		snprintf(buf, sizeof(buf), "%s %s: %d(%d)",
		    asrc, adst, hdr->sport, hdr->dport);
	else
		snprintf(buf, sizeof(buf), "%s %s", asrc, adst);
		

	return (buf);
}

static char *
honeyd_logtime(void)
{
	static char logtime[32];
	struct timeval tv;
	struct tm *tm;
	time_t seconds;

	if (gettimeofday(&tv, NULL) == -1)
	{
		syslog(LOG_ERR, "%s: gettimeofday", __func__);
		exit(EXIT_FAILURE);
	}
	seconds = tv.tv_sec;
	
	/* ctime returns 26-character string */
	tm = localtime(&seconds);
	snprintf(logtime, sizeof(logtime),
	    "%04d-%02d-%02d-%02d:%02d:%02d.%04d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    (int)(tv.tv_usec / 100));

	return (logtime);
}

char *
honeyd_logdate(void)
{
	static char logtime[32];
	struct timeval tv;
	struct tm *tm;
	time_t seconds;

	if (gettimeofday(&tv, NULL) == -1)
	{
		syslog(LOG_ERR, "%s: gettimeofday, failed to get time of day", __func__);
		exit(EXIT_FAILURE);
	}
	seconds = tv.tv_sec;
	
	/* ctime returns 26-character string */
	tm = localtime(&seconds);
	snprintf(logtime, sizeof(logtime),
	    "%04d-%02d-%02d",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

	return (logtime);
}

static char *
honeyd_logproto(int proto)
{
	static char protoname[32];

	struct protoent *pe;
	struct protoent tcp = { "tcp", NULL, IP_PROTO_TCP };
	struct protoent udp = { "udp", NULL, IP_PROTO_UDP };
	struct protoent icmp = { "icmp", NULL, IP_PROTO_ICMP };

	switch(proto) {
	case IP_PROTO_TCP:
		pe = &tcp;
		break;
	case IP_PROTO_UDP:
		pe = &udp;
		break;
	case IP_PROTO_ICMP:
		pe = &icmp;
		break;
	default:
		/* Reads a file and is very slow */
		pe = getprotobynumber(proto);
		break;
	}

	if (pe == NULL)
		snprintf(protoname, sizeof(protoname), "unkn(%d)", proto);
	else
		snprintf(protoname, sizeof(protoname), "%s(%d)",
		    pe->p_name, proto);

	return (protoname);
}

#define TESTFLAG(x,y) do { \
	if (flags & (x)) \
		tcpflags[i++] = (y); \
} while (0)

static char *
honeyd_logtcpflags(int flags)
{
	static char tcpflags[11];
	int i = 1;

	tcpflags[0] = ' ';
	TESTFLAG(TH_FIN, 'F');
	TESTFLAG(TH_SYN, 'S');
	TESTFLAG(TH_RST, 'R');
	TESTFLAG(TH_PUSH, 'P');
	TESTFLAG(TH_ACK, 'A');
	TESTFLAG(TH_URG, 'U');
	TESTFLAG(TH_ECE, 'E');
	TESTFLAG(TH_CWR, 'C');

	tcpflags[i] = '\0';

	return (tcpflags);
}

/*
 * JSON Lines event log (issue #24). Opt-in with --json-log FILE ("-" for
 * stdout). One object per line; see docs/json-log.md for the schema.
 */

#define JSONLOG_SCHEMA	1

static FILE *json_fp;
static char *json_path;
static int json_failed;		/* a write error was already reported */
uint64_t honeyd_json_connections;
static char *json_sensor;	/* sensor_id, --sensor-id or hostname (#30) */

void
honeyd_json_set_sensor(const char *id)
{
	free(json_sensor);
	json_sensor = id != NULL ? strdup(id) : NULL;
}

static const char *
json_sensor_id(void)
{
	char host[256];

	if (json_sensor == NULL || *json_sensor == '\0') {
		if (gethostname(host, sizeof(host)) == -1)
			strlcpy(host, "unknown", sizeof(host));
		host[sizeof(host) - 1] = '\0';
		honeyd_json_set_sensor(host);
	}
	return (json_sensor != NULL ? json_sensor : "unknown");
}

static void
json_str(FILE *out, const char *s)
{
	const unsigned char *p;

	fputc('"', out);
	for (p = (const unsigned char *)s; *p != '\0'; p++) {
		switch (*p) {
		case '"':  fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\n': fputs("\\n", out); break;
		case '\r': fputs("\\r", out); break;
		case '\t': fputs("\\t", out); break;
		default:
			/*
			 * Control characters and non-ASCII bytes are escaped
			 * (bytes as U+0000..U+00FF), so the output is always
			 * valid JSON whatever an attacker sends.
			 */
			if (*p < 0x20 || *p >= 0x7f)
				fprintf(out, "\\u%04x", *p);
			else
				fputc(*p, out);
		}
	}
	fputc('"', out);
}

static void
json_kv_str(FILE *out, const char *key, const char *val)
{
	if (val == NULL)
		return;
	fprintf(out, ",\"%s\":", key);
	json_str(out, val);
}

static void
json_kv_int(FILE *out, const char *key, long val)
{
	fprintf(out, ",\"%s\":%ld", key, val);
}

int
honeyd_json_open(const char *path)
{
	honeyd_json_close();
	if (path == NULL)
		return (0);
	if (json_path != path) {
		free(json_path);
		if ((json_path = strdup(path)) == NULL)
			return (-1);
	}

	if (strcmp(json_path, "-") == 0) {
		json_fp = stdout;
	} else if ((json_fp = fopen(json_path, "a")) == NULL) {
		syslog(LOG_ERR, "%s: fopen(\"%s\"): %m", __func__, json_path);
		return (-1);
	}
	setvbuf(json_fp, NULL, _IOLBF, 0);
	json_failed = 0;
	return (0);
}

void
honeyd_json_close(void)
{
	if (json_fp != NULL && json_fp != stdout)
		fclose(json_fp);
	else if (json_fp == stdout)
		fflush(stdout);
	json_fp = NULL;
}

/* Reopen after log rotation (SIGUSR1) */
void
honeyd_json_reopen(void)
{
	if (json_path != NULL)
		honeyd_json_open(json_path);
}

static void
json_time(FILE *out)
{
	struct timeval tv;
	struct tm tm;
	char buf[32];

	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
	fprintf(out, "{\"ts\":\"%s.%06ldZ\"", buf, (long)tv.tv_usec);
}

static void
json_tcpflags(FILE *out, int flags)
{
	char f[9];
	int i = 0;

	if (flags & TH_FIN) f[i++] = 'F';
	if (flags & TH_SYN) f[i++] = 'S';
	if (flags & TH_RST) f[i++] = 'R';
	if (flags & TH_PUSH) f[i++] = 'P';
	if (flags & TH_ACK) f[i++] = 'A';
	if (flags & TH_URG) f[i++] = 'U';
	if (flags & TH_ECE) f[i++] = 'E';
	if (flags & TH_CWR) f[i++] = 'C';
	f[i] = '\0';
	json_kv_str(out, "tcp_flags", f);
}

/* Common fields: event, protocol, endpoints, honeypot template */
static void
json_common(FILE *out, const char *event, int proto, const struct tuple *hdr)
{
	char asrc[24], adst[24], protoname[16];
	struct addr src, dst;
	struct template *tmpl;
	const char *hp = NULL;
	u_short sport, dport;
	struct protoent *pe;

	json_time(out);
	json_kv_int(out, "v", JSONLOG_SCHEMA);
	json_kv_str(out, "event", event);
	json_kv_str(out, "sensor_id", json_sensor_id());

	switch (proto) {
	case IP_PROTO_TCP:  strlcpy(protoname, "tcp", sizeof(protoname)); break;
	case IP_PROTO_UDP:  strlcpy(protoname, "udp", sizeof(protoname)); break;
	case IP_PROTO_ICMP: strlcpy(protoname, "icmp", sizeof(protoname)); break;
	default:
		pe = getprotobynumber(proto);
		strlcpy(protoname, pe != NULL ? pe->p_name : "unknown",
		    sizeof(protoname));
	}
	json_kv_str(out, "proto", protoname);
	json_kv_int(out, "proto_num", proto);

	if (hdr == NULL)
		return;

	/* Same orientation as the text log: src is the initiator */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src, IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);
	sport = hdr->sport;
	dport = hdr->dport;
	if (hdr->local) {
		struct addr t = src;
		src = dst; dst = t;
		sport = hdr->dport; dport = hdr->sport;
	}
	addr_ntop(&src, asrc, sizeof(asrc));
	addr_ntop(&dst, adst, sizeof(adst));

	json_kv_str(out, "src_ip", asrc);
	json_kv_str(out, "dst_ip", adst);
	if (hdr->type == SOCK_STREAM || hdr->type == SOCK_DGRAM) {
		json_kv_int(out, "src_port", sport);
		json_kv_int(out, "dst_port", dport);
	} else if (hdr->type == SOCK_RAW && proto == IP_PROTO_ICMP) {
		json_kv_int(out, "icmp_type", hdr->sport);
		json_kv_int(out, "icmp_code", hdr->dport);
	}

	/* The honeypot is whichever side has a bound template */
	if ((tmpl = template_find(adst)) != NULL)
		hp = adst;
	else if ((tmpl = template_find(asrc)) != NULL)
		hp = asrc;
	if (tmpl != NULL) {
		json_kv_str(out, "honeypot_ip", hp);
		json_kv_str(out, "template",
		    tmpl->origin != NULL ? tmpl->origin : tmpl->name);
		if (tmpl->person != NULL)
			json_kv_str(out, "personality", tmpl->person->name);
	}
	/* outbound: sent by the honeypot (replies, honeypot-initiated) */
	if (hp != NULL)
		json_kv_str(out, "direction",
		    hp == asrc ? "outbound" : "inbound");
}

/* Writes a finished event; reports write errors once until recovery */
static void
json_emit(char *buf, size_t len)
{
	if (fwrite(buf, 1, len, json_fp) != len || fflush(json_fp) == EOF ||
	    ferror(json_fp)) {
		if (!json_failed)
			syslog(LOG_ERR, "%s: write to JSON log \"%s\" failed: %m",
			    __func__, json_path);
		json_failed = 1;
		clearerr(json_fp);
	} else if (json_failed) {
		syslog(LOG_NOTICE, "%s: JSON log \"%s\" writable again",
		    __func__, json_path);
		json_failed = 0;
	}
}

#define JSON_BEGIN(out, buf, len) \
	char *buf = NULL; size_t len = 0; FILE *out; \
	if (json_fp == NULL || (out = open_memstream(&buf, &len)) == NULL) \
		return
#define JSON_END(out, buf, len) do { \
	fputs("}\n", out); \
	if (fclose(out) == 0) \
		json_emit(buf, len); \
	free(buf); \
} while (0)

static void
json_log_probe(int proto, const struct tuple *hdr, int size, int flags,
    const char *comment)
{
	struct ip_hdr ip;
	JSON_BEGIN(out, buf, len);

	json_common(out, "packet", proto, hdr);
	json_kv_int(out, "bytes", size);
	if (proto == IP_PROTO_TCP)
		json_tcpflags(out, flags);
	ip.ip_src = hdr->ip_src;
	json_kv_str(out, "os_guess", honeyd_osfp_name(&ip));
	json_kv_str(out, "comment", comment);
	JSON_END(out, buf, len);
}

static void
json_log_flow(const char *event, int proto, const struct tuple *hdr)
{
	struct ip_hdr ip;
	JSON_BEGIN(out, buf, len);

	json_common(out, event, proto, hdr);
	if (strcmp(event, "connection.end") == 0) {
		json_kv_int(out, "bytes_in", hdr->received);
		json_kv_int(out, "bytes_out", hdr->sent);
	} else {
		ip.ip_src = hdr->ip_src;
		json_kv_str(out, "os_guess", honeyd_osfp_name(&ip));
	}
	JSON_END(out, buf, len);
}

static void
json_log_service(int proto, const struct tuple *hdr, const char *line)
{
	JSON_BEGIN(out, buf, len);

	json_common(out, "service", proto, hdr);
	json_kv_str(out, "message", line);
	JSON_END(out, buf, len);
}

FILE *
honeyd_logstart(const char *filename)
{
	FILE *logfp;
	char *logtime;

	logfp = fopen(filename, "a");
	if (logfp == NULL) {
		syslog(LOG_WARNING, "%s: fopen(\"%s\"): %m", __func__, filename);
		return (NULL);
	}

	/* Line buffered I/O */
	setvbuf(logfp, NULL, _IOLBF, 0);

	logtime = honeyd_logtime();
	fprintf(logfp, "%s phantom-mirage log started ------\n", logtime);

	return (logfp);
}

static char *
honeyd_log_comment(int proto, const struct tuple *hdr, const char *remark)
{
	static char comment[256];
	struct ip_hdr ip;
	char *name;
	
	comment[0] = '\0';

	ip.ip_src = hdr->ip_src;
	name = honeyd_osfp_name(&ip);
	if (name != NULL)
		snprintf(comment, sizeof(comment), " [%s]", name);
	if (remark != NULL)
		strlcat(comment, remark, sizeof(comment));

	return (comment);
}

void
honeyd_logend(FILE *logfp)
{
	char *logtime;

	if (logfp == NULL)
		return;

	logtime = honeyd_logtime();
	fprintf(logfp, "%s phantom-mirage log stopped ------\n", logtime);

	fclose(logfp);
}

void
honeyd_log_service(FILE *fp, int proto, const struct tuple *hdr,
    const char *line)
{
	static char myline[1024];
	char *p;
	int len;

	syslog(LOG_NOTICE, "E%s: %s", honeyd_contoa(hdr), line);
	json_log_service(proto, hdr, line);

	if (fp == NULL)
		return;

	do {
		len = sizeof(myline);
		p = strchr(line, '\n');
		if (p != NULL) {
			if ((int)(p - line) < sizeof(myline))
				len = (int)(p - line) + 1;
		}
		strlcpy(myline, line, len);

		if (p != NULL)
			line = ++p;

		fprintf(fp, "%s %s %s: |%s|\n",
		    honeyd_logtime(),
		    honeyd_logproto(proto),
		    honeyd_logtuple(hdr),
		    myline);
	} while (p != NULL && *p);
}

void
honeyd_log_probe(FILE *fp, int proto, const struct tuple *hdr,
    int size, int flags, const char *comment)
{
	json_log_probe(proto, hdr, size, flags, comment);
	if (fp == NULL)
		return;

	fprintf(fp, "%s %s - %s: %d%s%s\n",
	    honeyd_logtime(),
	    honeyd_logproto(proto),
	    honeyd_logtuple(hdr),
	    size,
	    proto == IP_PROTO_TCP ? honeyd_logtcpflags(flags) : "",
	    honeyd_log_comment(proto, hdr, comment));
}

void
honeyd_log_flownew(FILE *fp, int proto, const struct tuple *hdr)
{
	char *tuple, *logtime, *protoname;

	honeyd_json_connections++;
	json_log_flow("connection.start", proto, hdr);

	if (fp == NULL)
		return;

	logtime = honeyd_logtime();
	tuple = honeyd_logtuple(hdr);
	protoname = honeyd_logproto(proto);
	fprintf(fp, "%s %s S %s%s\n",
	    logtime, protoname, tuple,
	    honeyd_log_comment(proto, hdr, NULL));
}

void
honeyd_log_flowend(FILE *fp, int proto, const struct tuple *hdr)
{
	char *tuple, *logtime, *protoname;

	json_log_flow("connection.end", proto, hdr);

	if (fp == NULL)
		return;

	logtime = honeyd_logtime();
	tuple = honeyd_logtuple(hdr);
	protoname = honeyd_logproto(proto);
	fprintf(fp, "%s %s E %s: %d %d\n", logtime, protoname, tuple,
	    hdr->received, hdr->sent);
}

/* Periodic liveness event (--heartbeat, #30); no proto/endpoint fields */
void
honeyd_json_heartbeat(long uptime, uint64_t pkts_in, uint64_t pkts_out,
    uint64_t conns)
{
	JSON_BEGIN(out, buf, len);
	json_time(out);
	json_kv_int(out, "v", JSONLOG_SCHEMA);
	json_kv_str(out, "event", "heartbeat");
	json_kv_str(out, "sensor_id", json_sensor_id());
	json_kv_int(out, "uptime_s", uptime);
	fprintf(out, ",\"packets_in\":%llu,\"packets_out\":%llu"
	    ",\"connections\":%llu", (unsigned long long)pkts_in,
	    (unsigned long long)pkts_out, (unsigned long long)conns);
	JSON_END(out, buf, len);
}
