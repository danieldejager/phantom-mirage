/*
 * PM-SCR-140: IPL and RIPL from a fingerprint file are converted and
 * offset without range checks, so out of range values become negative
 * or very large quote lengths. Each case parses one synthetic
 * fingerprint and checks out of range values are refused at load.
 *
 * Usage: pers_ipl
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "fuzz_common.h"

static int ncase;

static int
check(const char *u1, int want_ok, int quotelen, int riplen)
{
	char buf[256], name[32];
	struct personality *pers;
	FILE *fp;
	int rc, fail = 0;

	snprintf(name, sizeof(name), "Test Host %d", ++ncase);
	snprintf(buf, sizeof(buf), "Fingerprint %s\nU1(%s)\n", name, u1);
	if ((fp = fmemopen(buf, strlen(buf), "r")) == NULL)
		abort();
	rc = personality_parse(fp);
	fclose(fp);
	printf("U1(%s): parse %s", u1, rc == 0 ? "accepted" : "refused");
	if (want_ok && rc != 0)
		fail = 1;
	if (!want_ok && rc == 0)
		fail = 1;
	if (rc == 0 && want_ok) {
		if ((pers = personality_find(name)) == NULL)
			abort();
		printf(", quotelen %d riplen %d", pers->udptest.quotelen,
		    pers->udptest.riplen);
		if (pers->udptest.quotelen != quotelen ||
		    pers->udptest.riplen != riplen)
			fail = 1;
	}
	printf("%s\n", fail ? " FAIL" : "");
	return (fail);
}

int
main(void)
{
	int fail = 0;

	fuzz_honeyd_init(NULL);
	/* In range values still load */
	fail |= check("R=Y%IPL=38%RIPL=G", 1, 28, 0);
	fail |= check("R=Y%IPL=1C%RIPL=134", 1, 0, -20);
	fail |= check("R=Y%IPL=FFFF%RIPL=FFFF", 1, 65507, 65207);
	/* Out of range values are refused */
	fail |= check("R=Y%IPL=10%RIPL=G", 0, 0, 0);
	fail |= check("R=Y%IPL=0%RIPL=G", 0, 0, 0);
	fail |= check("R=Y%IPL=10000%RIPL=G", 0, 0, 0);
	fail |= check("R=Y%IPL=FFFFFFFF%RIPL=G", 0, 0, 0);
	fail |= check("R=Y%IPL=ZZ%RIPL=G", 0, 0, 0);
	fail |= check("R=Y%IPL=38%RIPL=10000", 0, 0, 0);
	fail |= check("R=Y%IPL=38%RIPL=FFFFFFFF", 0, 0, 0);
	fail |= check("R=Y%IPL=38%RIPL=ZZ", 0, 0, 0);
	printf(fail ? "FAIL\n" : "OK\n");
	return (fail);
}
