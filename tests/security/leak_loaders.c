/*
 * PM-SCR-213, personality.c personality_config_new: a fingerprint whose
 * name was already loaded replaced the old personality, but
 * personality_free released only the name and the struct, not the TCP
 * option arrays of its tests (CWE-401).
 *
 * PM-SCR-214, xprobe_assoc.c parse_associations: an association whose
 * key was already loaded was neither inserted nor freed (CWE-401).
 *
 * PM-SCR-231, personality.c parse_option: a fingerprint test line that
 * repeats its O= field allocated a second options array over the first
 * one (CWE-401).
 *
 * Each case loads a small file with the same entry twice and exits; the
 * test runs LeakSanitizer with no suppressions.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <event2/event.h>
#include <dnet.h>
#include "honeyd.h"
#include "personality.h"
#include "xprobe_assoc.h"

extern rand_t *honeyd_rand;
extern struct event_base *libevent_base;

static const char fingerprint[] =
	"Fingerprint Leak Test OS\n"
	"Class Test | embedded || test\n"
	"SEQ(SP=0-5%GCD=61A8|C350%ISR=8A-94%TI=I%II=RI%SS=O%TS=U)\n"
	"OPS(O1=M5B4|WANM5B4T10S%O2=M578|M578W0ST10L%O3=M280|T10NNW5NM280"
	"%O4=M5B4|ST10WAL%O5=M218|M218ST10WAL%O6=M109|M109ST10)\n"
	"WIN(W1=0|3180%W2=0|3180%W3=0|3180%W4=0|3180%W5=0|3180%W6=0|3180)\n"
	"ECN(R=Y%DF=N%T=3B-45%TG=40%W=0%O=WANM5B4SNN%CC=N%Q=R)\n"
	"T1(R=Y%DF=N%T=3B-45%TG=40%S=O|Z%A=S+%F=AR|AS%RD=0%Q=)\n"
	"T2(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=Z%A=S%F=AR%O=WANM109T10S%RD=0%Q=)\n"
	"T3(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=O%F=AR%O=WANM109T10S%RD=0%Q=)\n"
	"T4(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=WANM109T10S%RD=0%Q=)\n"
	"T5(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=WANM109T10S%RD=0%Q=)\n"
	"T6(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=WANM109T10S%RD=0%Q=)\n"
	"T7(R=Y%DF=N%T=3B-45%TG=40%W=0%S=Z%A=S+%F=AR%O=WFNM109T10S%RD=0%Q=)\n"
	"U1(DF=N%T=FA-104%TG=FF%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G"
	"%RUD=G)\n"
	"IE(DFI=S%T=FA-104%TG=FF%CD=S)\n"
	"\n";

/* T2 repeats O=; the second value wins */
static const char dupfield[] =
	"Fingerprint Dup Field OS\n"
	"Class Test | embedded || test\n"
	"T2(R=Y%DF=Y%W=0%O=WANM109T10S%S=Z%A=S%F=AR%O=M5B4NNS%RD=0%Q=)\n"
	"\n";

static FILE *
twice(const char *text)
{
	FILE *fp;

	if ((fp = tmpfile()) == NULL)
		abort();
	fputs(text, fp);
	fputs(text, fp);
	rewind(fp);
	return (fp);
}

int
main(int argc, char **argv)
{
	const char *t = argc > 1 ? argv[1] : "";
	FILE *fp;

	if ((honeyd_rand = rand_open()) == NULL)
		abort();
	/* personality_init adds its timer to the base, as the daemon does */
	if ((libevent_base = event_base_new()) == NULL)
		abort();

	if (strcmp(t, "personality") == 0) {
		personality_init();
		xprobe_personality_init();
		associations_init();
		fp = twice(fingerprint);
		if (personality_parse(fp) == -1 ||
		    personality_find("Leak Test OS") == NULL) {
			printf("FAIL: fingerprint not loaded\n");
			return (1);
		}
		fclose(fp);
		printf("ok: duplicate fingerprint loaded\n");
		return (0);
	}
	if (strcmp(t, "dupfield") == 0) {
		struct personality *pers;

		personality_init();
		xprobe_personality_init();
		associations_init();
		if ((fp = tmpfile()) == NULL)
			abort();
		fputs(dupfield, fp);
		rewind(fp);
		if (personality_parse(fp) == -1 ||
		    (pers = personality_find("Dup Field OS")) == NULL) {
			printf("FAIL: fingerprint not loaded\n");
			return (1);
		}
		fclose(fp);
		printf("T2 options: %u, first %c\n",
		    pers->t_tests[1].options.count,
		    pers->t_tests[1].options.count ?
		    pers->t_tests[1].options.options[0].opt_type : '-');
		if (pers->t_tests[1].options.count != 4 ||
		    pers->t_tests[1].options.options[0].opt_type != 'M') {
			printf("FAIL: the last O= value is not the one kept\n");
			return (1);
		}
		printf("ok: repeated field loaded\n");
		return (0);
	}
	if (strcmp(t, "assoc") == 0) {
		static struct xp_fingerprint xp;

		xprobe_personality_init();
		associations_init();
		xp.os_id = "Leak Test XP";
		SPLAY_INSERT(xp_fprint_tree, &xp_fprints, &xp);
		fp = twice("Leak Test OS;Leak Test XP\n");
		if (parse_associations(fp) == -1) {
			printf("FAIL: associations not loaded\n");
			return (1);
		}
		fclose(fp);
		printf("ok: duplicate association loaded\n");
		return (0);
	}
	printf("FAIL: unknown case %s\n", t);
	return (1);
}
