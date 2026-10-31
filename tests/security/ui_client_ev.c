/*
 * PM-SCR-007, ui.c: ui_dead() only called event_del() on the read and
 * write events of a control client, so every control connection leaked
 * two events.
 *
 * ui_init() sets up the control socket in a temporary directory, so the
 * peer credential check accepts our own uid. Each round connects, lets
 * the accept event run ui_new(), closes the client end and lets
 * ui_handler() see EOF and call ui_dead().
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "fuzz_common.h"
#include "evcount.h"

extern char *ui_file;
void ui_init(void);

#define ROUNDS	50

int
main(void)
{
	struct sockaddr_un sun;
	char dir[] = "/tmp/ui_client_ev.XXXXXX";
	int i, base, made, c;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(NULL);
	if (mkdtemp(dir) == NULL)
		abort();
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/s", dir);
	ui_file = sun.sun_path;
	ui_init();

	base = ev_live;
	made = ev_made;
	for (i = 0; i < ROUNDS; i++) {
		if ((c = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ||
		    connect(c, (struct sockaddr *)&sun, sizeof(sun)) == -1)
			abort();
		fuzz_drain_events();	/* accept: ui_new() */
		close(c);
		fuzz_drain_events();	/* EOF: ui_dead() */
		fuzz_drain_events();
	}
	if (ev_made - made < 2 * ROUNDS) {
		printf("FAIL ui: only %d events made, clients not accepted\n",
		    ev_made - made);
		return (1);
	}
	ev_check("ui", ROUNDS, ev_live - base, 0);

	unlink(sun.sun_path);
	rmdir(dir);
	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: ui_client_ev\n");
	return (0);
}
