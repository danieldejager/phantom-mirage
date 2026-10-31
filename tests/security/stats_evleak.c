/*
 * PM-SCR-132: the stats collector's read_cb() allocated and added a new
 * receive event for every datagram and never freed it.
 *
 * honeydstats_main.c is compiled in with its main() renamed; make_socket
 * is wrapped to return one end of a local datagram socketpair and
 * signature_process is wrapped, so nothing touches the network. LeakSanitizer
 * reports what is lost after 10000 datagrams.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define main honeydstats_real_main
#include "../../honeydstats_main.c"
#undef main

#define NDGRAMS	10000

static int peer = -1;
static int processed;

int
__wrap_make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    int type, char *address, uint16_t port)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == -1)
		return (-1);
	peer = sv[1];
	return (sv[0]);
}

int
__wrap_signature_process(struct evbuffer *evbuf)
{
	processed++;
	return (0);
}

static int
free_event(const struct event_base *base, const struct event *ev, void *arg)
{
	event_del((struct event *)ev);
	event_free((struct event *)ev);
	return (0);
}

int
main(void)
{
	int i;

	stats_libevent_base = event_base_new();
	setup_socket("127.0.0.1", 0);
	for (i = 0; i < NDGRAMS; i++) {
		if (send(peer, "x", 1, 0) != 1) {
			printf("FAIL: send\n");
			return (1);
		}
		event_base_loop(stats_libevent_base, EVLOOP_ONCE);
	}
	printf("datagrams processed: %d\n", processed);
	if (processed != NDGRAMS) {
		printf("FAIL: expected %d\n", NDGRAMS);
		return (1);
	}
	/* Free whatever receive event is still registered */
	event_base_foreach_event(stats_libevent_base, free_event, NULL);
	evbuffer_free(evbuf_recv);
	event_base_free(stats_libevent_base);
	close(fd_recv);
	close(peer);
	return (0);
}
