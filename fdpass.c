/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/uio.h>
#include <syslog.h>

#include <errno.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>

#include "fdpass.h"

int
send_fd(int socket, int fd, void *base, size_t len)
{
#if defined(HAVE_SENDMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	char ch = '\0';
	ssize_t n;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
#endif

	if (base == NULL) {
		vec.iov_base = &ch;
		vec.iov_len = 1;
	} else {
		vec.iov_base = base;
		vec.iov_len = len;
	}
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	if ((n = sendmsg(socket, &msg, 0)) == -1) {
		if (errno == EAGAIN)
			return (-1);
		syslog(LOG_ERR,"%s: sendmsg(%d): %s", __func__, fd, strerror(errno));
		return (-1);
	}
	if (n == 0)
	{
		syslog(LOG_ERR,"%s: sendmsg: expected setn >0 got %ld", __func__, (long)n);
		errno = EPIPE;
		return (-1);
	}
	if ((size_t)n != vec.iov_len) {
		/*
		 * CWE-252: the descriptor went with a partial message. The
		 * peer cannot use it, and a retry would pass it twice.
		 */
		syslog(LOG_ERR, "%s: sendmsg: sent %ld of %lu bytes",
		    __func__, (long)n, (unsigned long)vec.iov_len);
		errno = EPIPE;
		return (-1);
	}
#else
	syslog(LOG_ERR, "%s: subsystems not supported due to lack of fd passing",__func__);
			exit(EXIT_FAILURE);
#endif

	return (0);
}

int
receive_fd(int socket, void *base, socklen_t *len)
{
#if defined(HAVE_RECVMSG) && (defined(HAVE_ACCRIGHTS_IN_MSGHDR) || defined(HAVE_CONTROL_IN_MSGHDR))
	struct msghdr msg;
	struct iovec vec;
	ssize_t n;
	char ch;
	int fd;
#ifndef HAVE_ACCRIGHTS_IN_MSGHDR
	char tmp[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
#endif

	memset(&msg, 0, sizeof(msg));
	if (base == NULL) {
		vec.iov_base = &ch;
		vec.iov_len = 1;
	} else {
		vec.iov_base = base;
		vec.iov_len = *len;
	}
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	msg.msg_accrights = (caddr_t)&fd;
	msg.msg_accrightslen = sizeof(fd);
#else
	msg.msg_control = tmp;
	msg.msg_controllen = sizeof(tmp);
#endif

	while ((n = recvmsg(socket, &msg, 0)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return (-1);
		syslog(LOG_ERR,"%s: recvmsg: %s", __func__, strerror(errno));
		return (-1);
	}
	if (n == 0)
	{
		syslog(LOG_ERR,"%s: recvmsg: expected received >0 got %ld", __func__, (long)n);
		errno = ECONNRESET;
		return (-1);
	}
	if (len != 0)
		*len = n;

#ifdef HAVE_ACCRIGHTS_IN_MSGHDR
	if (msg.msg_accrightslen != sizeof(fd))
	{
		syslog(LOG_ERR,"%s: no fd", __func__);
		errno = EBADMSG;
		return (-1);
	}
#else
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || (msg.msg_flags & MSG_CTRUNC) ||
	    cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
		/* Close any descriptor that did arrive with the message */
		if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			size_t i, nfds = (cmsg->cmsg_len - CMSG_LEN(0)) /
			    sizeof(int);

			for (i = 0; i < nfds && CMSG_LEN((i + 1) * sizeof(int)) <=
			    msg.msg_controllen; i++) {
				memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int),
				    sizeof(fd));
				close(fd);
			}
		}
		syslog(LOG_ERR, "%s: message without a single descriptor",
		    __func__);
		errno = EBADMSG;
		return (-1);
	}
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
#endif
	return fd;
#else
	{
	syslog(LOG_ERR, "%s: subsystems not supported due to lack of fd pasing", __func__);
	exit(EXIT_FAILURE);
	}
#endif
}

/*
 * Like receive_fd, but waits at most timeout_ms for the descriptor when
 * the socket is non blocking, and makes the received descriptor non
 * blocking. Returns -1 with errno ETIMEDOUT when the peer sends nothing
 * in time.
 */
int
receive_fd_timed(int socket, void *base, socklen_t *len, int timeout_ms)
{
	struct timespec start, now;
	struct pollfd pfd;
	int fd, left;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		if ((fd = receive_fd(socket, base, len)) != -1) {
			/* Our end only: never block on what a peer sent */
			if (fcntl(fd, F_SETFL,
			    fcntl(fd, F_GETFL) | O_NONBLOCK) == -1) {
				syslog(LOG_ERR, "%s: fcntl(O_NONBLOCK): %s",
				    __func__, strerror(errno));
				close(fd);
				return (-1);
			}
			return (fd);
		}
		if (errno != EAGAIN)
			return (-1);
		clock_gettime(CLOCK_MONOTONIC, &now);
		left = timeout_ms - (int)((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000);
		if (left <= 0) {
			syslog(LOG_ERR, "%s: no descriptor after %d ms",
			    __func__, timeout_ms);
			errno = ETIMEDOUT;
			return (-1);
		}
		pfd.fd = socket;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, left) == -1 && errno != EINTR)
			return (-1);
	}
}

/*
 * Like send_fd, but on a non blocking socket waits at most timeout_ms
 * for room instead of failing at once. Returns -1 with errno ETIMEDOUT
 * when the peer does not drain the socket in time.
 */
int
send_fd_timed(int socket, int fd, void *base, size_t len, int timeout_ms)
{
	struct timespec start, now;
	struct pollfd pfd;
	int left;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		if (send_fd(socket, fd, base, len) == 0)
			return (0);
		if (errno != EAGAIN)
			return (-1);
		clock_gettime(CLOCK_MONOTONIC, &now);
		left = timeout_ms - (int)((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000);
		if (left <= 0) {
			syslog(LOG_ERR, "%s: peer not draining after %d ms",
			    __func__, timeout_ms);
			errno = ETIMEDOUT;
			return (-1);
		}
		pfd.fd = socket;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, left) == -1 && errno != EINTR)
			return (-1);
	}
}
