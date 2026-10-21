/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _UI_H_
#define _UI_H_

struct uiclient {
	int fd;

	struct event *ev_read;
	struct event *ev_write;

	struct evbuffer *inbuf;
	struct evbuffer *outbuf;
};

void ui_init(void);

/*
 * The control socket accepts config-language commands, which can make
 * honeyd run arbitrary programs: access to it is root-equivalent. It
 * lives in a root-owned directory (0700, or 0750 when HONEYD_UI_GROUP
 * names a group allowed to use honeydctl).
 */
#define UI_DIR		"/run/phantom-mirage"
#define UI_FIFO		UI_DIR "/phantom-mirage.sock"
#define UI_GROUP_ENV	"PHANTOM_MIRAGE_UI_GROUP"

#endif /* !_UI_H_ */
