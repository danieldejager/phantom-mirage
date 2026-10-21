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

#ifndef _POOL_
#define _POOL_

#include <stddef.h>
#include <syslog.h>

#define POOL_PAGE_SIZE	4096

struct pool_entry {
	SLIST_ENTRY(pool_entry) next;
	void *data;
	size_t size;
};

/*
 * Every entry header and the object that follows it must be suitably
 * aligned for any type.  The header is padded to POOL_ALIGN and each
 * slot stride is rounded up to POOL_ALIGN so page-carved entries stay
 * aligned regardless of the pool's element size (#54).
 */
#define POOL_ALIGN	_Alignof(max_align_t)
#define POOL_ROUNDUP(x)	(((x) + POOL_ALIGN - 1) & ~((size_t)POOL_ALIGN - 1))
#define POOL_HDR_SIZE	POOL_ROUNDUP(sizeof(struct pool_entry))
#define POOL_STRIDE(sz)	(POOL_HDR_SIZE + POOL_ROUNDUP(sz))

struct pool {
	SLIST_HEAD(poolq, pool_entry) entries;
	size_t size;
	int nalloc;
};

struct pool *pool_init(size_t);
void *pool_alloc_size(struct pool *, size_t);

/* 
 * The pool interface cached allocation of fixed sized objects,
 * but it can also be used to allocate larger buffers if necessary.
 */

static __inline void *
pool_alloc(struct pool *pool)
{
	struct pool_entry *entry;

	if ((entry = SLIST_FIRST(&pool->entries)) == NULL)
		return (pool_alloc_size(pool, 0));

	SLIST_REMOVE_HEAD(&pool->entries, next);
	return (entry->data);
}

static __inline void
pool_free(struct pool *pool, void *addr)
{
	struct pool_entry *entry = (void *)((char *)addr - POOL_HDR_SIZE);

	if (entry->data != addr)
	{
		syslog(LOG_ERR, "%s: bad address: %p != %p", __func__, addr, entry->data);
		exit(EXIT_FAILURE);
	}

	if (entry->size == pool->size)
		SLIST_INSERT_HEAD(&pool->entries, entry, next);
	else {
		free(entry);
		pool->nalloc--;
	}
}

#endif /* _POOL_ */
