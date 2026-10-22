/*
 * atomicio(): loop read(2)/write(2) until all n bytes are done.
 * Typed prototype (C23 / GCC 15: "()" no longer means "any arguments").
 */
#ifndef _ATOMICIO_H_
#define _ATOMICIO_H_

#include <sys/types.h>
#include <unistd.h>

ssize_t atomicio(ssize_t (*)(int, void *, size_t), int, void *, size_t);

/* write(2) takes a const buffer: same ABI, cast for atomicio() */
#define vwrite ((ssize_t (*)(int, void *, size_t))write)

#endif /* _ATOMICIO_H_ */
