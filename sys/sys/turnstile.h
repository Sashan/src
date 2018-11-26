/*	$OpenBSD$ */

/*
 * Copyright (c) 2018 Alexandr Nedvedicky <sashan@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_SYS_TURNSTILE_H_
#define	_SYS_TURNSTILE_H_

#ifdef WITH_TURNSTILES
#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/mcs_lock.h>

#define	TS_READER_Q	0
#define	TS_WRITER_Q	1
#define	TS_COUNT	2

struct proc;
struct turnstile;

extern void turnstile_init(void);
extern struct turnstile *turnstile_alloc(void);
extern void turnstile_free(struct turnstile *);
extern struct turnstile *turnstile_lookup(void *, struct mcs_lock *);
extern void turnstile_block(struct turnstile *, int, void *, struct mcs_lock *);
extern void turnstile_remove(struct turnstile *, struct proc *, int);
extern void turnstile_wakeup(struct turnstile *, int, int, struct mcs_lock *);
extern unsigned int turnstile_readers(struct turnstile *);
extern unsigned int turnstile_writers(struct turnstile *);
extern struct proc* turnstile_first(struct turnstile *, int);

#endif	/* _KERNEL */
#endif	/* WITH_TURNSTILES */
#endif	/* _SYS_TURNSTILE_H_ */
