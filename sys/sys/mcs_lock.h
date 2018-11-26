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


#ifndef	_SYS_MCS_LOCK_H_
#define	_SYS_MCS_LOCK_H_
struct mcs_lock {
	struct proc	*mcs_wait;
	struct mcs_lock	*mcs_next;
	struct mcs_lock *mcs_global;
};

extern void mcs_lock_init(struct mcs_lock *, struct mcs_lock *);
extern void mcs_lock_enter(struct mcs_lock *);
extern void mcs_lock_leave(struct mcs_lock *);
extern int mcs_owner(struct mcs_lock *);
#endif	/* _SYS_MCS_LOCK_H_ */
