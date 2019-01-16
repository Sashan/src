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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/mcs_lock.h>
#include <sys/atomic.h>

void
mcs_lock_init(struct mcs_lock *mcs_local, struct mcs_lock *mcs_global)
{
	memset(mcs_local, 0, sizeof (struct mcs_lock));
	mcs_local->mcs_global = mcs_global;
}

void
mcs_lock_enter(struct mcs_lock *mcs)
{
	struct mcs_lock *old_mcs;

	mcs->mcs_wait = curproc;
	mcs->mcs_next = NULL;
	old_mcs = atomic_swap_ptr(&mcs->mcs_global->mcs_next, mcs);
	
	if (old_mcs != NULL) {
		old_mcs->mcs_next = mcs;

		/* spin, waiting for other thread to finish */
		while (mcs->mcs_wait != NULL) ;

		mcs->mcs_wait = curproc;
	}

	return;
}

void
mcs_lock_leave(struct mcs_lock *mcs)
{
	struct mcs_lock *old_mcs;

	old_mcs = atomic_swap_ptr(&mcs->mcs_global->mcs_next, mcs->mcs_next);
	KASSERT(old_mcs != NULL);
	if (old_mcs != mcs) {
		/*
		 * Let the waiter run then.
		 */
		old_mcs->mcs_wait = NULL;
	}
}

#ifdef DIAGNOSTIC
int
mcs_owner(struct mcs_lock *mcs)
{
	return (curproc == mcs->mcs_wait);
}
#endif
