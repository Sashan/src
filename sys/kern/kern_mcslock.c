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

#ifdef DIAGNOSTIC
/*
 * should be ~2 secs on Hrvoje's boxes
 */
#define MCS_DELAY	1000000000UL
#endif

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
	struct proc *wait_mcs;
#ifdef DIAGNOSTIC
	unsigned long long i = MCS_DELAY;
#endif

	/*
	 * the last bit indicates a process waiting for spinlock.
	 */
	mcs->mcs_wait = (struct proc *)((unsigned long long)curproc | 1);
	mcs->mcs_next = NULL;
	old_mcs = atomic_swap_ptr(&mcs->mcs_global->mcs_next, mcs);
	
	if (old_mcs != NULL) {
		KASSERT(old_mcs->mcs_global == mcs->mcs_global);
		old_mcs->mcs_next = mcs;
		membar_exit();

		/*
		 * spin, waiting for other thread to finish
		 */
		membar_enter();
		wait_mcs = mcs->mcs_wait;
		while ((wait_mcs != NULL) && (panicstr == NULL) ) {
			membar_enter();
			wait_mcs = mcs->mcs_wait;
#ifdef DIAGNOSTIC
			i--;
			if (i == 0)
				panic("%s @ %p (%p) infinite spinlock "
				    "%p/old_mcs %p/mcs\n",
				    __func__, curproc, old_mcs->mcs_global,
				    old_mcs, mcs);
#endif
		}
	}

	mcs->mcs_wait = curproc;

	return;
}

void
mcs_lock_leave(struct mcs_lock *mcs)
{
	struct mcs_lock *old_mcs;
	struct mcs_lock *next_mcs;
#ifdef DIAGNOSTIC
	unsigned long long i = MCS_DELAY;
#endif

	membar_enter();
	next_mcs = mcs->mcs_next;
	if (next_mcs == NULL) {
		old_mcs = atomic_cas_ptr(&mcs->mcs_global->mcs_next, mcs, NULL);
		/*
		 * If there is no waiter, then we can just return.
		 */
		if (old_mcs == mcs) 
			return;
	}

	/*
	 * There is at least one waiter. We have to spin wait for our waiter to
	 * become ready.
	 */
	while (next_mcs == NULL) {
		membar_enter();
		next_mcs = mcs->mcs_next;
#ifdef DIAGNOSTIC
		i--;
		if (i == 0)
			panic("%s @ %p (%p) infinite spinlock %p/mcs\n",
			    __func__, curproc, mcs->mcs_global, mcs);
#endif
	}

	/*
	 * let our waiter run.
	 */
	KASSERT(mcs->mcs_global == next_mcs->mcs_global);
	mcs->mcs_next->mcs_wait = NULL;
	membar_exit();
}

#ifdef DIAGNOSTIC
int
mcs_owner(struct mcs_lock *mcs)
{
	return (curproc == mcs->mcs_wait);
}
#endif
