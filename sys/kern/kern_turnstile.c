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

#ifdef WITH_TURNSTILES

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/timeout.h>
#include <sys/pool.h>
#include <sys/turnstile.h>
#include <sys/mcs_lock.h>

#define	TS_READER_Q	0
#define	TS_WRITER_Q	1
#define	TS_COUNT	2

struct turnstile {
	LIST_ENTRY(turnstile)	 ts_chain_link;
	LIST_ENTRY(turnstile)	 ts_free_link;
	LIST_HEAD(, turnstile)	 ts_free_list;
	void			*ts_lock_addr;
	/* turnstile sleep queues are protected by chain lock (tc_lock) */
	TAILQ_HEAD(, proc)	 ts_sleepq[TS_COUNT];
	unsigned int		 ts_wcount[TS_COUNT];
};

#define	TS_READERS(ts)	((ts)->ts_wcount[TS_READER_Q])
#define	TS_WRITERS(ts)	((ts)->ts_wcount[TS_WRITER_Q])
#define	TS_ALL(ts)	\
	((ts)->ts_wcount[TS_READER_Q] + (ts)->ts_wcount[TS_WRITER_Q])

#define	TS_HASH_SIZE	32	/* must be power of 2 */
/*
 * We are hashing on memory address of lock. Shift by 8
 * as kern_synch.c does:
 *     We're only looking at 7 bits of the address; everything is
 *     aligned to 4, lots of things are aligned to greater powers
 *     of 2.  Shift right by 8, i.e. drop the bottom 256 worth.
 */
#define	TS_HASH(lock_addr)	\
	((((unsigned int)lock_addr) >> 8) & (TS_HASH_SIZE - 1))

struct ts_chain {
	LIST_HEAD(ts_list, turnstile)	tc_head;
	struct mcs_lock			tc_lock;	/* spin lock */
};

struct ts_chain	ts_chains[TS_HASH_SIZE];

struct pool ts_pool;

#define	TS_CHAIN_FIND(lock_addr)	&ts_chains[TS_HASH((lock_addr))]

void
turnstile_init(void)
{
	pool_init(&ts_pool, sizeof(struct turnstile), 0, IPL_NONE,
	    PR_WAITOK, "turnstilepl", NULL);
}

struct turnstile *
turnstile_alloc(void)
{
	return (pool_get(&ts_pool, PR_WAITOK|PR_ZERO));
}

void
turnstile_free(struct turnstile *ts)
{
	pool_put(&ts_pool, ts);
}

struct turnstile *
turnstile_lookup(void *lock_addr, struct mcs_lock *mcs)
{
	struct ts_chain *tc = TS_CHAIN_FIND(lock_addr);
	struct turnstile *ts = NULL;

	mcs_lock_init(mcs, &tc->tc_lock);
	mcs_lock_enter(mcs);
	ts = LIST_FIRST(&tc->tc_head);
	while ((ts != NULL) && (ts->ts_lock_addr != lock_addr))
		ts = LIST_NEXT(ts, ts_chain_link);

	return (ts);
}

void
turnstile_block(struct turnstile *ts, int q, void *lock_addr,
    struct mcs_lock *mcs)
{
	struct ts_chain *tc = TS_CHAIN_FIND(lock_addr);
	int			s;


	KASSERT(mcs_owner(mcs));

	if (ts == NULL) {
		/*
		 * We must donate our own turnstile, because we are the first
		 * thread, which is going to wait for particular lock.
		 */
		ts = curproc->p_ts;
		ts->ts_lock_addr = lock_addr;
		LIST_INSERT_HEAD(&tc->tc_head, ts, ts_chain_link);
	} else {
		/*
		 * Someone else has donated the turnstile, we put our turnstile
		 * to the free list.
		 */
		LIST_INSERT_HEAD(&ts->ts_free_list, curproc->p_ts,
		    ts_free_link);
		/*
		 * associate curproc with turnstile linked to lock. This way we can
		 * quickly track, which lock a thread is wiating for.
		 */
		curproc->p_ts = ts;
	}

	/*
	 * Code below implements special case of sleep_setup() for turnstile.
	 */
#ifdef DIAGNOSTIC
	if (curproc->p_flag & P_CANTSLEEP)
		panic("sleep: %s failed insomnia", curproc->p_p->ps_comm);

	if (curproc->p_stat != SONPROC)
		panic("tsleep: not SONPROC");
#endif
	curproc->p_wchan = lock_addr;
	curproc->p_wmesg = "TODO: get rwlock name";
	curproc->p_slptime = 0;
	curproc->p_priority = 0;	/* priority will come later */
	TAILQ_INSERT_HEAD(&ts->ts_sleepq[q], curproc, p_runq);
	ts->ts_wcount[q]++;
	/*
	 * sleep_setup() is done. Now we should do turnstile specific sleep
	 * finish.
	 */

	curproc->p_stat = SSLEEP;
	curproc->p_ru.ru_nvcsw++;

	mcs_lock_leave(mcs);

	/*
	 * We'd like current process to give up CPU here. It will be woken
	 * up by lock exit() call, not by scheduler (unless there will be
	 * signal sent to process). mi_switch() expects we acquire scheduler
	 * lock. 
	 */
	SCHED_LOCK(s);
	mi_switch();
}

void
turnstile_remove(struct turnstile *ts, struct proc *p, int q)
{
	int	s;

	if ((p->p_ts = LIST_FIRST(&ts->ts_free_list)) != NULL) {
		KASSERT(TS_ALL(ts) > 1);
		LIST_REMOVE(p->p_ts, ts_free_link);
	} else {
		KASSERT(TS_ALL(ts) == 1);
		LIST_REMOVE(ts, ts_chain_link);
	}

	ts->ts_wcount[q]--;
	TAILQ_REMOVE(&ts->ts_sleepq[q], p, p_runq);
	/*
	 * TODO:
	 *	inspect the code for correct lock order of SCHED_LOCK() and
	 *	turnstile chain lock. We are still holding a chain lock here.
	 */
	SCHED_LOCK(s);
	p->p_wchan = 0;
	KASSERT(p->p_stat == SSLEEP);
	setrunnable(p);
	SCHED_UNLOCK(s);
}

void
turnstile_wakeup(struct turnstile *ts, int q, int count, struct mcs_lock *mcs)
{
	struct ts_chain *tc = TS_CHAIN_FIND(ts->ts_lock_addr);
	struct proc *p;

	KASSERT(mcs_owner(&tc->tc_lock));
	while (count > 0) {
		p = TAILQ_FIRST(&ts->ts_sleepq[q]);
		turnstile_remove(ts, p, q);
	}

	mcs_lock_leave(mcs);
}

unsigned int
turnstile_readers(struct turnstile *ts)
{
	return (TS_READERS(ts));
}

unsigned int
turnstile_writers(struct turnstile *ts)
{
	return (TS_WRITERS(ts));
}

struct proc *
turnstile_first(struct turnstile *ts, int q)
{
	return (TAILQ_FIRST(&ts->ts_sleepq[q]));
}
#endif	/* WITH_TURNSTILES */
