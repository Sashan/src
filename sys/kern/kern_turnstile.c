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
#include <sys/signalvar.h>
#include <sys/turnstile.h>
#include <sys/mcs_lock.h>

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
#define	TS_ALL(ts)	TS_READERS((ts)) + TS_WRITERS((ts))

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
	struct turnstile *ts;
	int i;

	ts = pool_get(&ts_pool, PR_WAITOK|PR_ZERO);

	for (i = 0; i < TS_COUNT; i++)
		TAILQ_INIT(&ts->ts_sleepq[i]);

	return (ts);
}

void
turnstile_free(struct turnstile *ts)
{
#ifdef	DEBUG
	int	i;

	for (i = 0; i < TS_COUNT; i++)
		KASSERT(TAILQ_EMPTY(ts->ts_sleepq[i]));
#endif
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

int
turnstile_block(struct turnstile *ts, unsigned int q, int interruptible,
    void *lock_addr, struct mcs_lock *mcs)
{
	struct ts_chain *tc = TS_CHAIN_FIND(lock_addr);
	int		 s, sig, sigintr;
	struct proc	*p = curproc;
	int		 rv;

	KASSERT(mcs_owner(mcs));
	KASSERT(q < TS_COUNT);

	if (ts == NULL) {
		/*
		 * We must donate our own turnstile, because we are the first
		 * thread, which is going to wait for particular lock.
		 */
		ts = p->p_ts;
		ts->ts_lock_addr = lock_addr;
		LIST_INSERT_HEAD(&tc->tc_head, ts, ts_chain_link);
	} else {
		/*
		 * Someone else has donated the turnstile, we put our turnstile
		 * to the free list.
		 */
		LIST_INSERT_HEAD(&ts->ts_free_list, p->p_ts,
		    ts_free_link);
		/*
		 * associate curproc with turnstile linked to lock. This way we can
		 * quickly track, which lock a thread is wiating for.
		 */
		p->p_ts = ts;
	}

	printf("%s @ %p (%p)\n", __func__, ts->ts_lock_addr, p);

#ifdef DIAGNOSTIC
	if (p->p_flag & P_CANTSLEEP)
		panic("sleep: %s failed insomnia", p->p_p->ps_comm);

	if (p->p_stat != SONPROC)
		panic("tsleep: not SONPROC");
#endif
	p->p_wchan = lock_addr;
	p->p_wmesg = "TODO: get rwlock name";
	p->p_slptime = 0;
	p->p_priority = 0;	/* priority will come later */
	p->p_ts_q = q;
	TAILQ_INSERT_HEAD(&ts->ts_sleepq[q], p, p_runq);
	ts->ts_wcount[q]++;

	mcs_lock_leave(mcs);

	/*
	 * mi_switch() expects we acquire scheduler lock. 
	 */
	SCHED_LOCK(s);

	/*
	 * It's right time to handle signal. If caller has set RW_INTR bit,
	 * then we must let curproc continue to run on CPU. The
	 * turnstile_block() bails out with error in this case.
	 */
	if (interruptible != 0) {
		/*
		 * Code below implements sleep_setup_signal() for turnstiles.
		 */
		atomic_setbits_int(&p->p_flag, P_SINTR);
		if (p->p_p->ps_single != NULL || (sig = CURSIG(p)) != 0) {
			/*
			 * There is a signal pending and caller wants to be
			 * interrupted by signal. In this case we must let
			 * caller to run on CPU. The function must bail out
			 * with  proper error code.
			 */
			p->p_stat = SONPROC;
			p->p_wchan = 0;
			p->p_wmesg = NULL;
			p->p_cpu->ci_schedstate.spc_curpriority = p->p_usrpri;

			/*
			 * We must unlock scheduler and run relevant part of
			 * sleep_finish() and sleep_finish_signal().
			 */
			SCHED_UNLOCK(s);
			/*
			 * Even though this belongs to the signal handling part
			 * of sleep, we need to clear it before the ktrace.
			 */
			atomic_clearbits_int(&p->p_flag, P_SINTR);

			/*
			 * Do turnstile specific unsleep().
			 */
			mcs_lock_enter(mcs);
			turnstile_interrupt(ts, p, mcs);

			/*
			 * Do sleep_finish_signal() for turnstile.
			 */
			rv = single_thread_check(p, 1);
			if (rv == 0) {
				sigintr = p->p_p->ps_sigacts->ps_sigintr;
				if (sigintr  & sigmask(sig))
					rv = EINTR;
				else
					rv = ERESTART;
			}
			return (rv);
		}
	}

	p->p_stat = STSLEEP;
	p->p_ru.ru_nvcsw++;
	mi_switch();

	return (0);
}

void
turnstile_remove(struct turnstile *ts, struct proc *p, int q)
{
	/*
	 * Last turnstile must be attached to process p.
	 */
	KASSERT((p->p_ts == ts) || (TS_ALL(ts) > 1));
	if ((p->p_ts = LIST_FIRST(&ts->ts_free_list)) != NULL) {
		KASSERT(TS_ALL(ts) > 1);
		LIST_REMOVE(p->p_ts, ts_free_link);
	} else {
		KASSERT(TS_ALL(ts) == 1);
		LIST_REMOVE(ts, ts_chain_link);
		ts->ts_lock_addr = 0;
		p->p_ts = ts;
	}

	ts->ts_wcount[q]--;
	TAILQ_REMOVE(&ts->ts_sleepq[q], p, p_runq);
	p->p_ts_q = TS_COUNT;
}

void
turnstile_wakeup(struct turnstile *ts, unsigned int q, int count, struct mcs_lock *mcs)
{
	TAILQ_HEAD(, proc)	wake_q;
	struct proc *p;
	int	s;

	KASSERT(mcs_owner(mcs));
	KASSERT((q == TS_READER_Q) || (q == TS_WRITER_Q));
	KASSERT(((q == TS_READER_Q) && (count <= TS_READERS(ts))) ||
	    ((q == TS_WRITER_Q) && (count <= TS_WRITERS(ts))));

	TAILQ_INIT(&wake_q);
	while (count > 0) {
		p = TAILQ_FIRST(&ts->ts_sleepq[q]);
		printf("%s @ %p (%p)\n", __func__, ts->ts_lock_addr, p);
		turnstile_remove(ts, p, q);
		TAILQ_INSERT_TAIL(&wake_q, p, p_runq);
		p->p_ts_q = TS_COUNT;
		count--;
	}
	mcs_lock_leave(mcs);

	SCHED_LOCK(s);
	while ((p = TAILQ_FIRST(&wake_q)) != NULL) {
		TAILQ_REMOVE(&wake_q, p, p_runq);
		p->p_wchan = 0;
		p->p_wmesg = NULL;
		KASSERT(p->p_stat == STSLEEP);
		setrunnable(p);
	}
	SCHED_UNLOCK(s);
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
	KASSERT(q < TS_COUNT);
	return (TAILQ_FIRST(&ts->ts_sleepq[q]));
}

/*
 * Unlike turnstile_wakeup(), turnstile_interrupt() runs on behalf of
 * setrunnable(), therefore we must not call it to avoid recursion.
 * turnstile_interrupt() just emulates unsleep().
 */
void
turnstile_interrupt(struct turnstile *ts, struct proc *p, struct mcs_lock *mcs)
{
#ifdef DEBUG
	struct proc *p_dbg;
#endif	/* DEBUG */

	KASSERT(ts != NULL);
	KASSERT(p->p_ts == ts);
	KASSERT(ts->ts_lock_addr == p->p_wchan);
	KASSERT(mcs_owner(mcs));

	if ((p->p_ts = LIST_FIRST(&ts->ts_free_list)) != NULL) {
		KASSERT(TS_ALL(ts) > 1);
		LIST_REMOVE(p->p_ts, ts_free_link);
	} else {
		KASSERT(TS_ALL(ts) == 1);
		LIST_REMOVE(ts, ts_chain_link);
	}

#ifdef DEBUG
	TAILQ_FOREACH(p_dbg, &ts->ts_sleepq[p->p_ts_q], p_runq) {
		if (p_dbg == p)
			break;
	}
	KASSERT(ts_dbg == ts);
#endif	/* DEBUG */
	printf("%s @ %p (%p)\n", __func__, ts->ts_lock_addr, p);
	TAILQ_REMOVE(&ts->ts_sleepq[p->p_ts_q], p, p_runq);
	ts->ts_wcount[p->p_ts_q]--;
	mcs_lock_leave(mcs);
	p->p_ts_q = TS_COUNT;
}
#endif	/* WITH_TURNSTILES */
