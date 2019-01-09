/*	$OpenBSD: kern_rwlock.c,v 1.37 2018/06/08 15:38:15 guenther Exp $	*/

/*
 * Copyright (c) 2002, 2003 Artur Grabowski <art@openbsd.org>
 * Copyright (c) 2011 Thordur Bjornsson <thib@secnorth.net>
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
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/limits.h>
#include <sys/atomic.h>
#include <sys/witness.h>
#ifdef WITH_TURNSTILES
#include <sys/turnstile.h>
#endif

/* XXX - temporary measure until proc0 is properly aligned */
#define RW_PROC(p) (((long)p) & ~RWLOCK_MASK)

#ifdef MULTIPROCESSOR
#define rw_cas(p, o, n)	(atomic_cas_ulong(p, o, n) != o)
#else
static inline int
rw_cas(volatile unsigned long *p, unsigned long o, unsigned long n)
{
	if (*p != o)
		return (1);
	*p = n;

	return (0);
}
#endif

#ifndef WITH_TURNSTILES
/*
 * Magic wand for lock operations. Every operation checks if certain
 * flags are set and if they aren't, it increments the lock with some
 * value (that might need some computing in a few cases). If the operation
 * fails, we need to set certain flags while waiting for the lock.
 *
 * RW_WRITE	The lock must be completely empty. We increment it with
 *		RWLOCK_WRLOCK and the proc pointer of the holder.
 *		Sets RWLOCK_WAIT|RWLOCK_WRWANT while waiting.
 * RW_READ	RWLOCK_WRLOCK|RWLOCK_WRWANT may not be set. We increment
 *		with RWLOCK_READ_INCR. RWLOCK_WAIT while waiting.
 */
static const struct rwlock_op {
	unsigned long inc;
	unsigned long check;
	unsigned long wait_set;
	long proc_mult;
	int wait_prio;
} rw_ops[] = {
	{	/* RW_WRITE */
		RWLOCK_WRLOCK,
		ULONG_MAX,
		RWLOCK_WAIT | RWLOCK_WRWANT,
		1,
		PLOCK - 4
	},
	{	/* RW_READ */
		RWLOCK_READ_INCR,
		RWLOCK_WRLOCK,
		RWLOCK_WAIT,
		0,
		PLOCK
	},
	{	/* Sparse Entry. */
		0,
	},
	{	/* RW_DOWNGRADE */
		RWLOCK_READ_INCR - RWLOCK_WRLOCK,
		0,
		0,
		-1,
		PLOCK
	},
};
#endif	/* !WITH_TURNSTILES */

void
_rw_enter_read(struct rwlock *rwl LOCK_FL_VARS)
{
	unsigned long owner = rwl->rwl_owner;

	if (__predict_false((owner & RWLOCK_WRLOCK) ||
	    rw_cas(&rwl->rwl_owner, owner, owner + RWLOCK_READ_INCR)))
		_rw_enter(rwl, RW_READ LOCK_FL_ARGS);
	else {
		membar_enter_after_atomic();
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj, LOP_NEWORDER, file, line,
		    NULL);
		WITNESS_LOCK(&rwl->rwl_lock_obj, 0, file, line);
	}
}

void
_rw_enter_write(struct rwlock *rwl LOCK_FL_VARS)
{
	struct proc *p = curproc;

	if (__predict_false(rw_cas(&rwl->rwl_owner, 0,
	    RW_PROC(p) | RWLOCK_WRLOCK)))
		_rw_enter(rwl, RW_WRITE LOCK_FL_ARGS);
	else {
		membar_enter_after_atomic();
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj,
		    LOP_EXCLUSIVE | LOP_NEWORDER, file, line, NULL);
		WITNESS_LOCK(&rwl->rwl_lock_obj, LOP_EXCLUSIVE, file, line);
	}
}

void
_rw_exit_read(struct rwlock *rwl LOCK_FL_VARS)
{
	unsigned long owner = rwl->rwl_owner;

	rw_assert_rdlock(rwl);

	membar_exit_before_atomic();
	if (__predict_false((owner & RWLOCK_WAIT) ||
	    rw_cas(&rwl->rwl_owner, owner, owner - RWLOCK_READ_INCR)))
		_rw_exit(rwl LOCK_FL_ARGS);
	else
		WITNESS_UNLOCK(&rwl->rwl_lock_obj, 0, file, line);
}

void
_rw_exit_write(struct rwlock *rwl LOCK_FL_VARS)
{
	unsigned long owner = rwl->rwl_owner;

	rw_assert_wrlock(rwl);

	membar_exit_before_atomic();
	if (__predict_false((owner & RWLOCK_WAIT) ||
	    rw_cas(&rwl->rwl_owner, owner, 0)))
		_rw_exit(rwl LOCK_FL_ARGS);
	else
		WITNESS_UNLOCK(&rwl->rwl_lock_obj, LOP_EXCLUSIVE, file, line);
}

#ifdef DIAGNOSTIC
/*
 * Put the diagnostic functions here to keep the main code free
 * from ifdef clutter.
 */
static void
rw_enter_diag(struct rwlock *rwl, int flags)
{
	switch (flags & RW_OPMASK) {
	case RW_WRITE:
	case RW_READ:
		if (RW_PROC(curproc) == RW_PROC(rwl->rwl_owner))
			panic("rw_enter: %s locking against myself",
			    rwl->rwl_name);
		break;
	case RW_DOWNGRADE:
		/*
		 * If we're downgrading, we must hold the write lock.
		 */
		if ((rwl->rwl_owner & RWLOCK_WRLOCK) == 0)
			panic("rw_enter: %s downgrade of non-write lock",
			    rwl->rwl_name);
		if (RW_PROC(curproc) != RW_PROC(rwl->rwl_owner))
			panic("rw_enter: %s downgrade, not holder",
			    rwl->rwl_name);
		break;

	default:
		panic("rw_enter: unknown op 0x%x", flags);
	}
}

#else
#define rw_enter_diag(r, f)
#endif

static void
_rw_init_flags_witness(struct rwlock *rwl, const char *name, int lo_flags,
    const struct lock_type *type)
{
	rwl->rwl_owner = 0;
	rwl->rwl_name = name;

#ifdef WITNESS
	rwl->rwl_lock_obj.lo_flags = lo_flags;
	rwl->rwl_lock_obj.lo_name = name;
	rwl->rwl_lock_obj.lo_type = type;
	WITNESS_INIT(&rwl->rwl_lock_obj, type);
#else
	(void)type;
	(void)lo_flags;
#endif
}

void
_rw_init_flags(struct rwlock *rwl, const char *name, int flags,
    const struct lock_type *type)
{
	_rw_init_flags_witness(rwl, name, RWLOCK_LO_FLAGS(flags), type);
}

#ifdef DEBUG_LOCK
#define	DPRINT_FLAGS(_f_)	\
	((_f_) & RW_DOWNGRADE) ? "DOWN" : ".",	\
	((_f_) & RW_READ) ? "READ" : ".",	\
	((_f_) & RW_WRITE) ? "WRITE" : "."

#define	DPRINT_LOCK(_rwl_, _f_)		do {		\
		if ((_rwl_)->rwl_owner & RWLOCK_WRLOCK) {	\
			printf("[%s:%s] Owner: 0x%lX, %s %s %s, asking: %s %s %s\n",\
			    __func__,						\
			    (_rwl_)->rwl_name,						\
			    RW_PROC((_rwl_)->rwl_owner),			\
			    ((_rwl_)->rwl_owner & RWLOCK_WRWANT) ? "WRWANT" : ".",	\
			    ((_rwl_)->rwl_owner & RWLOCK_WRLOCK) ? "WRITER" : ".",	\
			    ((_rwl_)->rwl_owner & RWLOCK_WAIT) ? "WAITERS" : ".",	\
			    PRINT_FLAGS(_f_));	\
		} else {				\
			printf("[%s:%s] Readers: 0x%lX, %s %s %s, asking: %s %s %s\n",	\
			    __func__,							\
			    (_rwl_)->rwl_name,						\
			    RW_PROC((_rwl_)->rwl_owner),				\
			    ((_rwl_)->rwl_owner & RWLOCK_WRWANT) ? "WRWANT" : ".",	\
			    ((_rwl_)->rwl_owner & RWLOCK_WRLOCK) ? "!!WRITER!!" : ".",	\
			    ((_rwl_)->rwl_owner & RWLOCK_WAIT) ? "WAITERS" : ".",	\
			    PRINT_FLAGS(_f_));	\
		}	\
	} while (0)
#define DPRINTF(x...)	do { printf(x); } while (0)
#else
#define DPRINT_FLAGS(_f_)	(void)(0)
#define	DPRINT_LOCK(_rwl_, _f_)	(void)(0)
#define	DPRINTF(x...)		(void)(0)
#endif


#ifdef WITH_TURNSTILES
int
_rw_enter(struct rwlock *rwl, int flags LOCK_FL_VARS)
{
	unsigned long o, rwl_incr;
	unsigned int queue, rwl_setwait, rwl_needwait;
	struct turnstile *ts;
	struct mcs_lock	mcs;
	int e;
#ifdef WITNESS
	int lop_flags;

	lop_flags = LOP_NEWORDER;
	if (flags & RW_WRITE)
		lop_flags |= LOP_EXCLUSIVE;
	if (flags & RW_DUPOK)
		lop_flags |= LOP_DUPOK;
	if ((flags & RW_NOSLEEP) == 0 && (flags & RW_DOWNGRADE) == 0)
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj, lop_flags, file, line,
		    NULL);
#endif

	DPRINT_LOCK(rwl, flags);
	if (flags & RW_READ) {
		rwl_incr = RWLOCK_READ_INCR;
		rwl_setwait = RWLOCK_WAIT;
		rwl_needwait = RWLOCK_WRLOCK|RWLOCK_WRWANT;
		queue = (flags & RW_INTR) ? TS_IREADER_Q : TS_READER_Q;
	} else if (flags & RW_WRITE) {
		rwl_incr = RW_PROC(curproc) | RWLOCK_WRLOCK;
		rwl_setwait = RWLOCK_WAIT | RWLOCK_WRWANT;
		rwl_needwait = RWLOCK_WRLOCK;
		queue = (flags & RW_INTR) ? TS_IWRITER_Q : TS_WRITER_Q; 
	} else
		panic("%s: invalid rw-flags: 0x%x", __func__, flags);

	flags &= ~RW_INTR;

	do {
		rw_enter_diag(rwl, flags);

		o = rwl->rwl_owner;
		if (((o & rwl_needwait) == 0) &&
		    (!rw_cas(&rwl->rwl_owner, o,
			o + (rwl_incr & ~RWLOCK_WRWANT)))) {
			/*
			 * We could acquire a lock almost for free for
			 * one of the reasons below:
			 *	- lock was empty
			 *	- we were yet another reader to grab
			 *	  the lock with no writers waiting.
			 */
			membar_enter();
			break;
		}

		if (panicstr || db_active)
			return (0);

		if (flags & RW_NOSLEEP)
			return (EBUSY);

		/*
		 * Keep in mind turnstile_lookup() may busy wait on bucket,
		 * hence we must reload owner as soon as it comes back.
		 * Also remember the turnstile is blocked, we have to
		 * eihter sleep or perform turnstile_exit(), before bailing
		 * out.
		 */
		ts = turnstile_lookup(rwl, &mcs);
		o = rwl->rwl_owner;

		if (((o & rwl_needwait) == 0) &&
		    (rw_cas(&rwl->rwl_owner, o, o | rwl_setwait))) {
			/*
			 * We've lost the race with other thread competing for
			 * the same lock. We must restart lock acquisition
			 * process. We also must unlock the turnstile's lock
			 */
			mcs_lock_leave(&mcs);
			continue;
		}

		e = turnstile_block(ts, queue, rwl, &mcs);

		if (e != 0)
			return (e);

		/*
		 * We came back after sleeping on turnstile. Let's see
		 * if we could acquire a lock. Remember we could loose
		 * race with another writer.
		 */
		if ((flags == RW_READ) ||
		    (RWLOCK_OWNER(rwl) == (struct proc *)RW_PROC(curproc)))
			break;
	} while (1);

	if (flags & RW_DOWNGRADE)
		WITNESS_DOWNGRADE(&rwl->rwl_lock_obj, lop_flags, file, line);
	else
		WITNESS_LOCK(&rwl->rwl_lock_obj, lop_flags, file, line);

	return (0);

}

void
_rw_exit(struct rwlock *rwl LOCK_FL_VARS)
{
	struct mcs_lock	mcs;
	unsigned long o, decr, newo;
	struct turnstile *ts;
	int rcnt, wcnt;

	o = rwl->rwl_owner;
	if ((o & RWLOCK_WRLOCK) != 0) {
		decr = RW_PROC(o) | RWLOCK_WRLOCK;
		KASSERT(decr == ((unsigned long)curproc | RWLOCK_WRLOCK));
	} else {
		decr = RWLOCK_READ_INCR;
		KASSERT((o >> RWLOCK_READER_SHIFT) != 0);
	}

	DPRINT_LOCK(rwl, 0);

	/*
	 * If there are no waiters on the lock, then we may get away with
	 * rw_cas(), because we are the only thread, which currently owns the
	 * lock.
	 */
	WITNESS_UNLOCK(&rwl->rwl_lock_obj,
	    (o & RWLOCK_WRLOCK) ? LOP_EXCLUSIVE : 0, file, line);

	membar_exit_before_atomic();
	for (;;) {
		newo = (o - decr);
		if ((newo & (~RWLOCK_MASK | RWLOCK_WAIT)) == RWLOCK_WAIT)
			break;
		newo = atomic_cas_ulong(&rwl->rwl_owner, o, newo);
		if (newo == o) {
			membar_sync();
			DPRINTF("[%s] taking exit ", __func__);
			DPRINT_LOCK(rwl, 0);
			return;
		}
		o = newo;
	}

	ts = turnstile_lookup(rwl, &mcs);
	rcnt = turnstile_readers(ts);
	wcnt = turnstile_writers(ts);
	o = rwl->rwl_owner;

	if (decr == RWLOCK_READ_INCR) {
		/*
		 * Remember the turnstile got removed from ts chain, by
		 * thread/process, which has woken us up.
		 * 
		 */
		if (rcnt == 0) {
			/*
			 * If we are the last reader leaving the lock, then we
			 * must wake up writers. The idea is to wake all
			 * writers and let them compete for a lock. There will
			 * be one winner, which will proceed.
			 */
			atomic_swap_ulong(&rwl->rwl_owner, RWLOCK_WRWANT);
			turnstile_wakeup(ts, TS_WRITER_Q, wcnt, &mcs);
		} else {
			/*
			 * There are readers waiting for the lock. So to ensure
			 * a fairness, we wake up just one writer here.
			 */
			newo = RW_PROC(turnstile_first(ts, TS_WRITER_Q));
			newo |= RWLOCK_WAIT | RWLOCK_WRWANT;
			newo |= (wcnt > 1) ? RWLOCK_WRWANT : 0;
			atomic_swap_ulong(&rwl->rwl_owner, newo);
			turnstile_wakeup(ts, TS_WRITER_Q, 1, &mcs);
		}
	} else {
		/*
		 * let all readers run.
		 */
		newo = rcnt << RWLOCK_READER_SHIFT;
		newo |= (wcnt != 0) ? RWLOCK_WRWANT|RWLOCK_WAIT : 0;
		atomic_swap_ulong(&rwl->rwl_owner, newo);
		turnstile_wakeup(ts, TS_READER_Q, rcnt, &mcs);
	}
}

#else	/* !WITH_TURNSTILE */
int
_rw_enter(struct rwlock *rwl, int flags LOCK_FL_VARS)
{
	const struct rwlock_op *op;
	struct sleep_state sls;
	unsigned long inc, o;
	int error;
#ifdef WITNESS
	int lop_flags;

	lop_flags = LOP_NEWORDER;
	if (flags & RW_WRITE)
		lop_flags |= LOP_EXCLUSIVE;
	if (flags & RW_DUPOK)
		lop_flags |= LOP_DUPOK;
	if ((flags & RW_NOSLEEP) == 0 && (flags & RW_DOWNGRADE) == 0)
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj, lop_flags, file, line,
		    NULL);
#endif

	op = &rw_ops[(flags & RW_OPMASK) - 1];

	inc = op->inc + RW_PROC(curproc) * op->proc_mult;
retry:
	while (__predict_false(((o = rwl->rwl_owner) & op->check) != 0)) {
		unsigned long set = o | op->wait_set;
		int do_sleep;

		/* Avoid deadlocks after panic or in DDB */
		if (panicstr || db_active)
			return (0);

		rw_enter_diag(rwl, flags);

		if (flags & RW_NOSLEEP)
			return (EBUSY);

		sleep_setup(&sls, rwl, op->wait_prio, rwl->rwl_name);
		if (flags & RW_INTR)
			sleep_setup_signal(&sls, op->wait_prio | PCATCH);

		do_sleep = !rw_cas(&rwl->rwl_owner, o, set);

		sleep_finish(&sls, do_sleep);
		if ((flags & RW_INTR) &&
		    (error = sleep_finish_signal(&sls)) != 0)
			return (error);
		if (flags & RW_SLEEPFAIL)
			return (EAGAIN);
	}

	if (__predict_false(rw_cas(&rwl->rwl_owner, o, o + inc)))
		goto retry;
	membar_enter_after_atomic();

	/*
	 * If old lock had RWLOCK_WAIT and RWLOCK_WRLOCK set, it means we
	 * downgraded a write lock and had possible read waiter, wake them
	 * to let them retry the lock.
	 */
	if (__predict_false((o & (RWLOCK_WRLOCK|RWLOCK_WAIT)) ==
	    (RWLOCK_WRLOCK|RWLOCK_WAIT)))
		wakeup(rwl);

	if (flags & RW_DOWNGRADE)
		WITNESS_DOWNGRADE(&rwl->rwl_lock_obj, lop_flags, file, line);
	else
		WITNESS_LOCK(&rwl->rwl_lock_obj, lop_flags, file, line);

	return (0);
}

void
_rw_exit(struct rwlock *rwl LOCK_FL_VARS)
{
	unsigned long owner = rwl->rwl_owner;
	int wrlock = owner & RWLOCK_WRLOCK;
	unsigned long set;

	/* Avoid deadlocks after panic or in DDB */
	if (panicstr || db_active)
		return;

	if (wrlock)
		rw_assert_wrlock(rwl);
	else
		rw_assert_rdlock(rwl);

	WITNESS_UNLOCK(&rwl->rwl_lock_obj, wrlock ? LOP_EXCLUSIVE : 0,
	    file, line);

	membar_exit_before_atomic();
	do {
		owner = rwl->rwl_owner;
		if (wrlock)
			set = 0;
		else
			set = (owner - RWLOCK_READ_INCR) &
				~(RWLOCK_WAIT|RWLOCK_WRWANT);
	} while (rw_cas(&rwl->rwl_owner, owner, set));

	if (owner & RWLOCK_WAIT)
		wakeup(rwl);
}
#endif	/* WITH_TURNSTILE */

int
rw_status(struct rwlock *rwl)
{
	unsigned long owner = rwl->rwl_owner;

	if (owner & RWLOCK_WRLOCK) {
		if (RW_PROC(curproc) == RW_PROC(owner))
			return RW_WRITE;
		else
			return RW_WRITE_OTHER;
	}
	if (owner)
		return RW_READ;
	return (0);
}

#ifdef DIAGNOSTIC
void
rw_assert_wrlock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

	if (!(rwl->rwl_owner & RWLOCK_WRLOCK))
		panic("%s@%p: lock not held (%lX)", rwl->rwl_name, rwl,
		    rwl->rwl_owner);

	if (RWLOCK_OWNER(rwl) != (struct proc *)RW_PROC(curproc))
		panic("%s@%p: lock not held by this process (%lX vs. %p)",
		    rwl->rwl_name,
		    rwl,
		    RW_PROC(rwl->rwl_owner), curproc);
}

void
rw_assert_rdlock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

	if (!RWLOCK_OWNER(rwl) || (rwl->rwl_owner & RWLOCK_WRLOCK))
		panic("%s@%p: lock not shared (%lX)", rwl->rwl_name, rwl,
		    rwl->rwl_owner);
}

void
rw_assert_anylock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

	switch (rw_status(rwl)) {
	case RW_WRITE_OTHER:
		panic("%s@%p: lock held by different process (%lX vs. %p)",
		    rwl->rwl_name, rwl, rwl->rwl_owner, curproc);
	case 0:
		panic("%s@%p: lock not held", rwl->rwl_name, rwl);
	}
}

void
rw_assert_unlocked(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

	if (rwl->rwl_owner != 0L)
		panic("%s@%p: lock held (%lX)", rwl->rwl_name, rwl,
		    rwl->rwl_owner);
}
#endif

/* recursive rwlocks; */
void
_rrw_init_flags(struct rrwlock *rrwl, char *name, int flags,
    const struct lock_type *type)
{
	memset(rrwl, 0, sizeof(struct rrwlock));
	_rw_init_flags_witness(&rrwl->rrwl_lock, name, RRWLOCK_LO_FLAGS(flags),
	    type);
}

int
_rrw_enter(struct rrwlock *rrwl, int flags LOCK_FL_VARS)
{
	int	rv;

	if (RWLOCK_OWNER(&rrwl->rrwl_lock) ==
	    (struct proc *)RW_PROC(curproc)) {
		if (flags & RW_RECURSEFAIL)
			return (EDEADLK);
		else {
			rrwl->rrwl_wcnt++;
			WITNESS_LOCK(&rrwl->rrwl_lock.rwl_lock_obj,
			    LOP_EXCLUSIVE, file, line);
			return (0);
		}
	}

	rv = _rw_enter(&rrwl->rrwl_lock, flags LOCK_FL_ARGS);
	if (rv == 0)
		rrwl->rrwl_wcnt = 1;

	return (rv);
}

void
_rrw_exit(struct rrwlock *rrwl LOCK_FL_VARS)
{

	if (RWLOCK_OWNER(&rrwl->rrwl_lock) ==
	    (struct proc *)RW_PROC(curproc)) {
		KASSERT(rrwl->rrwl_wcnt > 0);
		rrwl->rrwl_wcnt--;
		if (rrwl->rrwl_wcnt != 0) {
			WITNESS_UNLOCK(&rrwl->rrwl_lock.rwl_lock_obj,
			    LOP_EXCLUSIVE, file, line);
			return;
		}
	}

	_rw_exit(&rrwl->rrwl_lock LOCK_FL_ARGS);
}

int
rrw_status(struct rrwlock *rrwl)
{
	return (rw_status(&rrwl->rrwl_lock));
}
