/*	$OpenBSD$ */

/*
 * Copyright (c) 2019 sashan@openbsd.org
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

#include <dev/lockstat.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <machine/cpu.h>
#include <sys/time.h>

#if LONG_BIT == 64
#define	LOCKSTAT_HASH_SHIFT	3
#elif LONG_BIT == 32
#define	LOCKSTAT_HASH_SHIFT	2
#endif

#define	LOCKSTAT_MINBUFS	1000
#define	LOCKSTAT_DEFBUFS	10000
#define	LOCKSTAT_MAXBUFS	1000000

#define	LOCKSTAT_HASH_SIZE	128
#define	LOCKSTAT_HASH_MASK	(LOCKSTAT_HASH_SIZE - 1)
#define	LOCKSTAT_HASH(key)	\
	((key >> LOCKSTAT_HASH_SHIFT) & LOCKSTAT_HASH_MASK)

#define LOCKSTAT_ENABLED_UPDATE() do { \
	lockstat_enabled = lockstat_dev_enabled; \
	membar_producer(); \
    } while (0)

struct proc *lockstat_p;
int lockstat_dev_enabled;
int lockstat_enabled;

SLIST_HEAD(slsbuf, lsbuf);
LIST_HEAD(llsbuf, lsbuf);

struct lscpu {
	struct slsbuf		lc_free;
/*
	SLIST_HEAD(, lsbuf)	lc_free;
*/
	u_int			lc_overflow;
	struct llsbuf		lc_hash[LOCKSTAT_HASH_SIZE];
/*
	LIST_HEAD(, lsbuf) lc_hash[LOCKSTAT_HASH_SIZE];
*/
};

struct lsbuf	*lockstat_baseb;
size_t		lockstat_sizeb;
uintptr_t	lockstat_csstart;
uintptr_t	lockstat_csend;
uintptr_t	lockstat_csmask;
uintptr_t	lockstat_lamask;
uintptr_t	lockstat_lockstart;
uintptr_t	lockstat_lockend;

struct timespec	lockstat_stime;

int lockstat_alloc(struct lsenable *le);
void lockstat_free(void);

/*
 * Allocate buffers for lockstat_start().
 */
int
lockstat_alloc(struct lsenable *le)
{
	struct lsbuf *lb;
	size_t sz;

	KASSERT(!lockstat_dev_enabled);
	lockstat_free();

	sz = sizeof(*lb) * le->le_nbufs;

	lb = malloc(sz, M_TEMP, M_WAITOK);

	/* coverity[assert_side_effect] */
	KASSERT(!lockstat_dev_enabled);
	KASSERT(lockstat_baseb == NULL);
	lockstat_sizeb = sz;
	lockstat_baseb = lb;
		
	return (0);
}

/*
 * Free allocated buffers after tracing has stopped.
 */
void
lockstat_free(void)
{

	KASSERT(!lockstat_dev_enabled);

	if (lockstat_baseb != NULL) {
		free(lockstat_baseb, M_TEMP, lockstat_sizeb);
		lockstat_baseb = NULL;
	}
}

/*
 * Prepare the per-CPU tables for use, or clear down tables when tracing is
 * stopped.
 */
void
lockstat_init_tables(struct lsenable *le)
{
	int i, per, slop, cpuno;
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	struct lscpu *lc;
	struct lsbuf *lb;

	/* coverity[assert_side_effect] */
	KASSERT(!lockstat_dev_enabled);

	CPU_INFO_FOREACH(cii, ci) {
		if (ci->ci_lockstat != NULL) {
			free(ci->ci_lockstat, M_TEMP, sizeof(struct lscpu));
			ci->ci_lockstat = NULL;
		}
	}

	if (le == NULL)
		return;

	lb = lockstat_baseb;
	per = le->le_nbufs / ncpus;
	slop = le->le_nbufs - (per * ncpus);
	cpuno = 0;
	CPU_INFO_FOREACH(cii, ci) {
		lc = malloc(sizeof(*lc), M_TEMP, M_WAITOK);
		lc->lc_overflow = 0;
		ci->ci_lockstat = lc;

		SLIST_INIT(&lc->lc_free);
		for (i = 0; i < LOCKSTAT_HASH_SIZE; i++)
			LIST_INIT(&lc->lc_hash[i]);

		for (i = per; i != 0; i--, lb++) {
			lb->lb_cpu = (uint16_t)cpuno;
			SLIST_INSERT_HEAD(&lc->lc_free, lb, lb_chain.slist);
		}
		if (--slop > 0) {
			lb->lb_cpu = (uint16_t)cpuno;
			SLIST_INSERT_HEAD(&lc->lc_free, lb, lb_chain.slist);
			lb++;
		}
		cpuno++;
	}
}

/*
 * Start collecting lock statistics.
 */
void
lockstat_start(struct lsenable *le)
{

	/* coverity[assert_side_effect] */
	KASSERT(!lockstat_dev_enabled);

	lockstat_init_tables(le);

	if ((le->le_flags & LE_CALLSITE) != 0)
		lockstat_csmask = (uintptr_t)-1LL;
	else
		lockstat_csmask = 0;

	if ((le->le_flags & LE_LOCK) != 0)
		lockstat_lamask = (uintptr_t)-1LL;
	else
		lockstat_lamask = 0;

	lockstat_csstart = le->le_csstart;
	lockstat_csend = le->le_csend;
	lockstat_lockstart = le->le_lockstart;
	lockstat_lockstart = le->le_lockstart;
	lockstat_lockend = le->le_lockend;
	membar_sync();
	getnanotime(&lockstat_stime);
	lockstat_dev_enabled = le->le_mask;
	LOCKSTAT_ENABLED_UPDATE();
}

void
lockstatattach(int num)
{
}

int
lockstatopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	if (minor(dev) >= 1)
		return (ENXIO);

	KERNEL_ASSERT_LOCKED();

	if (lockstat_p != NULL)
		return (EBUSY);

	lockstat_p = p;

	return (0);
}

int
lockstatclose(dev_t dev, int flags, int fmt, struct proc *p)
{
	if (minor(dev) >= 1)
		return (ENXIO);

	KERNEL_ASSERT_LOCKED();

	if (lockstat_p != p)
		return (ENXIO);

	lockstat_p = NULL;

	return (0);
}

/*
 * Stop collecting lock statistics.
 */
int
lockstat_stop(struct lsdisable *ld)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	u_int cpuno, overflow;
	struct timespec ts;
	int error;

	/* coverity[assert_side_effect] */
	KASSERT(lockstat_dev_enabled);

	/*
	 * Set enabled false, force a write barrier, and wait for other CPUs
	 * to exit lockstat_event().
	 */
	lockstat_dev_enabled = 0;
	LOCKSTAT_ENABLED_UPDATE();
	getnanotime(&ts);
	tsleep(&lockstat_stop, PPAUSE, "lockstat", 10);

	/*
	 * Did we run out of buffers while tracing?
	 */
	overflow = 0;
	CPU_INFO_FOREACH(cii, ci)
		overflow += ((struct lscpu *)ci->ci_lockstat)->lc_overflow;

	if (overflow != 0) {
		error = EOVERFLOW;
		log(LOG_NOTICE, "lockstat: %d buffer allocations failed\n",
		    overflow);
	} else
		error = 0;

	lockstat_init_tables(NULL);

	/* Run through all LWPs and clear the slate for the next run. */
	KERNEL_ASSERT_LOCKED();
#if 0
	/*
	 * clean per-process counters here.
	 */
	LIST_FOREACH(p, &alllwp, l_list) {
		p->p_pfailaddr = 0;
		p->p_pfailtime = 0;
		p->p_pfaillock = 0;
	}
#endif

	/*
	 * Fill out the disable struct for the caller.
	 */
	timespecsub(&ts, &lockstat_stime, &ld->ld_time);
	ld->ld_size = lockstat_sizeb;

	cpuno = 0;
	CPU_INFO_FOREACH(cii, ci) {
		if (cpuno >= sizeof(ld->ld_freq) / sizeof(ld->ld_freq[0])) {
			log(LOG_WARNING, "lockstat: too many CPUs\n");
			break;
		}
		ld->ld_freq[cpuno++] = 1000;
#if 0
		ld->ld_freq[cpuno++] = cpu_frequency(ci);
#endif
	}

	return (error);
}

int
lockstatioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
	int	error;
	struct lsenable le_buf;
	struct lsenable *le = &le_buf;
	struct lsdisable ld_buf;

	KERNEL_ASSERT_LOCKED();

	if (lockstat_p != p)
		return (EBUSY);

	switch (cmd) {
	case IOC_LOCKSTAT_GVERSION:
		*(int *)addr = LS_VERSION;
		error = 0;
		break;

	case IOC_LOCKSTAT_ENABLE:
		memmove(le, addr, sizeof(struct lsenable));

		if (lockstat_dev_enabled) {
			error = EBUSY;
			break;
		}

		/*
		 * Sanitize the arguments passed in and set up filtering.
		 */
		if (le->le_nbufs == 0)
			le->le_nbufs = LOCKSTAT_DEFBUFS;
		else if (le->le_nbufs > LOCKSTAT_MAXBUFS ||
		    le->le_nbufs < LOCKSTAT_MINBUFS) {
			error = EINVAL;
			break;
		}
		if ((le->le_flags & LE_ONE_CALLSITE) == 0) {
			le->le_csstart = 0;
			le->le_csend = le->le_csstart - 1;
		}
		if ((le->le_flags & LE_ONE_LOCK) == 0) {
			le->le_lockstart = 0;
			le->le_lockend = le->le_lockstart - 1;
		}
		if ((le->le_mask & LB_EVENT_MASK) == 0)
			return (EINVAL);
		if ((le->le_mask & LB_LOCK_MASK) == 0)
			return (EINVAL);

		/*
		 * Start tracing.
		 */
		if ((error = lockstat_alloc(le)) == 0)
			lockstat_start(le);
		break;

	case IOC_LOCKSTAT_DISABLE:
		if (!lockstat_dev_enabled)
			error = EINVAL;
		else {
			memset(&ld_buf, 0, sizeof(struct lsdisable));
			error = lockstat_stop(&ld_buf);
			if (error)
				break;

			memmove(addr, &ld_buf, sizeof(struct lsdisable));
		}
		break;


	default:
		error = ENOTSUP;
	}

	return (error);
}

int
lockstatread(dev_t dev, struct uio *uio, int flag)
{

	if (curproc != lockstat_p || lockstat_dev_enabled)
		return (EBUSY);
	return (uiomove(lockstat_baseb, lockstat_sizeb, uio));
}

/*
 * OpenBSD specific part.
 */
void
lockstat_reset_swatch(struct lockstat_swatch *sw)
{
	/*
	 * XXX enable data collection with running lockstat consumer
	 */
	sw->sw_lockstat_flags = 0;
	sw->sw_count = 0;
	sw->sw_start_tv.tv_sec = 0;
	sw->sw_start_tv.tv_usec = 0;
	sw->sw_stop_tv.tv_sec = 0;
	sw->sw_stop_tv.tv_usec = 0;
}

void
lockstat_set_swatch(struct lockstat_swatch *sw, struct timeval *start_tv)
{
	if (sw->sw_lockstat_flags == 0)
		return;

	sw->sw_start_tv.tv_sec = start_tv->tv_sec;
	sw->sw_start_tv.tv_usec = start_tv->tv_usec;
}

void
lockstat_start_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_flags == 0)
		return;

	microuptime(&sw->sw_start_tv);
}

void
lockstat_stop_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_flags == 0)
		return;

	microuptime(&sw->sw_stop_tv);
	timersub(&sw->sw_stop_tv, &sw->sw_start_tv, &sw->sw_start_tv);
	timeradd(&sw->sw_acc_tv, &sw->sw_start_tv, &sw->sw_acc_tv);
	sw->sw_count++;
}

void
lockstat_stopstart_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_flags == 0)
		return;

	microuptime(&sw->sw_stop_tv);
	timersub(&sw->sw_stop_tv, &sw->sw_start_tv, &sw->sw_start_tv);
	timeradd(&sw->sw_acc_tv, &sw->sw_start_tv, &sw->sw_acc_tv);
	sw->sw_start_tv = sw->sw_stop_tv;
	sw->sw_count++;
}

void
lockstat_event(uintptr_t rwl, uintptr_t caller, int lf,
    struct lockstat_swatch *sw)
{
	struct llsbuf *ll;
	struct lscpu *lc;
	struct lsbuf *lb;
	u_int event;
	int s, flags;

	flags = sw->sw_lockstat_flags;
	if (((flags & lockstat_dev_enabled) != flags) || (sw->sw_count == 0))
		return;

	if ((rwl < lockstat_lockstart) || (rwl > lockstat_lockend))
		return;

	if ((caller < lockstat_csstart) || (caller > lockstat_lockend))
		return;
	
	caller &= lockstat_csmask;
	rwl &= lockstat_lamask;

	/*
	 * Find the table for this lock+caller pair, and try to locate a
	 * buffer with the same key.
	 */
	s = splhigh();
	lc = curcpu()->ci_lockstat;
	ll = &lc->lc_hash[LOCKSTAT_HASH(rwl ^ caller)];
	event = (lf & LB_EVENT_MASK) - 1;

	LIST_FOREACH(lb, ll, lb_chain.list) {
		if (lb->lb_lock == rwl && lb->lb_callsite == caller)
			break;
	}

	if (lb != NULL) {
		/*
		 * We found a record.  Move it to the front of the list, as
		 * we're likely to hit it again soon.
		 */
		if (lb != LIST_FIRST(ll)) {
			LIST_REMOVE(lb, lb_chain.list);
			LIST_INSERT_HEAD(ll, lb, lb_chain.list);
		}
		lb->lb_counts[event] += sw->sw_count;
		timeradd(&lb->lb_times[event], &sw->sw_acc_tv,
		    &lb->lb_times[event]);
	} else if ((lb = SLIST_FIRST(&lc->lc_free)) != NULL) {
		/*
		 * Pinch a new buffer and fill it out.
		 */
		SLIST_REMOVE_HEAD(&lc->lc_free, lb_chain.slist);
		LIST_INSERT_HEAD(ll, lb, lb_chain.list);
		lb->lb_flags = (uint16_t)flags;
		lb->lb_lock = rwl;
		lb->lb_callsite = caller;
		lb->lb_counts[event] = sw->sw_count;
		lb->lb_times[event] = sw->sw_acc_tv;
	} else {
		/*
		 * We didn't find a buffer and there were none free.
		 * lockstat_stop() will notice later on and report the
		 * error.
		 */
		 lc->lc_overflow++;
	}

	splx(s);
}
