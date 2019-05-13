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

/*
 * Part of the code comes from NetBSD, version 1.14.
 */

#ifndef LOCKSTAT_H
#define LOCKSTAT_H

#include <sys/stdint.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/ioccom.h>

/*
 * Interface version.  The interface is not designed to provide
 * compatibility across NetBSD releases.
 */

#define	IOC_LOCKSTAT_GVERSION	_IOR('L', 0, int)

#define	LS_VERSION	5

/*
 * Enable request.  We can limit tracing by the call site and by
 * the lock.  We also specify the number of event buffers to
 * allocate up front, and what kind of events to track.
 */

#define	IOC_LOCKSTAT_ENABLE	_IOW('L', 1, struct lsenable)

#define LE_CALLSITE	0x01		/* track call sites */
#define	LE_ONE_CALLSITE	0x02		/* specific call site */
#define	LE_ONE_LOCK	0x04		/* specific lock */
#define LE_LOCK		0x08		/* track locks */

struct lsenable {
	uintptr_t	le_csstart;	/* callsite start */
	uintptr_t	le_csend;	/* callsite end */
	uintptr_t	le_lockstart;	/* lock address start */
	uintptr_t	le_lockend;	/* lock address end */
	uintptr_t	le_nbufs;	/* buffers to allocate, 0 = default */
	u_int		le_flags;	/* request flags */
	u_int		le_mask;	/* event mask (LB_*) */
};

/*
 * Disable request.
 */

#define	IOC_LOCKSTAT_DISABLE	_IOR('L', 2, struct lsdisable)

struct lsdisable {
	size_t		ld_size;	/* buffer space allocated */
	struct timespec	ld_time;	/* time spent enabled */
	uint64_t	ld_freq[64];	/* counter HZ by CPU number */
};

/*
 * Event buffers returned from reading from the devices.
 */

/*
 * Event types, for lockstat_event().  Stored in lb_flags but should be
 * meaningless to the consumer, also provided with the enable request
 * in le_mask.
 */
#define	LB_SPIN			0x00000001
#define	LB_SLEEP1		0x00000002
#define	LB_SLEEP2		0x00000003
#define	LB_NEVENT		0x00000003
#define	LB_EVENT_MASK		0x000000ff

/*
 * Lock types, the only part of lb_flags that should be inspected.  Also
 * provided with the enable request in le_mask.
 */
#define	LB_ADAPTIVE_MUTEX	0x00000100
#define	LB_SPIN_MUTEX		0x00000200
#define	LB_RWLOCK		0x00000300
#define	LB_NOPREEMPT		0x00000400
#define	LB_KERNEL_LOCK		0x00000500
#define	LB_MISC			0x00000600
#define	LB_NLOCK		0x00000600
#define	LB_LOCK_MASK		0x0000ff00
#define	LB_LOCK_SHIFT		8

#define	LB_DTRACE		0x00010000

struct lsbuf {
	union {
		LIST_ENTRY(lsbuf) list;
		SLIST_ENTRY(lsbuf) slist;
		TAILQ_ENTRY(lsbuf) tailq;
	} lb_chain;
	uintptr_t	lb_lock;		/* lock address */
	uintptr_t	lb_callsite;		/* call site */
	struct timespec	lb_times[LB_NEVENT];	/* cumulative times */
	uint32_t	lb_counts[LB_NEVENT];	/* count of events */
	uint16_t	lb_flags;		/* lock type */
	uint16_t	lb_cpu;			/* CPU number */
};

#ifdef _KERNEL
/*
 * stuff below is OpenBSD specific.
 */

/*
 * Stopwatch structure to collect lockstat statics.
 */
struct lockstat_swatch {
	int		sw_lockstat_flags;
	struct timespec	sw_start_tv;
	struct timespec	sw_stop_tv;
	struct timespec	sw_acc_tv;
	unsigned int	sw_count;
};

enum {
	LOCKSTAT_RW,
	LOCKSTAT_RW_READ,
	LOCKSTAT_RW_WRITE,
	LOCKSTAT_SPIN,
	LOCKSTAT_MUTEX
};

void lockstat_reset_swatch(struct lockstat_swatch *);
void lockstat_set_swatch(struct lockstat_swatch *, struct timespec *);
void lockstat_start_swatch(struct lockstat_swatch *);
void lockstat_stop_swatch(struct lockstat_swatch *);
void lockstat_stopstart_swatch(struct lockstat_swatch *);
void lockstat_event(uintptr_t, uintptr_t, int, struct lockstat_swatch *);
#endif

#endif
