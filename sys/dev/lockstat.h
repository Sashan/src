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

#ifndef LOCKSTAT_H
#define LOCKSTAT_H

#include <sys/stdint.h>
#include <sys/time.h>

/*
 * Stopwatch structure to collect lockstat statics.
 */
struct lockstat_swatch {
	int		sw_lockstat_runs;
	struct timeval	sw_start_tv;
	struct timeval	sw_stop_tv;
	struct timeval	sw_acc_tv;
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
void lockstat_set_swatch(struct lockstat_swatch *, struct timeval *);
void lockstat_start_swatch(struct lockstat_swatch *);
void lockstat_stop_swatch(struct lockstat_swatch *);
void lockstat_stopstart_swatch(struct lockstat_swatch *);
void lockstat_event(uintptr_t, uintptr_t, int, struct lockstat_swatch *);

#endif
