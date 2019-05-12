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

#ifdef WITH_LOCKSTAT

#include <dev/lockstat.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/types.h>

void
lockstatattach(int num)
{
	log(LOG_ERR, "%s: Hello\n", __func__);
}

int
lockstatopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	if (minor(dev) >= 1)
		return (ENXIO);

	return (0);
}

int
lockstatclose(dev_t dev, int flags, int fmt, struct proc *p)
{
	if (minor(dev) >= 1)
		return (ENXIO);

	return (0);
}

int
lockstatioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
	return (ENODEV);
}

void
lockstat_reset_swatch(struct lockstat_swatch *sw)
{
	/*
	 * XXX enable data collection with running lockstat consumer
	 */
	sw->sw_lockstat_runs = 0;
	sw->sw_count = 0;
	sw->sw_start_tv.tv_sec = 0;
	sw->sw_start_tv.tv_usec = 0;
	sw->sw_stop_tv.tv_sec = 0;
	sw->sw_stop_tv.tv_usec = 0;
}

void
lockstat_set_swatch(struct lockstat_swatch *sw, struct timeval *start_tv)
{
	if (sw->sw_lockstat_runs == 0)
		return;

	sw->sw_start_tv.tv_sec = start_tv->tv_sec;
	sw->sw_start_tv.tv_usec = start_tv->tv_usec;
}

void
lockstat_start_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_runs == 0)
		return;

	microuptime(&sw->sw_start_tv);
}

void
lockstat_stop_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_runs == 0)
		return;

	microuptime(&sw->sw_stop_tv);
	timersub(&sw->sw_stop_tv, &sw->sw_start_tv, &sw->sw_start_tv);
	timeradd(&sw->sw_acc_tv, &sw->sw_start_tv, &sw->sw_acc_tv);
	sw->sw_count++;
}

void
lockstat_stopstart_swatch(struct lockstat_swatch *sw)
{
	if (sw->sw_lockstat_runs == 0)
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
	if (sw->sw_lockstat_runs == 0)
		return;
}

#endif
