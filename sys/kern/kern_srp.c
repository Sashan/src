/*	$OpenBSD: kern_srp.c,v 1.12 2017/09/08 05:36:53 deraadt Exp $ */

/*
 * Copyright (c) 2014 Jonathan Matthew <jmatthew@openbsd.org>
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
#include <sys/timeout.h>
#include <sys/srp.h>
#include <sys/atomic.h>
#ifdef SRP_DEBUG
#include <machine/db_machdep.h>
#include <ddb/db_sym.h>
#include <sys/proc.h>
#endif

void	srp_v_gc_start(struct srp_gc *, struct srp *, void *);

void
srpl_rc_init(struct srpl_rc *rc,  void (*ref)(void *, void *),
    void (*unref)(void *, void *), void *cookie)
{
	rc->srpl_ref = ref;
	srp_gc_init(&rc->srpl_gc, unref, cookie);
}

void
srp_gc_init(struct srp_gc *srp_gc, void (*dtor)(void *, void *), void *cookie)
{
	srp_gc->srp_gc_dtor = dtor;
	srp_gc->srp_gc_cookie = cookie;
	refcnt_init(&srp_gc->srp_gc_refcnt);
}

void
srp_init(struct srp *srp)
{
	srp->ref = NULL;
}

void *
srp_swap_locked(struct srp *srp, void *nv)
{
	void *ov;

	/*
	 * this doesn't have to be as careful as the caller has already
	 * prevented concurrent updates, eg. by holding the kernel lock.
	 * can't be mixed with non-locked updates though.
	 */

	ov = srp->ref;
	srp->ref = nv;

	return (ov);
}

void
srp_update_locked(struct srp_gc *srp_gc, struct srp *srp, void *v)
{
	if (v != NULL)
		refcnt_take(&srp_gc->srp_gc_refcnt);

	v = srp_swap_locked(srp, v);

	if (v != NULL)
		srp_v_gc_start(srp_gc, srp, v);
}

void *
srp_get_locked(struct srp *srp)
{
	return (srp->ref);
}

void
srp_gc_finalize(struct srp_gc *srp_gc)
{
	refcnt_finalize(&srp_gc->srp_gc_refcnt, "srpfini");
}

#ifdef MULTIPROCESSOR
#include <machine/cpu.h>
#include <sys/pool.h>

struct srp_gc_ctx {
	struct srp_gc		*srp_gc;
	struct timeout		tick;
	struct srp_hazard	hzrd;
};

int	srp_v_referenced(struct srp *, void *);
void	srp_v_gc(void *);

struct pool srp_gc_ctx_pool;

void
srp_startup(void)
{
	pool_init(&srp_gc_ctx_pool, sizeof(struct srp_gc_ctx), 0,
	    IPL_SOFTCLOCK, PR_WAITOK, "srpgc", NULL);
}

int
srp_v_referenced(struct srp *srp, void *v)
{
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;
	u_int i;
	struct srp_hazard *hzrd;

	CPU_INFO_FOREACH(cii, ci) {
		for (i = 0; i < nitems(ci->ci_srp_hazards); i++) {
			hzrd = &ci->ci_srp_hazards[i];

			if (hzrd->sh_p != srp)
				continue;
			membar_consumer();
			if (hzrd->sh_v != v)
				continue;

			return (1);
		}
	}

	return (0);
}

void
srp_v_dtor(struct srp_gc *srp_gc, void *v)
{
	(*srp_gc->srp_gc_dtor)(srp_gc->srp_gc_cookie, v);

	refcnt_rele_wake(&srp_gc->srp_gc_refcnt);
}

void
srp_v_gc_start(struct srp_gc *srp_gc, struct srp *srp, void *v)
{
	struct srp_gc_ctx *ctx;

	if (!srp_v_referenced(srp, v)) {
		/* we win */
		srp_v_dtor(srp_gc, v);
		return;
	}

	/* in use, try later */

	ctx = pool_get(&srp_gc_ctx_pool, PR_WAITOK);
	ctx->srp_gc = srp_gc;
	ctx->hzrd.sh_p = srp;
	ctx->hzrd.sh_v = v;

	timeout_set(&ctx->tick, srp_v_gc, ctx);
	timeout_add(&ctx->tick, 1);
}

void
srp_v_gc(void *x)
{
	struct srp_gc_ctx *ctx = x;

	if (srp_v_referenced(ctx->hzrd.sh_p, ctx->hzrd.sh_v)) {
		/* oh well, try again later */
		timeout_add(&ctx->tick, 1);
		return;
	}

	srp_v_dtor(ctx->srp_gc, ctx->hzrd.sh_v);
	pool_put(&srp_gc_ctx_pool, ctx);
}

void *
srp_swap(struct srp *srp, void *v)
{
	return (atomic_swap_ptr(&srp->ref, v));
}

void
srp_update(struct srp_gc *srp_gc, struct srp *srp, void *v)
{
	if (v != NULL)
		refcnt_take(&srp_gc->srp_gc_refcnt);

	v = srp_swap(srp, v);
	if (v != NULL)
		srp_v_gc_start(srp_gc, srp, v);
}

static inline void *
srp_v(struct srp_hazard *hzrd, struct srp *srp)
{
	void *v;

	hzrd->sh_p = srp;

	/*
	 * ensure we update this cpu's hazard pointer to a value that's still
	 * current after the store finishes, otherwise the gc task may already
	 * be destroying it
	 */
	do {
		v = srp->ref;
		hzrd->sh_v = v;
		membar_consumer();
	} while (__predict_false(v != srp->ref));

#ifdef SRP_DEBUG
	hzrd->sh_stack[0] = __builtin_return_address(1);
	hzrd->sh_stack[1] = __builtin_return_address(2);
	hzrd->sh_stack[2] = __builtin_return_address(3);
	hzrd->sh_stack[3] = __builtin_return_address(4);
	hzrd->sh_stack[4] = __builtin_return_address(5);
	hzrd->sh_stack[5] = __builtin_return_address(6);
	hzrd->sh_stack[6] = __builtin_return_address(7);
	hzrd->sh_stack[7] = __builtin_return_address(8);
	hzrd->sh_stack[8] = __builtin_return_address(9);
	hzrd->sh_stack[9] = __builtin_return_address(10);
#if 0
	hzrd->sh_stack[10] = __builtin_return_address(11);
	hzrd->sh_stack[11] = __builtin_return_address(12);
	hzrd->sh_stack[12] = __builtin_return_address(13);
#endif
	hzrd->sh_proc = curproc->p_p;
#endif
	return (v);
}

void *
srp_enter(struct srp_ref *sr, struct srp *srp)
{
	struct cpu_info *ci = curcpu();
	struct srp_hazard *hzrd;
	u_int i;

	for (i = 0; i < nitems(ci->ci_srp_hazards); i++) {
		hzrd = &ci->ci_srp_hazards[i];
		if (hzrd->sh_p == NULL) {
			sr->hz = hzrd;
			return (srp_v(hzrd, srp));
		}
	}

	panic("%s: not enough srp hazard records", __func__);

	/* NOTREACHED */
	return (NULL);
}

void *
srp_follow(struct srp_ref *sr, struct srp *srp)
{
	return (srp_v(sr->hz, srp));
}

void
srp_leave(struct srp_ref *sr)
{
#ifdef SRP_DEBUG
	memset(sr->hz->sh_stack, 0, sizeof (uintptr_t) * SRP_STACKTRACE);
	sr->hz->sh_proc = NULL;
#endif
	sr->hz->sh_p = NULL;
}

static inline int
srp_referenced(void *v)
{
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;
	u_int i;
	struct srp_hazard *hzrd;

	CPU_INFO_FOREACH(cii, ci) {
		for (i = 0; i < nitems(ci->ci_srp_hazards); i++) {
			hzrd = &ci->ci_srp_hazards[i];

			if (hzrd->sh_p != NULL && hzrd->sh_v == v)
				return (1);
		}
	}

	return (0);
}

void
srp_finalize(void *v, const char *wmesg)
{
	while (srp_referenced(v))
		tsleep(v, PWAIT, wmesg, 1);
}

#else /* MULTIPROCESSOR */

void
srp_startup(void)
{

}

void
srp_v_gc_start(struct srp_gc *srp_gc, struct srp *srp, void *v)
{
	(*srp_gc->srp_gc_dtor)(srp_gc->srp_gc_cookie, v);
	refcnt_rele_wake(&srp_gc->srp_gc_refcnt);
}

#endif /* MULTIPROCESSOR */

#ifdef SRP_DEBUG
int
srp_print(void *v,
    int (*pr)(const char *, ...))
{
	int i, j, cpunum;
	struct cpu_info	*ci;
	CPU_INFO_ITERATOR cii;
	struct srp_hazard *hzrd;
	db_expr_t off;
	char *name;
	uintptr_t *pc;
	Elf_Sym *sym;

	cpunum = 0;
	CPU_INFO_FOREACH(cii, ci) {
		(*pr)("CPU: %d\n", cpunum);
		cpunum++;
		for (i = 0; i < nitems(ci->ci_srp_hazards); i++) {
			hzrd = &ci->ci_srp_hazards[i];
			(*pr)("  hzrd: %d\n", i);
			if (hzrd->sh_proc != NULL) {
				(*pr)("    owner: %p\t%s\n",
				    hzrd->sh_proc, hzrd->sh_proc->ps_comm);
				for (j = 0; j < SRP_STACKTRACE; j++) {
					if (hzrd->sh_stack[j] == NULL)
						break;
					pc = hzrd->sh_stack[j];
					sym = db_search_symbol((db_addr_t)pc,
					    DB_STGY_ANY, &off);
					db_symbol_values(sym, &name, NULL);
					if (name[0] == '\0')
						(*pr)("     %p\n", pc);
					else
						(*pr)("     %s()+0x%lx\n",
						    name, off);
				}
			}
		}
	}

	return (0);
}
#endif
