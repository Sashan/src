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
#include <sys/malloc.h>
#include <ddb/db_sym.h>
#include <ddb/db_access.h>
#include <ddb/db_output.h>
#include <sys/proc.h>
#endif

void	srp_v_gc_start(struct srp_gc *, struct srp *, void *);

#ifdef SRP_DEBUG

int db_srp_shadow_cmp(struct srp_shadow *, struct srp_shadow *);

struct srp_shadow *db_get_srp_shadow(struct srp *);
struct db_stack_record *db_get_stackrecord_for_shadow(struct srp_shadow *);
void db_stack_stop(struct srp *);

SPLAY_PROTOTYPE(srp_shadow_table, srp_shadow, srp_entry, db_srp_shadow_cmp)
SPLAY_GENERATE(srp_shadow_table, srp_shadow, srp_entry, db_srp_shadow_cmp)

#define	SRP_STACK_TRACE(_srp_)	do {					\
		struct srp_shadow	*srp_shadow;			\
		struct db_stack_record	*stack_record;			\
		struct db_stack_trace	*stack_trace;			\
									\
		srp_shadow = db_get_srp_shadow((_srp_));		\
		stack_record = db_get_stackrecord_for_shadow(srp_shadow);\
		if (stack_record != NULL) {				\
			stack_trace = db_get_stack_trace_aggr(stack_record);\
			db_save_stack_trace(stack_trace);		\
			stack_record = db_insert_stack_record(		\
			    srp_shadow->srp_stacks, stack_record);	\
			srp_shadow->srp_stack =				\
			    db_get_stack_trace_aggr(stack_record);	\
		}							\
	} while (0)

#define SRP_STACK_STOP(_srp_) do {					\
		db_stack_stop((_srp_));					\
	} while (0)
#else
#define SRP_STACK_TRACE(_srp_)	(void)(0)
#define SRP_STACK_STOP(_srp_)	(void)(0)
#endif

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

	return (v);
}

void *
srp_enter(struct srp_ref *sr, struct srp *srp)
{
	struct cpu_info *ci = curcpu();
	struct srp_hazard *hzrd;
	u_int i;

	SRP_STACK_TRACE(srp);

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
	SRP_STACK_STOP(sr->hz->sh_p);
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
db_srp_shadow_cmp(struct srp_shadow *a, struct srp_shadow *b)
{
	if (a->srp < b->srp)
		return (-1);
	else if (a->srp > b->srp)
		return (1);
	else
		return (0);
}

struct srp_shadow *
db_get_srp_shadow(struct srp *srp)
{
	struct srp_shadow	key;
	struct srp_shadow	*srp_shadow;
	struct cpu_info		*ci;
	struct srp_shadow_table	*srp_table;

	ci = curcpu();
	srp_table = &ci->ci_srp_table;
	key.srp = srp;
	srp_shadow = SPLAY_FIND(srp_shadow_table, srp_table, &key);
	if (srp_shadow == NULL) {
		srp_shadow = malloc(sizeof(struct srp_shadow), M_TEMP,
		    M_NOWAIT|M_ZERO);
		if (srp_shadow == NULL)
			return (NULL);

		srp_shadow->srp = srp;
		srp_shadow->srp_stacks = db_create_stack_aggr(256, 8);
		if (srp_shadow->srp_stacks == NULL) {
			free(srp_shadow, M_TEMP, sizeof(struct srp_shadow));
			return (NULL);
		}

		SPLAY_INSERT(srp_shadow_table, srp_table, srp_shadow);
	}

	return (srp_shadow);
}

void
db_stack_stop(struct srp *srp)
{
	struct srp_shadow	*srp_shadow;
	struct srp_shadow	key;
	struct cpu_info		*ci;
	struct srp_shadow_table	*srp_table;

	ci = curcpu();
	srp_table = &ci->ci_srp_table;
	key.srp = srp;
	srp_shadow = SPLAY_FIND(srp_shadow_table, srp_table, &key);

	if (srp_shadow != NULL) {
		SPLAY_REMOVE(srp_shadow_table, srp_table, srp_shadow);
		db_destroy_stack_aggr(srp_shadow->srp_stacks);
		free(srp_shadow, M_TEMP, sizeof(struct srp_shadow));
	}
}

struct db_stack_record *
db_get_stackrecord_for_shadow(struct srp_shadow *srp_shadow)
{
	struct db_stack_record *stack_record;

	if (srp_shadow == NULL)
		return (NULL);

	stack_record = db_alloc_stack_record(srp_shadow->srp_stacks);
	return (stack_record);
}

void
db_srp_display(db_expr_t *addr, int have_addr, db_expr_t count, char *modif)
{
	CPU_INFO_ITERATOR	 cii;
	struct cpu_info		*ci;
	unsigned int		 busy_hzrds;
	unsigned int		 i;
	db_expr_t		 offset;
	Elf_Sym			*sym;
	char			*name;
	struct srp_shadow	*srp_shadow;
	struct srp_shadow	 key;

	if ((modif == NULL) || (*modif == '\0')) {
		CPU_INFO_FOREACH(cii, ci) {
			busy_hzrds = 0;
			for (i = 0; i < SRP_HAZARD_NUM; i++) {
				if (ci->ci_srp_hazards[i].sh_p != NULL)
					busy_hzrds++;
			}

			db_printf("cpu %u, %u of %u in use\n", ci->ci_cpuid,
			    busy_hzrds, SRP_HAZARD_NUM);
		}

		return;
	}

	switch (*modif) {
	case 'c':
		ci = NULL;
		CPU_INFO_FOREACH(cii, ci) {
			if (ci->ci_cpuid == (u_int)count)
				break;
		}

		if (ci == NULL) {
			db_printf("no such CPU (%u)\n", (unsigned int)count);
			return;
		}

		for (i = 0; i < SRP_HAZARD_NUM; i++) {
			if (ci->ci_srp_hazards[i].sh_p != NULL) {
				key.srp = ci->ci_srp_hazards[i].sh_p;
				srp_shadow = SPLAY_FIND(srp_shadow_table,
				    &ci->ci_srp_table, &key);
				if (srp_shadow == NULL) {
					db_printf("[%u] no shadow\n", i);
				} else {
					sym = db_search_symbol(
					    srp_shadow->srp_stack->st_pc[1],
					    DB_STGY_ANY, &offset);
					db_symbol_values(sym, &name, NULL);
					db_printf("[%u] %p\t%s()\n", i, key.srp,
					    name);
				}
			} else {
				db_printf("[%u] --\n", i);
			}
		}
	default:
		db_printf("unknown option %c\n", *modif);
	}
}

void
db_srp_list_all(db_expr_t addr, int have_addr, db_expr_t count, char *modif)
{
	return;
}

void
db_srp_list(db_expr_t addr, int have_addr, db_expr_t count, char *modif)
{
	return;
}
#endif
