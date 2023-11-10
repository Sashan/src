/*	$OpenBSD: pf_table.c,v 1.145 2023/08/10 16:44:04 sashan Exp $	*/

/*
 * Copyright (c) 2002 Cedric Berger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/pool.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/ioccom.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_ipsp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif /* INET6 */

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

#define ACCEPT_FLAGS(flags, oklist)		\
	do {					\
		if ((flags & ~(oklist)) &	\
		    PFR_FLAG_ALLMASK)		\
			return (EINVAL);	\
	} while (0)

#define COPYIN(from, to, size, flags)		\
	((flags & PFR_FLAG_USERIOCTL) ?		\
	copyin((from), (to), (size)) :		\
	(bcopy((from), (to), (size)), 0))

#define COPYOUT(from, to, size, flags)		\
	((flags & PFR_FLAG_USERIOCTL) ?		\
	copyout((from), (to), (size)) :		\
	(bcopy((from), (to), (size)), 0))

#define YIELD(ok)				\
	do {					\
		if (ok)				\
			sched_pause(preempt);	\
	} while (0)

#define	FILLIN_SIN(sin, addr)			\
	do {					\
		(sin).sin_len = sizeof(sin);	\
		(sin).sin_family = AF_INET;	\
		(sin).sin_addr = (addr);	\
	} while (0)

#define	FILLIN_SIN6(sin6, addr)			\
	do {					\
		(sin6).sin6_len = sizeof(sin6);	\
		(sin6).sin6_family = AF_INET6;	\
		(sin6).sin6_addr = (addr);	\
	} while (0)

#define SWAP(type, a1, a2)			\
	do {					\
		type tmp = a1;			\
		a1 = a2;			\
		a2 = tmp;			\
	} while (0)

#define SUNION2PF(su, af) (((af)==AF_INET) ?	\
    (struct pf_addr *)&(su)->sin.sin_addr :	\
    (struct pf_addr *)&(su)->sin6.sin6_addr)

#define	AF_BITS(af)		(((af)==AF_INET)?32:128)
#define	ADDR_NETWORK(ad)	((ad)->pfra_net < AF_BITS((ad)->pfra_af))
#define	KENTRY_NETWORK(ke)	((ke)->pfrke_net < AF_BITS((ke)->pfrke_af))

#define NO_ADDRESSES		(-1)
#define ENQUEUE_UNMARKED_ONLY	(1)
#define INVERT_NEG_FLAG		(1)

struct pfr_walktree {
	enum pfrw_op {
		PFRW_MARK,
		PFRW_SWEEP,
		PFRW_ENQUEUE,
		PFRW_GET_ADDRS,
		PFRW_GET_ASTATS,
		PFRW_POOL_GET,
		PFRW_DYNADDR_UPDATE
	}	 pfrw_op;
	union {
		struct pfr_addr		*pfrw1_addr;
		struct pfr_astats	*pfrw1_astats;
		struct pfr_kentryworkq	*pfrw1_workq;
		struct pfr_kentryworkq	*pfrw1_ke_ioq;
		struct pfr_kentry	*pfrw1_kentry;
		struct pfi_dynaddr	*pfrw1_dyn;
	}	 pfrw_1;
	int	 pfrw_free;
};
#define pfrw_addr	pfrw_1.pfrw1_addr
#define pfrw_astats	pfrw_1.pfrw1_astats
#define pfrw_workq	pfrw_1.pfrw1_workq
#define pfrw_io_workq	pfrw_1.pfrw1_workq
#define pfrw_kentry	pfrw_1.pfrw1_kentry
#define pfrw_dyn	pfrw_1.pfrw1_dyn
#define pfrw_cnt	pfrw_free

#define senderr(e)	do { rv = (e); goto _bad; } while (0)

struct pool		 pfr_ktable_pl;
struct pool		 pfr_kentry_pl[PFRKE_MAX];
struct pool		 pfr_kcounters_pl;
union sockaddr_union	 pfr_mask;
struct pf_addr		 pfr_ffaddr;

int			 pfr_gcd(int, int);
void			 pfr_copyout_addr(struct pfr_addr *,
			    struct pfr_kentry *ke);
int			 pfr_validate_addr(struct pfr_addr *);
void			 pfr_mark_addrs(struct pfr_ktable *);
struct pfr_kentry	*pfr_lookup_addr(struct pfr_ktable *,
			    struct pfr_addr *, int);
struct pfr_kentry	*pfr_lookup_kentry(struct pfr_ktable *,
			    struct pfr_kentry *, int);
struct pfr_kentry	*pfr_create_kentry(struct pfr_addr *, int);
struct pfr_kentry 	*pfr_create_kentry_unlocked(struct pfr_addr *, int);
void			 pfr_kentry_kif_ref(struct pfr_kentry *);
void			 pfr_destroy_kentries(struct pfr_kentryworkq *);
void			 pfr_destroy_ioq(struct pfr_kentryworkq *, int);
void			 pfr_destroy_kentry(struct pfr_kentry *);
void			 pfr_insert_kentries(struct pfr_ktable *,
			    struct pfr_kentryworkq *, time_t);
void			 pfr_clstats_kentries(struct pfr_kentryworkq *, time_t,
			    int);
void			 pfr_reset_feedback(struct pfr_addr *, int, int);
void			 pfr_prepare_network(union sockaddr_union *, int, int);
int			 pfr_route_kentry(struct pfr_ktable *,
			    struct pfr_kentry *);
int			 pfr_unroute_kentry(struct pfr_ktable *,
			    struct pfr_kentry *);
int			 pfr_walktree(struct radix_node *, void *, u_int);
int			 pfr_validate_table(struct pfr_table *, int, int);
int			 pfr_fix_anchor(char *);
void			 pfr_merge_ktables(struct pfr_ktable *,
			    struct pfr_ktable *, time_t);
void			 pfr_insert_ktables(struct pf_rules_container *,
			    struct pfr_ktableworkq *);
void			 pfr_insert_ktable(struct pf_rules_container *,
			    struct pfr_ktable *);
void			 pfr_clstats_ktable(struct pfr_ktable *, time_t, int);
struct pfr_ktable	*pfr_create_ktable(struct pf_rules_container *,
			    struct pfr_table *, time_t, int);
void			 pfr_destroy_ktables(struct pfr_ktableworkq *, int);
void			 pfr_destroy_ktables_aux(struct pfr_ktableworkq *);
int			 pfr_ktable_compare(struct pfr_ktable *,
			    struct pfr_ktable *);
void			 pfr_ktable_winfo_update(struct pfr_ktable *,
			    struct pfr_kentry *);
void			 pfr_clean_node_mask(struct pfr_ktable *,
			    struct pfr_kentryworkq *);
int			 pfr_table_count(void);
int			 pfr_skip_table(struct pfr_table *,
			    struct pfr_ktable *, int);
struct pfr_kentry	*pfr_kentry_byidx(struct pfr_ktable *, int, int);
int			 pfr_islinklocal(sa_family_t, struct pf_addr *);
u_int32_t		 pfr_get_ktable_version(struct pfr_ktable *);
void			 pfr_update_tablerefs_anchor(struct pf_anchor *,
			    void *);
RB_GENERATE(pfr_ktablehead, pfr_ktable, pfrkt_tree, pfr_ktable_compare);

struct pfr_ktablehead	 pfr_ktables;
struct pfr_table	 pfr_nulltable;

int
pfr_gcd(int m, int n)
{
       int t;

       while (m > 0) {
	       t = n % m;
	       n = m;
	       m = t;
       }
       return (n);
}

void
pfr_initialize(void)
{
	rn_init(sizeof(struct sockaddr_in6));

	pool_init(&pfr_ktable_pl, sizeof(struct pfr_ktable),
	    0, IPL_SOFTNET, 0, "pfrktable", NULL);
	pool_init(&pfr_kentry_pl[PFRKE_PLAIN], sizeof(struct pfr_kentry),
	    0, IPL_SOFTNET, 0, "pfrke_plain", NULL);
	pool_init(&pfr_kentry_pl[PFRKE_ROUTE], sizeof(struct pfr_kentry_route),
	    0, IPL_SOFTNET, 0, "pfrke_route", NULL);
	pool_init(&pfr_kentry_pl[PFRKE_COST], sizeof(struct pfr_kentry_cost),
	    0, IPL_SOFTNET, 0, "pfrke_cost", NULL);
	pool_init(&pfr_kcounters_pl, sizeof(struct pfr_kcounters),
	    0, IPL_SOFTNET, 0, "pfrkcounters", NULL);

	memset(&pfr_ffaddr, 0xff, sizeof(pfr_ffaddr));
}

void
pfr_fill_feedback(struct pfr_kentry_all *ke, struct pfr_addr *ad)
{
	ad->pfra_type = ke->pfrke_type;

	switch (ke->pfrke_type) {
	case PFRKE_PLAIN:
		break;
	case PFRKE_COST:
		((struct pfr_kentry_cost *)ke)->weight = ad->pfra_weight;
		/* FALLTHROUGH */
	case PFRKE_ROUTE:
		if (ke->pfrke_rifname[0])
			strlcpy(ad->pfra_ifname, ke->pfrke_rifname, IFNAMSIZ);
		break;
	}

	switch (ke->pfrke_af) {
	case AF_INET:
		ad->pfra_ip4addr = ke->pfrke_sa.sin.sin_addr;
		break;
#ifdef	INET6
	case AF_INET6:
		ad->pfra_ip6addr = ke->pfrke_sa.sin6.sin6_addr;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ke->pfrke_af);
	}
	ad->pfra_weight = ((struct pfr_kentry_cost *)ke)->weight;
	ad->pfra_af = ke->pfrke_af;
	ad->pfra_net = ke->pfrke_net;
	if (ke->pfrke_flags & PFRKE_FLAG_NOT)
		ad->pfra_not = 1;
	ad->pfra_fback = ke->pfrke_fb;
}

int
pfr_copyin_addrs(struct pf_trans *t, struct pfr_table *tbl,
    struct pfr_addr *addr, int size)
{
	struct pfr_ktable	*ktt, *tmpkt;
	struct pfr_kentry	*ke;
	struct pfr_addr		 ad;
	int			 i;
	time_t			 tzero = gettime();

	if (t->pft_type != PF_TRANS_TAB) {
		log(LOG_ERR, "%s expects PF_TRANS_TAB only\n", __func__);
		return (EINVAL);
	}

	ACCEPT_FLAGS(t->pft_ioflags, PFR_FLAG_DUMMY | PFR_FLAG_FEEDBACK);

	if (pfr_validate_table(tbl, 0, t->pft_ioflags & PFR_FLAG_USERIOCTL))
		return (EINVAL);

	ktt = pfr_create_ktable(&t->pfttab_rc, tbl, tzero, PR_WAITOK);
	ktt->pfrkt_version = pfr_get_ktable_version(ktt);
	if (ktt->pfrkt_version == 0) {
		log(LOG_DEBUG, "%s %s@%s does not exist\n",
		    __func__, ktt->pfrkt_name, 
		    (ktt->pfrkt_rs->anchor == NULL) ?
		    "" : ktt->pfrkt_rs->anchor->path);
		return (ESRCH);
	}

	/*
	 * We use tmpkt to find duplicate addresses. I think
	 * it's still faster than populate ktt and then
	 * 'unroute' all kentries from ktt later.
	 *
	 * ktt is just placeholder/key which allows commit operation
	 * to find table to update.
	 */
	tmpkt = pfr_create_ktable(NULL, &pfr_nulltable, 0, PR_WAITOK);

	for (i = 0; i < size; i++) {
		YIELD(1);
		if (COPYIN(&addr[i], &ad, sizeof(ad), t->pft_ioflags)) {
			pfr_destroy_ktable(tmpkt, 0);
			return (EFAULT);
		}
		if (pfr_validate_addr(&ad)) {
			pfr_destroy_ktable(tmpkt, 0);
			return (EINVAL);
		}

		ke = pfr_create_kentry_unlocked(&ad, t->pft_ioflags);
		if (ke == NULL) {
			pfr_destroy_ktable(tmpkt, 0);
			return (ENOMEM);
		}
		ke->pfrke_fb = PFR_FB_NONE;
		if (pfr_lookup_kentry(tmpkt, ke, 1) != NULL) {
			ke->pfrke_fb = PFR_FB_DUPLICATE;
			log(LOG_DEBUG, "%s duplicate %d\n", __func__, i);
		} else {
			pfr_route_kentry(tmpkt, ke);
			log(LOG_DEBUG, "%s got it %d\n", __func__, i);
			t->pfttab_ke_ioq_len++;
		}

		SLIST_INSERT_HEAD(&t->pfttab_ke_ioq, ke, pfrke_ioq);
	}

	pfr_destroy_ktable(tmpkt, 0);

	return (0);
}

int
pfr_copyout_addrs(struct pf_trans *t, void *iobuf)
{
	struct pfr_astats *asbuf = (struct pfr_astats *)iobuf;
	struct pfr_addr *abuf = (struct pfr_addr *)iobuf;
	struct pfr_kentry *ke;
	struct pfr_astats as;
	unsigned int i = 0;

	SLIST_FOREACH(ke, &t->pfttab_ke_ioq, pfrke_ioq) {
		pfr_copyout_addr(&as.pfras_a, ke);
		switch (t->pfttab_iocmd) {
		case DIOCRGETADDRS:
			if (copyout(&as.pfras_a, &abuf[i++],
			    sizeof(as.pfras_a)))
				return (EFAULT);
			break;
		case DIOCRGETASTATS:
			if (ke->pfrke_counters) {
				bcopy(ke->pfrke_counters->pfrkc_packets,
				    as.pfras_packets,
				    sizeof(as.pfras_packets));
				bcopy(ke->pfrke_counters->pfrkc_bytes,
				    as.pfras_bytes,
				    sizeof(as.pfras_bytes));
			} else {
				bzero(as.pfras_packets,
				    sizeof(as.pfras_packets));
				bzero(as.pfras_bytes,
				    sizeof(as.pfras_bytes));
				as.pfras_a.pfra_fback = PFR_FB_NOCOUNT;
			}
			if (copyout(&as, &asbuf[i++], sizeof(as)))
				return (EFAULT);
			break;
		default:
			panic("%s invalid iocmd", __func__);
			break;
		}
	}

	return (0);
}

void
pfr_addaddrs_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable *ktt, *kt;
	struct pfr_kentry *ke, *exists;

	KASSERT(ta->tables == 1);
	ktt = RB_ROOT(&ta->ktables);

	kt = RB_FIND(pfr_ktablehead, &a->ktables, ktt);
	KASSERT(kt != NULL);
	KASSERT(kt->pfrkt_version == ktt->pfrkt_version);

	SLIST_FOREACH(ke, &t->pfttab_ke_ioq, pfrke_ioq) {
		if (ke->pfrke_fb == PFR_FB_DUPLICATE)
			continue;

		exists = pfr_lookup_kentry(kt, ke, 1);
		if (exists == NULL) {
			pfr_kentry_kif_ref(ke);
			if (t->pft_ioflags & PFR_FLAG_DUMMY) {
				ke->pfrke_fb = PFR_FB_ADDED;
				t->pfttab_nadd++;
			} else if (pfr_route_kentry(kt, ke) == 0) {
				ke->pfrke_fb = PFR_FB_ADDED;
				t->pfttab_nadd++;
			} else
				ke->pfrke_fb = PFR_FB_NONE;
		} else {
			if ((exists->pfrke_flags & PFRKE_FLAG_NOT) !=
			    (ke->pfrke_flags & PFRKE_FLAG_NOT))
				ke->pfrke_fb = PFR_FB_CONFLICT;
			else
				ke->pfrke_fb = PFR_FB_NONE; /* PFR_FB_MATCH? */
		}
	}

	if ((t->pfttab_nadd != 0) &&
	    ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0))
		kt->pfrkt_cnt += t->pfttab_nadd;		
}

int
pfr_addrs_feedback(struct pf_trans *t, struct pfr_addr *addr, int size,
    int garbage_too)
{
	int	i, old_fb;
	struct pfr_kentry *ke;
	struct pfr_addr ad;

	if ((t->pft_ioflags & PFR_FLAG_FEEDBACK) == 0)
		return (0);

	i = 0;
	SLIST_FOREACH(ke, &t->pfttab_ke_ioq, pfrke_ioq) {
		YIELD(1);
		bzero(&ad, sizeof(ad));
		pfr_fill_feedback((struct pfr_kentry_all *)ke, &ad);
		if (COPYOUT(&ad, &addr[i], sizeof(ad), t->pft_ioflags))
			return (EFAULT);
		i++;
	}

	if (garbage_too == PFR_GARBAGE_TOO) {
		SLIST_FOREACH(ke, &t->pfttab_ke_garbage, pfrke_workq) {
			YIELD(1);
			old_fb = ke->pfrke_fb;
			ke->pfrke_fb = PFR_FB_DELETED;
			pfr_fill_feedback((struct pfr_kentry_all *)ke, &ad);
			ke->pfrke_fb = old_fb;
			if (COPYOUT(&ad, addr+i, sizeof(ad), t->pft_ioflags))
				return (EFAULT);
			i++;
		}
	}

	return (0);
}

int
pfr_tst_addrs(struct pfr_table *tbl, struct pfr_addr *addr, int size,
	int *nmatch, int flags)
{
	struct pfr_ktable	*kt;
	struct pfr_kentry	*p;
	struct pfr_addr		 ad;
	int			 i, xmatch = 0;
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	ACCEPT_FLAGS(flags, PFR_FLAG_REPLACE);
	if (pfr_validate_table(tbl, 0, 0))
		return (EINVAL);
	PF_ASSERT_LOCKED();
	rs = pf_find_ruleset(&pf_global, tbl->pfrt_anchor);
	if (rs == NULL)
		return (ESRCH);
	if ((a = rs->anchor) == NULL)
		a = &pf_main_anchor;
	kt = pfr_lookup_table(a, tbl);
	if (kt == NULL || !(kt->pfrkt_flags & PFR_TFLAG_ACTIVE))
		return (ESRCH);

	for (i = 0; i < size; i++) {
		YIELD(flags & PFR_FLAG_USERIOCTL);
		if (COPYIN(addr+i, &ad, sizeof(ad), flags))
			return (EFAULT);
		if (pfr_validate_addr(&ad))
			return (EINVAL);
		if (ADDR_NETWORK(&ad))
			return (EINVAL);
		p = pfr_lookup_addr(kt, &ad, 0);
		if (flags & PFR_FLAG_REPLACE)
			pfr_copyout_addr(&ad, p);
		ad.pfra_fback = (p == NULL) ? PFR_FB_NONE :
		    ((p->pfrke_flags & PFRKE_FLAG_NOT) ?
		    PFR_FB_NOTMATCH : PFR_FB_MATCH);
		if (p != NULL && !(p->pfrke_flags & PFRKE_FLAG_NOT))
			xmatch++;
		if (COPYOUT(&ad, addr+i, sizeof(ad), flags))
			return (EFAULT);
	}
	if (nmatch != NULL)
		*nmatch = xmatch;
	return (0);
}

int
pfr_get_addrs(struct pf_trans *t, struct pfr_table *tbl, int *size)
{
	struct pfr_ktable	*kt;
	struct pfr_walktree	 w;
	int			 rv;
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	ACCEPT_FLAGS(t->pft_ioflags, 0);
	if (pfr_validate_table(tbl, 0, 0))
		return (EINVAL);
	PF_ASSERT_LOCKED();
	rs = pf_find_ruleset(&pf_global, tbl->pfrt_anchor);
	if (rs == NULL)
		return (ESRCH);
	if ((a = rs->anchor) == NULL)
		a = &pf_main_anchor;
	kt = pfr_lookup_table(a, tbl);
	if (kt == NULL || !(kt->pfrkt_flags & PFR_TFLAG_ACTIVE))
		return (ESRCH);
	if (kt->pfrkt_cnt > *size) {
		*size = kt->pfrkt_cnt;
		return (0);
	}

	bzero(&w, sizeof(w));
	w.pfrw_op = PFRW_GET_ADDRS;
	w.pfrw_free = kt->pfrkt_cnt;
	w.pfrw_io_workq = &t->pfttab_ke_ioq;
	rv = rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w);
	if (!rv)
		rv = rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w);
	if (rv)
		return (rv);

	if (w.pfrw_free) {
		DPFPRINTF(LOG_ERR,
		    "pfr_get_addrs: corruption detected (%d)", w.pfrw_free);
		return (ENOTTY);
	}
	*size = kt->pfrkt_cnt;
	return (0);
}

int
pfr_get_astats(struct pf_trans *t, struct pfr_table *tbl, int *size)
{
	struct pfr_ktable	*kt;
	struct pfr_walktree	 w;
	struct pfr_kentryworkq	 workq;
	int			 rv;
	time_t			 tzero = gettime();
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	if (pfr_validate_table(tbl, 0, 0))
		return (EINVAL);
	PF_ASSERT_LOCKED();
	rs = pf_find_ruleset(&pf_global, tbl->pfrt_anchor);
	if (rs == NULL)
		return (ESRCH);
	if ((a = rs->anchor) == NULL)
		a = &pf_main_anchor;
	kt = pfr_lookup_table(a, tbl);
	if (kt == NULL || !(kt->pfrkt_flags & PFR_TFLAG_ACTIVE))
		return (ESRCH);
	if (kt->pfrkt_cnt > *size) {
		*size = kt->pfrkt_cnt;
		return (0);
	}

	bzero(&w, sizeof(w));
	w.pfrw_op = PFRW_GET_ASTATS;
	w.pfrw_free = kt->pfrkt_cnt;
	rv = rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w);
	if (!rv)
		rv = rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w);
	if (!rv && (t->pft_ioflags & PFR_FLAG_CLSTATS)) {
		pfr_enqueue_addrs(kt, &workq, NULL, 0);
		pfr_clstats_kentries(&workq, tzero, 0);
	}
	if (rv)
		return (rv);

	if (w.pfrw_free) {
		DPFPRINTF(LOG_ERR,
		    "pfr_get_astats: corruption detected (%d)", w.pfrw_free);
		return (ENOTTY);
	}
	*size = kt->pfrkt_cnt;
	return (0);
}

int
pfr_clr_astats(struct pfr_table *tbl, struct pfr_addr *addr, int size,
    int *nzero, int flags)
{
	struct pfr_ktable	*kt;
	struct pfr_kentryworkq	 workq;
	struct pfr_kentry	*p;
	struct pfr_addr		 ad;
	int			 i, rv, xzero = 0;
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	ACCEPT_FLAGS(flags, PFR_FLAG_DUMMY | PFR_FLAG_FEEDBACK);
	if (pfr_validate_table(tbl, 0, 0))
		return (EINVAL);
	PF_ASSERT_LOCKED();
	rs = pf_find_ruleset(&pf_global, tbl->pfrt_anchor);
	if (rs == NULL)
		return (ESRCH);
	if ((a = rs->anchor) == NULL)
		a = &pf_main_anchor;
	kt = pfr_lookup_table(a, tbl);
	if (kt == NULL || !(kt->pfrkt_flags & PFR_TFLAG_ACTIVE))
		return (ESRCH);
	SLIST_INIT(&workq);
	for (i = 0; i < size; i++) {
		YIELD(flags & PFR_FLAG_USERIOCTL);
		if (COPYIN(addr+i, &ad, sizeof(ad), flags))
			senderr(EFAULT);
		if (pfr_validate_addr(&ad))
			senderr(EINVAL);
		p = pfr_lookup_addr(kt, &ad, 1);
		if (flags & PFR_FLAG_FEEDBACK) {
			ad.pfra_fback = (p != NULL) ?
			    PFR_FB_CLEARED : PFR_FB_NONE;
			if (COPYOUT(&ad, addr+i, sizeof(ad), flags))
				senderr(EFAULT);
		}
		if (p != NULL) {
			SLIST_INSERT_HEAD(&workq, p, pfrke_workq);
			xzero++;
		}
	}

	if (!(flags & PFR_FLAG_DUMMY))
		pfr_clstats_kentries(&workq, gettime(), 0);
	if (nzero != NULL)
		*nzero = xzero;
	return (0);
_bad:
	if (flags & PFR_FLAG_FEEDBACK)
		pfr_reset_feedback(addr, size, flags);
	return (rv);
}

int
pfr_validate_addr(struct pfr_addr *ad)
{
	int i;

	switch (ad->pfra_af) {
	case AF_INET:
		if (ad->pfra_net > 32) {
			log(LOG_DEBUG,
			    "%s invalid mask length %d for AF_INET\n",
			    __func__, ad->pfra_net);
			return (-1);
		}
		break;
#ifdef INET6
	case AF_INET6:
		if (ad->pfra_net > 128) {
			log(LOG_DEBUG,
			    "%s invalid mask length %d for AF_INET6\n",
			    __func__, ad->pfra_net);
			return (-1);
		}
		break;
#endif /* INET6 */
	default:
		log(LOG_DEBUG, "%s unknown AF\n", __func__);
		return (-1);
	}
	if (ad->pfra_net < 128 &&
	    (((caddr_t)ad)[ad->pfra_net/8] & (0xFF >> (ad->pfra_net%8)))) {
		log(LOG_DEBUG, "%s, non-zero mask %x\n", __func__,
		    (((caddr_t)ad)[ad->pfra_net/8] & (0xFF >> (ad->pfra_net%8))));
		return (-1);
	}
	for (i = (ad->pfra_net+7)/8; i < sizeof(ad->pfra_u); i++) {
		if (((caddr_t)ad)[i]) {
			log(LOG_DEBUG, "%s invalid mask %d\n", __func__, i);
			return (-1);
		}
	}
	if (ad->pfra_not && ad->pfra_not != 1) {
		log(LOG_DEBUG, "%s pfra_not must be either 0 or 1 (%d)\n",
		    __func__, ad->pfra_not);
		return (-1);
	}
	if (ad->pfra_fback != PFR_FB_NONE) {
		log(LOG_DEBUG, "%s pfra_fback != PFR_FB_NONE\n", __func__);
		return (-1);
	}
	if (ad->pfra_type >= PFRKE_MAX) {
		log(LOG_DEBUG, "%s invalid type\n", __func__);
		return (-1);
	}
	return (0);
}

void
pfr_enqueue_addrs(struct pfr_ktable *kt, struct pfr_kentryworkq *workq,
	int *naddr, int sweep)
{
	struct pfr_walktree	w;

	SLIST_INIT(workq);
	bzero(&w, sizeof(w));
	w.pfrw_op = sweep ? PFRW_SWEEP : PFRW_ENQUEUE;
	w.pfrw_workq = workq;
	if (kt->pfrkt_ip4 != NULL)
		if (rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w))
			DPFPRINTF(LOG_ERR,
			    "pfr_enqueue_addrs: IPv4 walktree failed.");
	if (kt->pfrkt_ip6 != NULL)
		if (rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w))
			DPFPRINTF(LOG_ERR,
			    "pfr_enqueue_addrs: IPv6 walktree failed.");
	if (naddr != NULL)
		*naddr = w.pfrw_cnt;
}

void
pfr_mark_addrs(struct pfr_ktable *kt)
{
	struct pfr_walktree	w;

	bzero(&w, sizeof(w));
	w.pfrw_op = PFRW_MARK;
	if (rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w))
		DPFPRINTF(LOG_ERR,
		    "pfr_mark_addrs: IPv4 walktree failed.");
	if (rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w))
		DPFPRINTF(LOG_ERR,
		    "pfr_mark_addrs: IPv6 walktree failed.");
}


struct pfr_kentry *
pfr_lookup_addr(struct pfr_ktable *kt, struct pfr_addr *ad, int exact)
{
	union sockaddr_union	 sa, mask;
	struct radix_node_head	*head;
	struct pfr_kentry	*ke;

	bzero(&sa, sizeof(sa));
	switch (ad->pfra_af) {
	case AF_INET:
		FILLIN_SIN(sa.sin, ad->pfra_ip4addr);
		head = kt->pfrkt_ip4;
		break;
#ifdef	INET6
	case AF_INET6:
		FILLIN_SIN6(sa.sin6, ad->pfra_ip6addr);
		head = kt->pfrkt_ip6;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ad->pfra_af);
	}
	if (ADDR_NETWORK(ad)) {
		pfr_prepare_network(&mask, ad->pfra_af, ad->pfra_net);
		ke = (struct pfr_kentry *)rn_lookup(&sa, &mask, head);
	} else {
		ke = (struct pfr_kentry *)rn_match(&sa, head);
		if (exact && ke && KENTRY_NETWORK(ke))
			ke = NULL;
	}
	return (ke);
}

struct pfr_kentry *
pfr_lookup_kentry(struct pfr_ktable *kt, struct pfr_kentry *key, int exact)
{
	union sockaddr_union	 mask;
	struct radix_node_head	*head;
	struct pfr_kentry	*ke;

	switch (key->pfrke_af) {
	case AF_INET:
		head = kt->pfrkt_ip4;
		break;
#ifdef	INET6
	case AF_INET6:
		head = kt->pfrkt_ip6;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(key->pfrke_af);
	}
	if (KENTRY_NETWORK(key)) {
		pfr_prepare_network(&mask, key->pfrke_af, key->pfrke_net);
		ke = (struct pfr_kentry *)rn_lookup(&key->pfrke_sa, &mask,
		    head);
	} else {
		ke = (struct pfr_kentry *)rn_match(&key->pfrke_sa, head);
		if (exact && ke && KENTRY_NETWORK(ke))
			ke = NULL;
	}
	return (ke);
}

struct pfr_kentry *
pfr_create_kentry(struct pfr_addr *ad, int mflags)
{
	struct pfr_kentry_all	*ke;

	if (ad->pfra_type >= PFRKE_MAX)
		panic("unknown pfra_type %d", ad->pfra_type);

	ke = pool_get(&pfr_kentry_pl[ad->pfra_type], mflags | PR_ZERO);
	if (ke == NULL)
		return (NULL);

	ke->pfrke_type = ad->pfra_type;

	/* set weight allowing implicit weights */
	if (ad->pfra_weight == 0)
		ad->pfra_weight = 1;

	switch (ke->pfrke_type) {
	case PFRKE_PLAIN:
		break;
	case PFRKE_COST:
		((struct pfr_kentry_cost *)ke)->weight = ad->pfra_weight;
		/* FALLTHROUGH */
	case PFRKE_ROUTE:
		if (ad->pfra_ifname[0])
			ke->pfrke_rkif = pfi_kif_get(ad->pfra_ifname, NULL);
		if (ke->pfrke_rkif)
			pfi_kif_ref(ke->pfrke_rkif, PFI_KIF_REF_ROUTE);
		break;
	}

	switch (ad->pfra_af) {
	case AF_INET:
		FILLIN_SIN(ke->pfrke_sa.sin, ad->pfra_ip4addr);
		break;
#ifdef	INET6
	case AF_INET6:
		FILLIN_SIN6(ke->pfrke_sa.sin6, ad->pfra_ip6addr);
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ad->pfra_af);
	}
	ke->pfrke_af = ad->pfra_af;
	ke->pfrke_net = ad->pfra_net;
	if (ad->pfra_not)
		ke->pfrke_flags |= PFRKE_FLAG_NOT;
	return ((struct pfr_kentry *)ke);
}

struct pfr_kentry *
pfr_create_kentry_unlocked(struct pfr_addr *ad, int flags)
{
	struct pfr_kentry_all	*ke;
	int mflags = PR_ZERO;

	if (ad->pfra_type >= PFRKE_MAX)
		panic("unknown pfra_type %d", ad->pfra_type);

	if (flags & PFR_FLAG_USERIOCTL)
		mflags |= PR_WAITOK;
	else
		mflags |= PR_NOWAIT;

	ke = pool_get(&pfr_kentry_pl[ad->pfra_type], mflags);
	if (ke == NULL)
		return (NULL);

	ke->pfrke_type = ad->pfra_type;

	/* set weight allowing implicit weights */
	if (ad->pfra_weight == 0)
		ad->pfra_weight = 1;

	switch (ke->pfrke_type) {
	case PFRKE_PLAIN:
		break;
	case PFRKE_COST:
		((struct pfr_kentry_cost *)ke)->weight = ad->pfra_weight;
		/* FALLTHROUGH */
	case PFRKE_ROUTE:
		if (ad->pfra_ifname[0])
			(void) strlcpy(ke->pfrke_rifname, ad->pfra_ifname,
			    IFNAMSIZ);
		break;
	}

	switch (ad->pfra_af) {
	case AF_INET:
		FILLIN_SIN(ke->pfrke_sa.sin, ad->pfra_ip4addr);
		break;
#ifdef	INET6
	case AF_INET6:
		FILLIN_SIN6(ke->pfrke_sa.sin6, ad->pfra_ip6addr);
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ad->pfra_af);
	}
	ke->pfrke_af = ad->pfra_af;
	ke->pfrke_net = ad->pfra_net;
	if (ad->pfra_not)
		ke->pfrke_flags |= PFRKE_FLAG_NOT;
	return ((struct pfr_kentry *)ke);
}

void
pfr_kentry_kif_ref(struct pfr_kentry *ke_all)
{
	struct pfr_kentry_all	*ke = (struct pfr_kentry_all *)ke_all;

	NET_ASSERT_LOCKED();
	switch (ke->pfrke_type) {
	case PFRKE_PLAIN:
		break;
	case PFRKE_COST:
	case PFRKE_ROUTE:
		if (ke->pfrke_rifname[0])
			ke->pfrke_rkif = pfi_kif_get(ke->pfrke_rifname, NULL);
		if (ke->pfrke_rkif)
			pfi_kif_ref(ke->pfrke_rkif, PFI_KIF_REF_ROUTE);
		break;
	}
}

void
pfr_destroy_kentries(struct pfr_kentryworkq *workq)
{
	struct pfr_kentry	*p;

	while ((p = SLIST_FIRST(workq)) != NULL) {
		YIELD(1);
		SLIST_REMOVE_HEAD(workq, pfrke_workq);
		pfr_destroy_kentry(p);
	}
}

void
pfr_destroy_ioq(struct pfr_kentryworkq *ioq, int flags)
{
	struct pfr_kentry	*p;

	while ((p = SLIST_FIRST(ioq)) != NULL) {
		YIELD(flags & PFR_FLAG_USERIOCTL);
		SLIST_REMOVE_HEAD(ioq, pfrke_ioq);
		/*
		 * we destroy only those entries, which did not make it to
		 * table
		 */
		if ((p->pfrke_fb != PFR_FB_ADDED) || (flags & PFR_FLAG_DUMMY))
			pfr_destroy_kentry(p);
	}
}

void
pfr_destroy_kentry(struct pfr_kentry *ke)
{
	if (ke->pfrke_counters)
		pool_put(&pfr_kcounters_pl, ke->pfrke_counters);
	if (ke->pfrke_type == PFRKE_COST || ke->pfrke_type == PFRKE_ROUTE)
		pfi_kif_unref(((struct pfr_kentry_all *)ke)->pfrke_rkif,
		    PFI_KIF_REF_ROUTE);
	pool_put(&pfr_kentry_pl[ke->pfrke_type], ke);
}

void
pfr_insert_kentries(struct pfr_ktable *kt,
    struct pfr_kentryworkq *workq, time_t tzero)
{
	struct pfr_kentry	*p;
	int			 rv, n = 0;

	SLIST_FOREACH(p, workq, pfrke_workq) {
		rv = pfr_route_kentry(kt, p);
		if (rv) {
			DPFPRINTF(LOG_ERR,
			    "pfr_insert_kentries: cannot route entry "
			    "(code=%d).", rv);
			p->pfrke_fb = PFR_FB_NONE;
		}
		p->pfrke_tzero = tzero;
		++n;
		if (p->pfrke_type == PFRKE_COST)
			kt->pfrkt_refcntcost++;
		pfr_ktable_winfo_update(kt, p);
	}
	kt->pfrkt_cnt += n;
}

int
pfr_insert_kentry(struct pfr_ktable *kt, struct pfr_addr *ad, time_t tzero)
{
	struct pfr_kentry	*p;
	int			 rv;

	p = pfr_lookup_addr(kt, ad, 1);
	if (p != NULL)
		return (0);
	p = pfr_create_kentry(ad, M_WAITOK);
	if (p == NULL)
		return (EINVAL);

	rv = pfr_route_kentry(kt, p);
	if (rv)
		return (rv);

	p->pfrke_tzero = tzero;
	if (p->pfrke_type == PFRKE_COST)
		kt->pfrkt_refcntcost++;
	kt->pfrkt_cnt++;
	pfr_ktable_winfo_update(kt, p);

	return (0);
}

void
pfr_remove_kentries(struct pfr_ktable *kt,
    struct pfr_kentryworkq *workq)
{
	struct pfr_kentry	*p;
	struct pfr_kentryworkq   addrq;
	int			 n = 0;

	SLIST_FOREACH(p, workq, pfrke_workq) {
		pfr_unroute_kentry(kt, p);
		++n;
		YIELD(1);
		if (p->pfrke_type == PFRKE_COST)
			kt->pfrkt_refcntcost--;
	}
	kt->pfrkt_cnt -= n;
	pfr_destroy_kentries(workq);

	/* update maxweight and gcd for load balancing */
	if (kt->pfrkt_refcntcost > 0) {
		kt->pfrkt_gcdweight = 0;
		kt->pfrkt_maxweight = 1;
		pfr_enqueue_addrs(kt, &addrq, NULL, 0);
		SLIST_FOREACH(p, &addrq, pfrke_workq)
			pfr_ktable_winfo_update(kt, p);
	}
}

void
pfr_clean_node_mask(struct pfr_ktable *kt,
    struct pfr_kentryworkq *workq)
{
	struct pfr_kentry	*p;

	SLIST_FOREACH(p, workq, pfrke_workq) {
		pfr_unroute_kentry(kt, p);
	}
}

void
pfr_clstats_kentries(struct pfr_kentryworkq *workq, time_t tzero, int negchange)
{
	struct pfr_kentry	*p;

	SLIST_FOREACH(p, workq, pfrke_workq) {
		if (negchange)
			p->pfrke_flags ^= PFRKE_FLAG_NOT;
		if (p->pfrke_counters) {
			pool_put(&pfr_kcounters_pl, p->pfrke_counters);
			p->pfrke_counters = NULL;
		}
		p->pfrke_tzero = tzero;
	}
}

void
pfr_reset_feedback(struct pfr_addr *addr, int size, int flags)
{
	struct pfr_addr	ad;
	int		i;

	for (i = 0; i < size; i++) {
		YIELD(flags & PFR_FLAG_USERIOCTL);
		if (COPYIN(addr+i, &ad, sizeof(ad), flags))
			break;
		ad.pfra_fback = PFR_FB_NONE;
		if (COPYOUT(&ad, addr+i, sizeof(ad), flags))
			break;
	}
}

void
pfr_prepare_network(union sockaddr_union *sa, int af, int net)
{
#ifdef	INET6
	int	i;
#endif	/* INET6 */

	bzero(sa, sizeof(*sa));
	switch (af) {
	case AF_INET:
		sa->sin.sin_len = sizeof(sa->sin);
		sa->sin.sin_family = AF_INET;
		sa->sin.sin_addr.s_addr = net ? htonl(-1 << (32-net)) : 0;
		break;
#ifdef	INET6
	case AF_INET6:
		sa->sin6.sin6_len = sizeof(sa->sin6);
		sa->sin6.sin6_family = AF_INET6;
		for (i = 0; i < 4; i++) {
			if (net <= 32) {
				sa->sin6.sin6_addr.s6_addr32[i] =
				    net ? htonl(-1 << (32-net)) : 0;
				break;
			}
			sa->sin6.sin6_addr.s6_addr32[i] = 0xFFFFFFFF;
			net -= 32;
		}
		break;
#endif	/* INET6 */
	default:
		unhandled_af(af);
	}
}

int
pfr_route_kentry(struct pfr_ktable *kt, struct pfr_kentry *ke)
{
	union sockaddr_union	 mask;
	struct radix_node	*rn;
	struct radix_node_head	*head;

	bzero(&ke->pfrke_node, sizeof(ke->pfrke_node));
	switch (ke->pfrke_af) {
	case AF_INET:
		head = kt->pfrkt_ip4;
		break;
#ifdef	INET6
	case AF_INET6:
		head = kt->pfrkt_ip6;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ke->pfrke_af);
	}

	if (KENTRY_NETWORK(ke)) {
		pfr_prepare_network(&mask, ke->pfrke_af, ke->pfrke_net);
		rn = rn_addroute(&ke->pfrke_sa, &mask, head, ke->pfrke_node, 0);
	} else
		rn = rn_addroute(&ke->pfrke_sa, NULL, head, ke->pfrke_node, 0);

	return (rn == NULL ? -1 : 0);
}

int
pfr_unroute_kentry(struct pfr_ktable *kt, struct pfr_kentry *ke)
{
	union sockaddr_union	 mask;
	struct radix_node	*rn;
	struct radix_node_head	*head;

	switch (ke->pfrke_af) {
	case AF_INET:
		head = kt->pfrkt_ip4;
		break;
#ifdef	INET6
	case AF_INET6:
		head = kt->pfrkt_ip6;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ke->pfrke_af);
	}

	if (KENTRY_NETWORK(ke)) {
		pfr_prepare_network(&mask, ke->pfrke_af, ke->pfrke_net);
		rn = rn_delete(&ke->pfrke_sa, &mask, head, NULL);
	} else
		rn = rn_delete(&ke->pfrke_sa, NULL, head, NULL);

	if (rn == NULL) {
		DPFPRINTF(LOG_ERR, "pfr_unroute_kentry: delete failed.\n");
		return (-1);
	}
	return (0);
}

void
pfr_copyout_addr(struct pfr_addr *ad, struct pfr_kentry *ke)
{
	bzero(ad, sizeof(*ad));
	if (ke == NULL)
		return;
	ad->pfra_af = ke->pfrke_af;
	ad->pfra_net = ke->pfrke_net;
	ad->pfra_type = ke->pfrke_type;
	if (ke->pfrke_flags & PFRKE_FLAG_NOT)
		ad->pfra_not = 1;

	switch (ad->pfra_af) {
	case AF_INET:
		ad->pfra_ip4addr = ke->pfrke_sa.sin.sin_addr;
		break;
#ifdef	INET6
	case AF_INET6:
		ad->pfra_ip6addr = ke->pfrke_sa.sin6.sin6_addr;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(ad->pfra_af);
	}
	if (ke->pfrke_counters != NULL)
		ad->pfra_states = ke->pfrke_counters->states;
	switch (ke->pfrke_type) {
	case PFRKE_COST:
		ad->pfra_weight = ((struct pfr_kentry_cost *)ke)->weight;
		/* FALLTHROUGH */
	case PFRKE_ROUTE:
		if (((struct pfr_kentry_route *)ke)->kif != NULL)
			strlcpy(ad->pfra_ifname,
			    ((struct pfr_kentry_route *)ke)->kif->pfik_name,
			    IFNAMSIZ);
		break;
	default:
		break;
	}
}

int
pfr_walktree(struct radix_node *rn, void *arg, u_int id)
{
	struct pfr_kentry	*ke = (struct pfr_kentry *)rn;
	struct pfr_walktree	*w = arg;
	union sockaddr_union	 mask;

	switch (w->pfrw_op) {
	case PFRW_MARK:
		ke->pfrke_flags &= ~PFRKE_FLAG_MARK;
		break;
	case PFRW_SWEEP:
		if (ke->pfrke_flags & PFRKE_FLAG_MARK)
			break;
		/* FALLTHROUGH */
	case PFRW_ENQUEUE:
		SLIST_INSERT_HEAD(w->pfrw_workq, ke, pfrke_workq);
		w->pfrw_cnt++;
		break;
	case PFRW_GET_ADDRS:
	case PFRW_GET_ASTATS:
		if (w->pfrw_free-- > 0)
			SLIST_INSERT_HEAD(w->pfrw_io_workq, ke, pfrke_ioq);
		break;
	case PFRW_POOL_GET:
		if (ke->pfrke_flags & PFRKE_FLAG_NOT)
			break; /* negative entries are ignored */
		if (!w->pfrw_cnt--) {
			w->pfrw_kentry = ke;
			return (1); /* finish search */
		}
		break;
	case PFRW_DYNADDR_UPDATE:
		switch (ke->pfrke_af) {
		case AF_INET:
			if (w->pfrw_dyn->pfid_acnt4++ > 0)
				break;
			pfr_prepare_network(&mask, AF_INET, ke->pfrke_net);
			w->pfrw_dyn->pfid_addr4 = *SUNION2PF(
			    &ke->pfrke_sa, AF_INET);
			w->pfrw_dyn->pfid_mask4 = *SUNION2PF(
			    &mask, AF_INET);
			break;
#ifdef	INET6
		case AF_INET6:
			if (w->pfrw_dyn->pfid_acnt6++ > 0)
				break;
			pfr_prepare_network(&mask, AF_INET6, ke->pfrke_net);
			w->pfrw_dyn->pfid_addr6 = *SUNION2PF(
			    &ke->pfrke_sa, AF_INET6);
			w->pfrw_dyn->pfid_mask6 = *SUNION2PF(
			    &mask, AF_INET6);
			break;
#endif	/* INET6 */
		default:
			unhandled_af(ke->pfrke_af);
		}
		break;
	}
	return (0);
}

struct pfr_ktable *
pfr_promote_table(struct pf_anchor *a, struct pfr_ktable *kt)
{
	struct pf_anchor	*parent = a->parent;
	struct pfr_ktable	*ktp, *exists;
	struct pfr_kentryworkq	 workq;

	/*
	 * Tables which are not referred by rules can be
	 * disposed right away. Tell caller to dispose the
	 * table.
	 */
	if (kt->pfrkt_refcnt == 0)
		return (kt);

	/*
	 * Flush all addresses, table which is going to
	 * be promoted should be empty.
	 */
	SLIST_INIT(&workq);
	pfr_enqueue_addrs(kt, &workq, NULL, 0);
	pfr_remove_kentries(kt, &workq);

	/*
	 * Find parent table which can be used in 'a' and
	 * and 'a's chiildren.
	 */
	ktp = NULL;
	while (parent != NULL) {
		ktp = RB_FIND(pfr_ktablehead, &parent->ktables, kt);
		if (ktp != NULL)
			break;
		parent = parent->parent;
	}


	/*
	 * if no parent was found we start with update from root (main anchor)
	 */
	if (parent == NULL)
		parent = &pf_main_anchor;
	
	/*
	 * insert table to parent tree.
	 */
	if (ktp == NULL) {
		exists = RB_INSERT(pfr_ktablehead, &parent->ktables, kt);
		KASSERT(exists == NULL);
		/*  table is still in use, tell caller not to free it */
		kt = NULL;
	}
	pfr_update_table_refs(parent);

	return (kt);
}

struct pf_anchor *
pfr_select_anchor(struct pf_trans *t)
{
	struct pf_anchor *a, *ta;
	/*
	 * this is currently really awkward. In order to find desired
	 * anchor in globals, we must walk all anchor tree in
	 * transaction to find a lookup key `ta` first. The lookup
	 * key is the anchor, where table exists.
	 */
	if (t->pfttab_rc.main_anchor.tables != 0) {
		KASSERT(t->pfttab_rc.main_anchor.tables == 1);
		a = &pf_main_anchor;
	} else {
		RB_FOREACH(ta, pf_anchor_global, &t->pfttab_rc.anchors) {
			if (ta->tables != 0) {
				KASSERT(ta->tables == 1);
				break;
			}
		}
		KASSERT(ta != NULL);
		a = RB_FIND(pf_anchor_global, &pf_anchors, ta);
	}

	return (a);
}

int
pfr_clr_tables(struct pf_trans *t)
{
	struct pfr_ktableworkq	 workq;
	struct pfr_ktable	*kt, *ktw;
	struct pf_anchor	*a;

	ACCEPT_FLAGS(t->pft_ioflags, PFR_FLAG_DUMMY | PFR_FLAG_ALLRSETS);

	SLIST_INIT(&workq);

	if (t->pft_ioflags & PFR_FLAG_ALLRSETS) {
		RB_FOREACH_SAFE(kt, pfr_ktablehead,
		    &pf_main_anchor.ktables, ktw) {
			if ((kt->pfrkt_flags & PFR_TFLAG_ACTIVE) == 0)
				continue;
			if ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0) {
				kt->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
				kt->pfrkt_flags |= ~PFR_TFLAG_INACTIVE;
				if (kt->pfrkt_refcnt == 0) {
					RB_REMOVE(pfr_ktablehead,
					    &pf_main_anchor.ktables, kt);
					SLIST_INSERT_HEAD(&t->pfttab_kt_garbage,
					    kt, pfrkt_workq);
					KASSERT(pf_main_anchor.tables > 0);
					pf_main_anchor.tables--;
				}
			}
			t->pfttab_ndel++;
			/*
			 * no further action needed for root tables.
			 */
		}

		RB_FOREACH(a, pf_anchor_global, &pf_anchors) {
			RB_FOREACH_SAFE(kt, pfr_ktablehead, &a->ktables, ktw) {
				if ((kt->pfrkt_flags & PFR_TFLAG_ACTIVE) == 0)
					continue;

				if ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0) {
					kt->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
					kt->pfrkt_flags |= ~PFR_TFLAG_INACTIVE;
					/*
					 * Detach kt from current anchor and
					 * try to promote table from current
					 * anchor to parent tree. If promotion
					 * fails (kt != NULL) then the table
					 * with the same name already exists in
					 * parent tree and kt can be destroyed.
					 */
					RB_REMOVE(pfr_ktablehead, &a->ktables,
					    kt);
					KASSERT(a->tables > 0);
					a->tables--;
					kt = pfr_promote_table(a, kt);
					if (kt != NULL) {
						SLIST_INSERT_HEAD(
						    &t->pfttab_kt_garbage, kt,
						    pfrkt_workq);
					}
				}
				t->pfttab_ndel++;
			}
		}
	} else {
		a = pf_lookup_anchor(&t->pfttab_anchor_key);
		if (a == NULL)
			return (ESRCH);
		RB_FOREACH_SAFE(kt, pfr_ktablehead, &a->ktables, ktw) {
			if (kt->pfrkt_flags & PFR_TFLAG_ACTIVE) {
				t->pfttab_ndel++;
				if ((t->pft_ioflags & PFR_FLAG_DUMMY) != 0)
					continue;
			
				kt->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
				kt->pfrkt_flags |= ~PFR_TFLAG_INACTIVE;
			}

			if (a != &pf_main_anchor) {
				/*
				 * Detach table from anchor and try to
				 * promote it to parent tree.
				 */
				RB_REMOVE(pfr_ktablehead, &a->ktables, kt);
				KASSERT(a->tables > 0);
				a->tables--;
				kt = pfr_promote_table(a, kt);
				if (kt != NULL) {
					SLIST_INSERT_HEAD(
					    &t->pfttab_kt_garbage, kt,
						    pfrkt_workq);
				}
			} else if (kt->pfrkt_refcnt == 0) {
				RB_REMOVE(pfr_ktablehead, &a->ktables, kt);
				KASSERT(a->tables > 0);
				a->tables--;
				SLIST_INSERT_HEAD(&t->pfttab_kt_garbage, kt,
				    pfrkt_workq);
			}
		}
	}

	return (0);
}

#ifdef DIAGNOSTIC
void
pfr_verify_tables(struct pf_anchor *a)
{
	int	got = 0;
	struct pfr_ktable *kt;

	RB_FOREACH(kt, pfr_ktablehead, &a->ktables) {
		got++;
	}

	log(LOG_DEBUG, "%s checking %s (%d)\n",
	    __func__,
	    a->path,
	    got);

	if (a->tables != got)
		panic("%s table count does not match in "
		    "%s, got: %d expected: %d",
		    __func__,
		    a->path,
		    got, a->tables);
}
#endif

int
pfr_get_tables(struct pf_trans *t)
{
	struct pfr_ktable	*p;
	int			 n, nn;
	struct pf_anchor	*a;
	struct pfr_table	*tbl = (struct pfr_table *)t->pfttab_kbuf;

	ACCEPT_FLAGS(t->pft_ioflags, PFR_FLAG_ALLRSETS);

	if ((t->pft_ioflags & PFR_FLAG_ALLRSETS) == 0) {
		a = pf_lookup_anchor(&t->pfttab_anchor_key);
		if (a == NULL)
			return (ENOENT);

		n = a->tables;
		nn = n;
		if (n > t->pfttab_size) {
			t->pfttab_size = n;
			return (0);
		}

#ifdef DIAGNOSTIC
		pfr_verify_tables(a);
#endif

		RB_FOREACH(p, pfr_ktablehead, &a->ktables) {
			if (n-- <= 0)
				continue;
			memcpy(tbl++, &p->pfrkt_t, sizeof(*tbl));
		}
	} else {
		n = pfr_table_count();
		if (n > t->pfttab_size) {
			t->pfttab_size = n;
			return (0);
		}

		nn = n;

		RB_FOREACH(p, pfr_ktablehead, &pf_main_anchor.ktables) {
			if (n-- <= 0) {
				log(LOG_DEBUG, "%s (/) n: %d: %s\n",
				    __func__, n, p->pfrkt_name);
				continue;
			} else
				log(LOG_DEBUG, "%s (/) n: %d: %s\n",
				    __func__, n, p->pfrkt_name);
			memcpy(tbl++, &p->pfrkt_t, sizeof(*tbl));
		}
		RB_FOREACH(a, pf_anchor_global, &pf_anchors) {
			RB_FOREACH(p, pfr_ktablehead, &a->ktables) {
				if (n-- <=0) {
					log(LOG_DEBUG, "%s (%s) n: %d: %s\n",
					    __func__, a->path, n,
					    p->pfrkt_name);
					continue;
				} else
					log(LOG_DEBUG, "%s (%s) n: %d: %s\n",
					    __func__, a->path, n,
					    p->pfrkt_name);
				memcpy(tbl++, &p->pfrkt_t, sizeof(*tbl));
			}
		}
	}

	if (n) {
		DPFPRINTF(LOG_ERR,
		    "pfr_get_tables: corruption detected at %s (%d).",
		    ((t->pft_ioflags & PFR_FLAG_ALLRSETS) == 0) ?
		    a->path : "*", n);
		return (ENOTTY);
	}
	t->pfttab_size = nn;

	return (0);
}

int
pfr_copyin_tables(struct pf_trans *t, struct pfr_table *tbl, int size)
{
	struct pfr_ktable	*kt, key;
	int			 i;
	time_t			 tzero = gettime();

	if (t->pft_type != PF_TRANS_TAB) {
		log(LOG_ERR, "%s expects PF_TRANS_TAB only\n", __func__);
		return (EINVAL);
	}
	for (i = 0; i < size; i++) {
		YIELD(1);
		if (COPYIN(tbl+i, &key.pfrkt_t, sizeof(key.pfrkt_t),
		    t->pft_ioflags))
			return (EFAULT);
		if (pfr_validate_table(&key.pfrkt_t, PFR_TFLAG_USRMASK,
		    t->pft_ioflags & PFR_FLAG_USERIOCTL))
			return (EINVAL);
		key.pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
		kt = pfr_create_ktable(&t->pfttab_rc, &key.pfrkt_t, tzero,
		    PR_WAITOK);
		if (kt == NULL)
			return (ENOMEM); /* when hitting a pool limit */
		kt->pfrkt_version = pfr_get_ktable_version(kt);
	}

	return (0);
}

int
pfr_get_tstats(struct pf_trans *t)
{
	struct pfr_ktable	*kt;
	int			 n, nn;
	time_t			 tzero = gettime();
	struct pfr_tstats	*tstats;
	struct pf_anchor	*a;
	int			 addrstoo =
	    t->pft_ioflags & PFR_FLAG_ADDRSTOO;

	/* XXX PFR_FLAG_CLSTATS disabled */
	ACCEPT_FLAGS(t->pft_ioflags, PFR_FLAG_ALLRSETS);

	tstats = (struct pfr_tstats *)t->pfttab_kbuf;
	if (t->pft_ioflags & PFR_FLAG_ALLRSETS) {

		n = nn = pfr_table_count();
		if (n == 0)
			return (ENOENT);
		if (n > t->pfttab_size) {
			t->pfttab_size = n;
			return (0);
		}

		RB_FOREACH(kt, pfr_ktablehead, &pf_main_anchor.ktables) {
			if (n-- <= 0)
				continue;
			memcpy(tstats++, &kt->pfrkt_ts,
			    sizeof(struct pfr_tstats));
			if (t->pft_ioflags & PFR_FLAG_CLSTATS)
				pfr_clstats_ktable(kt, tzero, addrstoo);
		}
		RB_FOREACH(a, pf_anchor_global, &pf_anchors) {
			RB_FOREACH(kt, pfr_ktablehead, &a->ktables) {
				if (n-- <= 0)
					continue;
				memcpy(tstats++, &kt->pfrkt_ts,
				    sizeof(struct pfr_tstats));
				if (t->pft_ioflags & PFR_FLAG_CLSTATS)
					pfr_clstats_ktable(kt, tzero, addrstoo);
			}
		}
	} else {
		a = pf_lookup_anchor(&t->pfttab_anchor_key);
		if (a == NULL)
			return (ESRCH);

		n = nn = a->tables;
		if (n == 0)
			return (ENOENT);
		if (n > t->pfttab_size) {
			t->pfttab_size = n;
			return (0);
		}

		RB_FOREACH(kt, pfr_ktablehead, &a->ktables) {
			if (n-- <= 0)
				continue;
			memcpy(tstats++, &kt->pfrkt_ts,
			    sizeof(struct pfr_tstats));
			if (t->pft_ioflags & PFR_FLAG_CLSTATS)
				pfr_clstats_ktable(kt, tzero, addrstoo);
		}
	}

	if (n) {
		DPFPRINTF(LOG_ERR,
		    "pfr_get_tstats: corruption detected (%d).", n);
		return (ENOTTY);
	}

	t->pfttab_size = nn;

	return (0);
}

void
pfr_update_tablerefs_anchor(struct pf_anchor *a, void *arg)
{
	struct pfr_ktable *kt = arg;
	struct pf_rule *r;

	TAILQ_FOREACH(r, a->ruleset.rules.ptr, entries) {
		if (r->src.addr.type == PF_ADDR_TABLE &&
		    r->src.addr.p.tbl != kt &&
		    PF_MATCH_KTABLE(&r->src.addr, kt)) {
			struct pfr_ktable *src_kt;

			src_kt = r->src.addr.p.tbl;
			src_kt->pfrkt_refcnt--;
			KASSERT(src_kt->pfrkt_refcnt >= 0);
			if (src_kt->pfrkt_refcnt == 0)
				src_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->src.addr.p.tbl = kt;
			kt->pfrkt_refcnt++;

			kt->pfrkt_flags |= PFR_TFLAG_REFERENCED;
			log(LOG_DEBUG, "%s %u@%s src %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    src_kt->pfrkt_name, src_kt->pfrkt_anchor);
		} else if (r->src.addr.type == PF_ADDR_TABLE &&
		    r->src.addr.p.tbl != NULL) {
			log(LOG_DEBUG, "%s %u@%s src %s@%s != %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    r->src.addr.p.tbl->pfrkt_name,
			    r->src.addr.p.tbl->pfrkt_anchor);
		}

		if (r->dst.addr.type == PF_ADDR_TABLE &&
		    r->dst.addr.p.tbl != kt &&
		    PF_MATCH_KTABLE(&r->dst.addr, kt)) {
			struct pfr_ktable *dst_kt;

			dst_kt = r->dst.addr.p.tbl;
			dst_kt->pfrkt_refcnt--;
			KASSERT(dst_kt->pfrkt_refcnt >= 0);
			if (dst_kt->pfrkt_refcnt == 0)
				dst_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->dst.addr.p.tbl = kt;
			kt->pfrkt_refcnt++;

			kt->pfrkt_flags |= PFR_TFLAG_REFERENCED;
			log(LOG_DEBUG, "%s %u@%s dst %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    dst_kt->pfrkt_name, dst_kt->pfrkt_anchor);
		} else if (r->dst.addr.type == PF_ADDR_TABLE &&
		    r->dst.addr.p.tbl != NULL) {
			log(LOG_DEBUG, "%s %u@%s dst %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    r->dst.addr.p.tbl->pfrkt_name,
			    r->dst.addr.p.tbl->pfrkt_anchor);
		}

		if (r->rdr.addr.type == PF_ADDR_TABLE &&
		    r->rdr.addr.p.tbl != kt &&
		    PF_MATCH_KTABLE(&r->rdr.addr, kt)) {
			struct pfr_ktable *rdr_kt;

			rdr_kt = r->rdr.addr.p.tbl;
			rdr_kt->pfrkt_refcnt--;
			KASSERT(rdr_kt->pfrkt_refcnt >= 0);
			if (rdr_kt->pfrkt_refcnt == 0)
				rdr_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->rdr.addr.p.tbl = kt;
			kt->pfrkt_refcnt++;

			kt->pfrkt_flags |= PFR_TFLAG_REFERENCED;

			log(LOG_DEBUG, "%s %u@%s rdr %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    rdr_kt->pfrkt_name, rdr_kt->pfrkt_anchor);
		} else if (r->rdr.addr.type == PF_ADDR_TABLE &&
		    r->rdr.addr.p.tbl != NULL) {
			log(LOG_DEBUG, "%s %u@%s rdr %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    r->rdr.addr.p.tbl->pfrkt_name,
			    r->rdr.addr.p.tbl->pfrkt_anchor);
		}

		if (r->nat.addr.type == PF_ADDR_TABLE &&
		    r->nat.addr.p.tbl != kt &&
		    PF_MATCH_KTABLE(&r->nat.addr, kt)) {
			struct pfr_ktable *nat_kt;

			nat_kt = r->nat.addr.p.tbl;
			nat_kt->pfrkt_refcnt--;
			KASSERT(nat_kt->pfrkt_refcnt >= 0);
			if (nat_kt->pfrkt_refcnt == 0)
				nat_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->nat.addr.p.tbl = kt;
			kt->pfrkt_refcnt++;

			kt->pfrkt_flags |= PFR_TFLAG_REFERENCED;

			log(LOG_DEBUG, "%s %u@%s nat %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    nat_kt->pfrkt_name, nat_kt->pfrkt_anchor);
		} else if (r->nat.addr.type == PF_ADDR_TABLE &&
		    r->nat.addr.p.tbl != NULL) {
			log(LOG_DEBUG, "%s %u@%s nat %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    r->nat.addr.p.tbl->pfrkt_name,
			    r->nat.addr.p.tbl->pfrkt_anchor);
		}

		if (r->route.addr.type == PF_ADDR_TABLE &&
		    r->route.addr.p.tbl != kt &&
		    PF_MATCH_KTABLE(&r->route.addr, kt)) {
			struct pfr_ktable *route_kt;

			route_kt = r->route.addr.p.tbl;
			route_kt->pfrkt_refcnt--;
			KASSERT(route_kt->pfrkt_refcnt >= 0);
			if (route_kt->pfrkt_refcnt == 0)
				route_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->route.addr.p.tbl = kt;
			kt->pfrkt_refcnt++;

			kt->pfrkt_flags |= PFR_TFLAG_REFERENCED;

			log(LOG_DEBUG, "%s %u@%s route %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    route_kt->pfrkt_name, route_kt->pfrkt_anchor);
		} else if (r->route.addr.type == PF_ADDR_TABLE &&
		    r->route.addr.p.tbl != NULL) {
			log(LOG_DEBUG, "%s %u@%s route %s@%s <-> %s@%s\n",
			    __func__,
			    r->nr, a->path,
			    kt->pfrkt_name, kt->pfrkt_anchor,
			    r->route.addr.p.tbl->pfrkt_name,
			    r->route.addr.p.tbl->pfrkt_anchor);
		}
	}
}

void
pfr_update_table_refs(struct pf_anchor *a)
{
	struct pfr_ktable *kt;

	RB_FOREACH(kt, pfr_ktablehead, &a->ktables) {
		pf_walk_anchor_subtree(a, kt, pfr_update_tablerefs_anchor);
	}
}

struct pfr_ktable *
pfr_find_parent_kt(struct pf_anchor *a, struct pfr_ktable *kt_key)
{
	struct pf_anchor *parent;
	struct pfr_ktable *kt = NULL;

	parent = a->parent;

	while ((parent != NULL) && (kt == NULL)) {
		kt = RB_FIND(pfr_ktablehead, &parent->ktables, kt_key);
		parent = parent->parent;
	}

	return (kt);
}

void
pfr_drop_tablerefs_anchor(struct pf_anchor *a, struct pfr_ktable *kt)
{
	struct pf_rule *r;
	struct pfr_ktable *parent_kt = NULL;
	struct pfr_ktable *kt_ref;

	/*
	 * If we can't find matching table in parent tree,
	 * then we let rule to refer to local table found
	 * in anchor where rule resides.
	 */
	TAILQ_FOREACH(r, a->ruleset.rules.ptr, entries) {
		if (r->src.addr.p.tbl == kt) {
			parent_kt = pfr_find_parent_kt(a, kt);
			if (parent_kt == NULL) {
				kt_ref = RB_FIND(pfr_ktablehead,
				    &a->ktables, kt);
			} else {
				kt_ref = parent_kt;
			}

			KASSERT(kt_ref != NULL);
			log(LOG_DEBUG, "%s linking src to %s@%s\n", __func__,
			    kt_ref->pfrkt_name, kt_ref->pfrkt_anchor);

			kt->pfrkt_refcnt--;
			KASSERT(kt->pfrkt_refcnt >= 0);
			if (kt->pfrkt_refcnt == 0)
				kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->src.addr.p.tbl = kt_ref;
			kt_ref->pfrkt_refcnt++;
			kt_ref->pfrkt_flags |= PFR_TFLAG_REFERENCED;

		}

		if (r->dst.addr.p.tbl == kt) {
			if (parent_kt == NULL)
				parent_kt = pfr_find_parent_kt(a, kt);
			if (parent_kt == NULL)
				kt_ref = RB_FIND(pfr_ktablehead,
				    &a->ktables, kt);
			else
				kt_ref = parent_kt;

			KASSERT(kt_ref != NULL);
			log(LOG_DEBUG, "%s linking dst to %s@%s\n", __func__,
			    kt_ref->pfrkt_name, kt_ref->pfrkt_anchor);

			kt->pfrkt_refcnt--;
			KASSERT(kt->pfrkt_refcnt >= 0);
			if (kt->pfrkt_refcnt == 0)
				kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->dst.addr.p.tbl = kt_ref;
			kt_ref->pfrkt_refcnt++;
			kt_ref->pfrkt_flags |= PFR_TFLAG_REFERENCED;
		}

		if (r->rdr.addr.p.tbl == kt) {
			if (parent_kt == NULL)
				parent_kt = pfr_find_parent_kt(a, kt);
			if (parent_kt == NULL)
				kt_ref = RB_FIND(pfr_ktablehead,
				    &a->ktables, kt);
			else
				kt_ref = parent_kt;

			KASSERT(kt_ref != NULL);
			log(LOG_DEBUG, "%s linking rdr to %s@%s\n", __func__,
			    kt_ref->pfrkt_name, kt_ref->pfrkt_anchor);

			kt->pfrkt_refcnt--;
			KASSERT(kt->pfrkt_refcnt >= 0);
			if (kt->pfrkt_refcnt == 0)
				kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->rdr.addr.p.tbl = kt_ref;
			kt_ref->pfrkt_refcnt++;
			kt_ref->pfrkt_flags |= PFR_TFLAG_REFERENCED;
		}

		if (r->nat.addr.p.tbl == kt) {
			if (parent_kt == NULL)
				parent_kt = pfr_find_parent_kt(a, kt);
			if (parent_kt == NULL)
				kt_ref = RB_FIND(pfr_ktablehead,
				    &a->ktables, kt);
			else
				kt_ref = parent_kt;

			KASSERT(kt_ref != NULL);
			log(LOG_DEBUG, "%s linking nat to %s@%s\n", __func__,
			    kt_ref->pfrkt_name, kt_ref->pfrkt_anchor);

			kt->pfrkt_refcnt--;
			KASSERT(kt->pfrkt_refcnt >= 0);
			if (kt->pfrkt_refcnt == 0)
				kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->nat.addr.p.tbl = kt_ref;
			kt_ref->pfrkt_refcnt++;
			kt_ref->pfrkt_flags |= PFR_TFLAG_REFERENCED;
		}

		if (r->route.addr.p.tbl == kt) {
			if (parent_kt == NULL)
				parent_kt = pfr_find_parent_kt(a, kt);
			if (parent_kt == NULL)
				kt_ref = RB_FIND(pfr_ktablehead,
				    &a->ktables, kt);
			else
				kt_ref = parent_kt;

			KASSERT(kt_ref != NULL);
			log(LOG_DEBUG, "%s linking route to %s@%s\n", __func__,
			    kt_ref->pfrkt_name, kt_ref->pfrkt_anchor);

			kt->pfrkt_refcnt--;
			KASSERT(kt->pfrkt_refcnt >= 0);
			if (kt->pfrkt_refcnt == 0)
				kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;

			r->route.addr.p.tbl = kt_ref;
			kt_ref->pfrkt_refcnt++;
			kt_ref->pfrkt_flags |= PFR_TFLAG_REFERENCED;
		}
	}
}

int
pfr_ina_define(struct pf_trans *t, struct pfr_table *tbl,
    struct pfr_addr *addr, int size, int *nadd, int *naddr, int flags)
{
	struct pfr_kentryworkq	 addrq;
	struct pfr_ktable	*kt, *kt_insert;
	struct pfr_kentry	*p;
	struct pfr_addr		 ad;
	struct pf_ruleset	*trs;
	struct pf_anchor	*ta;
	int			 i, rv, xadd = 0, xaddr = 0;

	ACCEPT_FLAGS(flags, PFR_FLAG_DUMMY | PFR_FLAG_ADDRSTOO);
	if (size && !(flags & PFR_FLAG_ADDRSTOO)) {
		log(LOG_DEBUG, "%s %s@%s %d %sPFR_FLAG_ADDRSTOO\n",
		    __func__, tbl->pfrt_name, tbl->pfrt_anchor,
		    size, (flags & PFR_FLAG_ADDRSTOO) ? "" : "!");
		return (EINVAL);
	}
	if (pfr_validate_table(tbl, PFR_TFLAG_USRMASK,
	    flags & PFR_FLAG_USERIOCTL)) {
		log(LOG_DEBUG, "%s pfr_validate_table() error\n",
		    __func__);
		return (EINVAL);
	}
	trs = pf_find_or_create_ruleset(&t->pftina_rc, tbl->pfrt_anchor);
	if (trs == NULL) {
		log(LOG_DEBUG, "%s trs is NULL\n", __func__);
		return (EBUSY);
	}
	if (trs->anchor == NULL)
		ta = &t->pftina_rc.main_anchor;
	else
		ta = trs->anchor;

	kt = RB_FIND(pfr_ktablehead, &ta->ktables, (struct pfr_ktable *)tbl);
	if (kt == NULL) {
		/*
		 * We've found ruleset where table should be attached already,
		 * so we will attach table ourselves.
		 */
		kt_insert = pfr_create_ktable(NULL, tbl, 0, PR_WAITOK);
		if (kt_insert == NULL)
			return (ENOMEM);

		log(LOG_DEBUG, "%s creating %s@%s\n", __func__,
		    tbl->pfrt_name, tbl->pfrt_anchor);
		kt_insert->pfrkt_rs = trs;
		kt_insert->pfrkt_version = pfr_get_ktable_version(kt_insert);
		/*
		 * Tables which are created on behalf of 'table' keyword
		 * are marked as active. so they can be reported by
		 * pfctl -sT
		 */
		kt_insert->pfrkt_flags |= PFR_TFLAG_ACTIVE;
		kt = kt_insert;
	} else {
		log(LOG_DEBUG, "%s found table %s@%s\n", __func__,
		    tbl->pfrt_name, tbl->pfrt_anchor);
		kt_insert = NULL;
		/*
		 * Note 1:
		 * former code was using shadow/pfrkt_shadow here. table
		 * bound to transaction works as shadow in fact.
		 *
		 * Note 2:
		 * consider file snippet as follows:
		 *	table <dup> { 1.2.3.4, 1.2.3.5 }
		 *	table <dup> { 1.2.3.6, 1.2.3.7 }
		 * loading pf.conf with definitions as above above will result 
		 * to table dup with addresses .6 and .7. This is how current
		 * (7.2) behaves.  To achieve the same behavior we just flush
		 * table here.
		 */
		pfr_enqueue_addrs(kt, &addrq, NULL, 0);
		pfr_clean_node_mask(kt, &addrq);
		pfr_destroy_kentries(&addrq);
		/*
		 * Make sure existing table gets ACTIVE flag set, because table
		 * is now instantiated by 'table' keyword.
		 */
		kt->pfrkt_flags |= PFR_TFLAG_ACTIVE;
		kt->pfrkt_version = pfr_get_ktable_version(kt);
	}

	/*
	 * also dealing with dummy flag is easy, all operations
	 * on transaction (pfr_ina_*())) are in fact dummy until
	 * we do 'COMMIT', so if pfctl runs in dummy mode we just
	 * avoid a commit operation and that's it.
	 *
	 * the transaction will be cleaned up with close on 
	 * /dev/pf
	 */
	for (i = 0; i < size; i++) {
		if (COPYIN(addr+i, &ad, sizeof(ad), flags)) {
			log(LOG_DEBUG,
			    "%s copyin(addr + %d...\n", __func__, i);
			senderr(EFAULT);
		}
		log(LOG_DEBUG, "%s (%d) %x\n", __func__, ad.pfra_af,
		    ad.pfra_ip4addr.s_addr);
		if (pfr_validate_addr(&ad)) {
			log(LOG_DEBUG, "%s pfr_validate_addr(%d)\n",
			    __func__, i);
			senderr(EINVAL);
		}
		if (pfr_lookup_addr(kt, &ad, 1) != NULL)
			continue;
		p = pfr_create_kentry(&ad, PR_WAITOK);
		if (pfr_route_kentry(kt, p)) {
			pfr_destroy_kentry(p);
			continue;
		}
		xaddr++;
		if (p->pfrke_type == PFRKE_COST)
			kt->pfrkt_refcntcost++;
		pfr_ktable_winfo_update(kt, p);
	}

	kt->pfrkt_cnt = (flags & PFR_FLAG_ADDRSTOO) ?  xaddr : NO_ADDRESSES;

	if (kt_insert != NULL) {

		kt = RB_INSERT(pfr_ktablehead, &ta->ktables, kt_insert);
		KASSERT(kt == NULL);
		ta->tables++;

		pf_walk_anchor_subtree(ta, kt_insert,
		    pfr_update_tablerefs_anchor);

		xadd++;
		kt_insert = NULL;
	}
	if (nadd != NULL)
		*nadd = xadd;
	if (naddr != NULL)
		*naddr = xaddr;
	return (0);
_bad:
	if (kt_insert != NULL) {
		log(LOG_DEBUG, "%s destroy on error (%s@%s(\n", __func__,
		    kt_insert->pfrkt_name, kt_insert->pfrkt_anchor);
		pfr_destroy_ktable(kt_insert, 1);
	}
	return (rv);
}

int
pfr_validate_table(struct pfr_table *tbl, int allowedflags, int no_reserved)
{
	int i;

	if (!tbl->pfrt_name[0]) {
		log(LOG_DEBUG, "%s empty name\n", __func__);
		return (-1);
	}
	if (no_reserved && !strcmp(tbl->pfrt_anchor, PF_RESERVED_ANCHOR)) {
		log(LOG_DEBUG, "%s reserved anchor %s\n",
		    __func__, tbl->pfrt_anchor);
		return (-1);
	}
	if (tbl->pfrt_name[PF_TABLE_NAME_SIZE-1]) {
		log(LOG_DEBUG, "%s table name too long\n", __func__);
		return (-1);
	}
	for (i = strlen(tbl->pfrt_name); i < PF_TABLE_NAME_SIZE; i++)
		if (tbl->pfrt_name[i]) {
			log(LOG_DEBUG, "%s non-zero padding in %s@%s\n",
			    __func__, tbl->pfrt_name, tbl->pfrt_anchor);
			return (-1);
		}
	if (pfr_fix_anchor(tbl->pfrt_anchor)) {
		log(LOG_DEBUG, "%s pfr_fix_anchor() error for %s\n",
		    __func__, tbl->pfrt_anchor);
		return (-1);
	}
	if (tbl->pfrt_flags & ~allowedflags) {
		log(LOG_DEBUG, "%s illegal flags in %s@%s %x\n",
		    __func__, tbl->pfrt_name, tbl->pfrt_anchor,
		    tbl->pfrt_flags & ~allowedflags);
		return (-1);
	}
	return (0);
}

/*
 * Rewrite anchors referenced by tables to remove slashes
 * and check for validity.
 */
int
pfr_fix_anchor(char *anchor)
{
	size_t siz = MAXPATHLEN;
	int i;

	if (anchor[0] == '/') {
		char *path;
		int off;

		path = anchor;
		off = 1;
		while (*++path == '/')
			off++;
		bcopy(path, anchor, siz - off);
		memset(anchor + siz - off, 0, off);
	}
	if (anchor[siz - 1])
		return (-1);
	for (i = strlen(anchor); i < siz; i++)
		if (anchor[i])
			return (-1);
	return (0);
}

int
pfr_table_count(void)
{
	int table_cnt;
	struct pf_anchor *a;

#ifdef DIAGNOSTIC
	pfr_verify_tables(&pf_main_anchor);
#endif
	table_cnt = pf_main_anchor.tables;
	RB_FOREACH(a, pf_anchor_global, &pf_anchors) {
#ifdef DIAGNOSTIC
		pfr_verify_tables(a);
#endif
		table_cnt += a->tables;
	}

	return (table_cnt);
}

void
pfr_insert_ktables(struct pf_rules_container *rc, struct pfr_ktableworkq *workq)
{
	struct pfr_ktable	*p;

	SLIST_FOREACH(p, workq, pfrkt_workq)
		pfr_insert_ktable(rc, p);
}

void
pfr_insert_ktable(struct pf_rules_container *rc, struct pfr_ktable *kt)
{
	struct pf_ruleset *rs;

	rs = pf_find_ruleset(rc, kt->pfrkt_anchor);
	RB_INSERT(pfr_ktablehead, &rs->anchor->ktables, kt);
	/* we should bump counter with commit */
}

void
pfr_clstats_ktables(struct pfr_ktableworkq *workq, time_t tzero, int recurse)
{
	struct pfr_ktable	*p;

	SLIST_FOREACH(p, workq, pfrkt_workq)
		pfr_clstats_ktable(p, tzero, recurse);
}

void
pfr_clstats_ktable(struct pfr_ktable *kt, time_t tzero, int recurse)
{
	struct pfr_kentryworkq	 addrq;

	if (recurse) {
		pfr_enqueue_addrs(kt, &addrq, NULL, 0);
		pfr_clstats_kentries(&addrq, tzero, 0);
	}
	bzero(kt->pfrkt_packets, sizeof(kt->pfrkt_packets));
	bzero(kt->pfrkt_bytes, sizeof(kt->pfrkt_bytes));
	kt->pfrkt_match = kt->pfrkt_nomatch = 0;
	kt->pfrkt_tzero = tzero;
}

struct pfr_ktable *
pfr_create_ktable(struct pf_rules_container *rc, struct pfr_table *tbl,
    time_t tzero, int wait)
{
	struct pfr_ktable	*kt_exists, *kt;
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	kt = pool_get(&pfr_ktable_pl, wait|PR_ZERO|PR_LIMITFAIL);
	if (kt == NULL) {
		log(LOG_DEBUG, "%s alloc failed for %s@%s\n", __func__,
		    tbl->pfrt_name, tbl->pfrt_anchor);
		return (NULL);
	}
	kt->pfrkt_t = *tbl;

	kt_exists = NULL;

	if (rc != NULL) {
		rs = pf_find_or_create_ruleset(rc, tbl->pfrt_anchor);
		if (rs == NULL) {
			pfr_destroy_ktable(kt, 0);
			return (NULL);
		}
		a = (rs->anchor == NULL) ? &rc->main_anchor : rs->anchor;
		kt->pfrkt_rs = rs;
		kt_exists = RB_INSERT(pfr_ktablehead, &a->ktables, kt);
		if (kt_exists != NULL) {
			pfr_destroy_ktable(kt, 0);
			kt = kt_exists;
		} else
			a->tables++;
	}

	if (kt_exists == NULL) {
		if (!rn_inithead((void **)&kt->pfrkt_ip4,
		    offsetof(struct sockaddr_in, sin_addr)) ||
		    !rn_inithead((void **)&kt->pfrkt_ip6,
		    offsetof(struct sockaddr_in6, sin6_addr))) {
			pfr_destroy_ktable(kt, 0);
			return (NULL);
		}
		kt->pfrkt_tzero = tzero;
		kt->pfrkt_refcntcost = 0;
		kt->pfrkt_gcdweight = 0;
		kt->pfrkt_maxweight = 1;
	}

	return (kt);
}

void
pfr_destroy_ktables(struct pfr_ktableworkq *workq, int flushaddr)
{
	struct pfr_ktable	*p;

	while ((p = SLIST_FIRST(workq)) != NULL) {
		SLIST_REMOVE_HEAD(workq, pfrkt_workq);
		pfr_destroy_ktable(p, flushaddr);
	}
}

void
pfr_destroy_ktables_aux(struct pfr_ktableworkq *auxq)
{
	struct pfr_ktable	*p;

	while ((p = SLIST_FIRST(auxq)) != NULL) {
		SLIST_REMOVE_HEAD(auxq, pfrkt_workq);
		KASSERT(p->pfrkt_rs == NULL);
		pfr_destroy_ktable(p, 0);
	}
}

void
pfr_destroy_ktable(struct pfr_ktable *kt, int flushaddr)
{
	struct pfr_kentryworkq	 addrq;

	log(LOG_DEBUG, "%s destroying %s@%s\n", __func__, kt->pfrkt_name,
	    kt->pfrkt_anchor);
	if (flushaddr) {
		pfr_enqueue_addrs(kt, &addrq, NULL, 0);
		pfr_clean_node_mask(kt, &addrq);
		pfr_destroy_kentries(&addrq);
	}
	if (kt->pfrkt_ip4 != NULL)
		free(kt->pfrkt_ip4, M_RTABLE, sizeof(*kt->pfrkt_ip4));
	if (kt->pfrkt_ip6 != NULL)
		free(kt->pfrkt_ip6, M_RTABLE, sizeof(*kt->pfrkt_ip6));
	pool_put(&pfr_ktable_pl, kt);
}

int
pfr_ktable_compare(struct pfr_ktable *p, struct pfr_ktable *q)
{
	return (strncmp(p->pfrkt_name, q->pfrkt_name, PF_TABLE_NAME_SIZE));
}

struct pfr_ktable *
pfr_lookup_table(struct pf_anchor *ac, struct pfr_table *tbl)
{
	/* struct pfr_ktable start like a struct pfr_table */
	return (RB_FIND(pfr_ktablehead, &ac->ktables,
	    (struct pfr_ktable *)tbl));
}

int
pfr_match_addr(struct pfr_ktable *kt, struct pf_addr *a, sa_family_t af)
{
	struct pfr_kentry	*ke = NULL;
	int			 match;

	ke = pfr_kentry_byaddr(kt, a, af, 0);

	match = (ke && !(ke->pfrke_flags & PFRKE_FLAG_NOT));
	if (match)
		kt->pfrkt_match++;
	else
		kt->pfrkt_nomatch++;

	return (match);
}

struct pfr_kentry *
pfr_kentry_byaddr(struct pfr_ktable *kt, struct pf_addr *a, sa_family_t af,
    int exact)
{
	struct pfr_kentry	*ke = NULL;
	struct sockaddr_in	 tmp4;
#ifdef INET6
	struct sockaddr_in6	 tmp6;
#endif /* INET6 */

	kt = pfr_ktable_select_active(kt);
	if (kt == NULL)
		return (0);

	switch (af) {
	case AF_INET:
		bzero(&tmp4, sizeof(tmp4));
		tmp4.sin_len = sizeof(tmp4);
		tmp4.sin_family = AF_INET;
		tmp4.sin_addr.s_addr = a->addr32[0];
		ke = (struct pfr_kentry *)rn_match(&tmp4, kt->pfrkt_ip4);
		break;
#ifdef INET6
	case AF_INET6:
		bzero(&tmp6, sizeof(tmp6));
		tmp6.sin6_len = sizeof(tmp6);
		tmp6.sin6_family = AF_INET6;
		bcopy(a, &tmp6.sin6_addr, sizeof(tmp6.sin6_addr));
		ke = (struct pfr_kentry *)rn_match(&tmp6, kt->pfrkt_ip6);
		break;
#endif /* INET6 */
	default:
		unhandled_af(af);
	}
	if (exact && ke && KENTRY_NETWORK(ke))
		ke = NULL;

	return (ke);
}

void
pfr_update_stats(struct pfr_ktable *kt, struct pf_addr *a, struct pf_pdesc *pd,
    int op, int notrule)
{
	struct pfr_kentry	*ke = NULL;
	struct sockaddr_in	 tmp4;
#ifdef INET6
	struct sockaddr_in6	 tmp6;
#endif /* INET6 */
	sa_family_t		 af = pd->af;
	u_int64_t		 len = pd->tot_len;
	int			 dir_idx = (pd->dir == PF_OUT);
	int			 op_idx;

	kt = pfr_ktable_select_active(kt);
	if (kt == NULL)
		return;

	switch (af) {
	case AF_INET:
		bzero(&tmp4, sizeof(tmp4));
		tmp4.sin_len = sizeof(tmp4);
		tmp4.sin_family = AF_INET;
		tmp4.sin_addr.s_addr = a->addr32[0];
		ke = (struct pfr_kentry *)rn_match(&tmp4, kt->pfrkt_ip4);
		break;
#ifdef INET6
	case AF_INET6:
		bzero(&tmp6, sizeof(tmp6));
		tmp6.sin6_len = sizeof(tmp6);
		tmp6.sin6_family = AF_INET6;
		bcopy(a, &tmp6.sin6_addr, sizeof(tmp6.sin6_addr));
		ke = (struct pfr_kentry *)rn_match(&tmp6, kt->pfrkt_ip6);
		break;
#endif /* INET6 */
	default:
		unhandled_af(af);
	}

	switch (op) {
	case PF_PASS:
		op_idx = PFR_OP_PASS;
		break;
	case PF_MATCH:
		op_idx = PFR_OP_MATCH;
		break;
	case PF_DROP:
		op_idx = PFR_OP_BLOCK;
		break;
	default:
		panic("unhandled op");
	}

	if ((ke == NULL || (ke->pfrke_flags & PFRKE_FLAG_NOT)) != notrule) {
		if (op_idx != PFR_OP_PASS)
			DPFPRINTF(LOG_DEBUG,
			    "pfr_update_stats: assertion failed.");
		op_idx = PFR_OP_XPASS;
	}
	kt->pfrkt_packets[dir_idx][op_idx]++;
	kt->pfrkt_bytes[dir_idx][op_idx] += len;
	if (ke != NULL && op_idx != PFR_OP_XPASS &&
	    (kt->pfrkt_flags & PFR_TFLAG_COUNTERS)) {
		if (ke->pfrke_counters == NULL)
			ke->pfrke_counters = pool_get(&pfr_kcounters_pl,
			    PR_NOWAIT | PR_ZERO);
		if (ke->pfrke_counters != NULL) {
			ke->pfrke_counters->pfrkc_packets[dir_idx][op_idx]++;
			ke->pfrke_counters->pfrkc_bytes[dir_idx][op_idx] += len;
		}
	}
}

struct pfr_ktable *
pfr_attach_table(struct pf_rules_container *rc, struct pf_ruleset *rs,
    char *name, int wait)
{
	struct pfr_ktable	*kt;
	struct pfr_table	 tbl;
	struct pf_anchor	*a;

	log(LOG_DEBUG, "%s %s@%s\n", __func__, name,
	    rs->anchor == NULL ? "" : rs->anchor->path);
	bzero(&tbl, sizeof(tbl));
	strlcpy(tbl.pfrt_name, name, sizeof(tbl.pfrt_name));
	strlcpy(tbl.pfrt_anchor,
	    rs->anchor == NULL ? "" : rs->anchor->path,
	    sizeof (tbl.pfrt_anchor));

	if (rs->anchor != NULL) {
		a = rs->anchor;
		do {
			kt = pfr_lookup_table(a, &tbl);
			a = a->parent;
		} while ((a != NULL) && (kt == NULL));
	} else
		kt = pfr_lookup_table(&rc->main_anchor, &tbl);

	if (kt == NULL) {
		/*
		 * Tables created on behalf of pfr_attach_table() are always
		 * kept in anchors where they are defined.
		 */
		kt = pfr_create_ktable(rc, &tbl, gettime(), wait);
		if (kt == NULL)
			return (NULL);
		/*
		 * We mark table as inactive if it is created on behalf of
		 * rule.
		 */
		kt->pfrkt_flags = PFR_TFLAG_REFERENCED;
		kt->pfrkt_flags = PFR_TFLAG_INACTIVE;
		kt->pfrkt_version = pfr_get_ktable_version(kt);
	}

	kt->pfrkt_refcnt++;

	return (kt);
}

void
pfr_detach_table(struct pfr_ktable *kt)
{
	/*
	 * Table will be purged with ioctl(). We can not afford
	 * to do expensive lookup for anchor which holds the table.
	 */
	KASSERT(kt->pfrkt_refcnt > 0);
	if (!--kt->pfrkt_refcnt)
		kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
}

int
pfr_islinklocal(sa_family_t af, struct pf_addr *addr)
{
#ifdef	INET6
	if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->v6))
		return (1);
#endif	/* INET6 */
	return (0);
}

int
pfr_pool_get(struct pf_pool *rpool, struct pf_addr **raddr,
    struct pf_addr **rmask, sa_family_t af)
{
	struct pfr_ktable	*kt;
	struct pfr_kentry	*ke, *ke2;
	struct pf_addr		*addr, *counter;
	union sockaddr_union	 mask;
	struct sockaddr_in	 tmp4;
#ifdef INET6
	struct sockaddr_in6	 tmp6;
#endif
	int			 startidx, idx = -1, loop = 0, use_counter = 0;

	switch (af) {
	case AF_INET:
		bzero(&tmp4, sizeof(tmp4));
		tmp4.sin_len = sizeof(tmp4);
		tmp4.sin_family = AF_INET;
		addr = (struct pf_addr *)&tmp4.sin_addr;
		break;
#ifdef	INET6
	case AF_INET6:
		bzero(&tmp6, sizeof(tmp6));
		tmp6.sin6_len = sizeof(tmp6);
		tmp6.sin6_family = AF_INET6;
		addr = (struct pf_addr *)&tmp6.sin6_addr;
		break;
#endif	/* INET6 */
	default:
		unhandled_af(af);
	}

	if (rpool->addr.type == PF_ADDR_TABLE)
		kt = rpool->addr.p.tbl;
	else if (rpool->addr.type == PF_ADDR_DYNIFTL)
		kt = rpool->addr.p.dyn->pfid_kt;
	else
		return (-1);
	kt = pfr_ktable_select_active(kt);
	if (kt == NULL)
		return (-1);

	counter = &rpool->counter;
	idx = rpool->tblidx;
	if (idx < 0 || idx >= kt->pfrkt_cnt)
		idx = 0;
	else
		use_counter = 1;
	startidx = idx;

 _next_block:
	if (loop && startidx == idx) {
		kt->pfrkt_nomatch++;
		return (1);
	}

	ke = pfr_kentry_byidx(kt, idx, af);
	if (ke == NULL) {
		/* we don't have this idx, try looping */
		if (loop || (ke = pfr_kentry_byidx(kt, 0, af)) == NULL) {
			kt->pfrkt_nomatch++;
			return (1);
		}
		idx = 0;
		loop++;
	}

	/* Get current weight for weighted round-robin */
	if (idx == 0 && use_counter == 1 && kt->pfrkt_refcntcost > 0) {
		rpool->curweight = rpool->curweight - kt->pfrkt_gcdweight;

		if (rpool->curweight < 1)
			rpool->curweight = kt->pfrkt_maxweight;
	}

	pfr_prepare_network(&pfr_mask, af, ke->pfrke_net);
	*raddr = SUNION2PF(&ke->pfrke_sa, af);
	*rmask = SUNION2PF(&pfr_mask, af);

	if (use_counter && !PF_AZERO(counter, af)) {
		/* is supplied address within block? */
		if (!pf_match_addr(0, *raddr, *rmask, counter, af)) {
			/* no, go to next block in table */
			idx++;
			use_counter = 0;
			goto _next_block;
		}
		pf_addrcpy(addr, counter, af);
	} else {
		/* use first address of block */
		pf_addrcpy(addr, *raddr, af);
	}

	if (!KENTRY_NETWORK(ke)) {
		/* this is a single IP address - no possible nested block */
		if (rpool->addr.type == PF_ADDR_DYNIFTL &&
		    pfr_islinklocal(af, addr)) {
			idx++;
			goto _next_block;
		}
		pf_addrcpy(counter, addr, af);
		rpool->tblidx = idx;
		kt->pfrkt_match++;
		rpool->states = 0;
		if (ke->pfrke_counters != NULL)
			rpool->states = ke->pfrke_counters->states;
		switch (ke->pfrke_type) {
		case PFRKE_COST:
			rpool->weight = ((struct pfr_kentry_cost *)ke)->weight;
			/* FALLTHROUGH */
		case PFRKE_ROUTE:
			rpool->kif = ((struct pfr_kentry_route *)ke)->kif;
			break;
		default:
			rpool->weight = 1;
			break;
		}
		return (0);
	}
	for (;;) {
		/* we don't want to use a nested block */
		switch (af) {
		case AF_INET:
			ke2 = (struct pfr_kentry *)rn_match(&tmp4,
			    kt->pfrkt_ip4);
			break;
#ifdef	INET6
		case AF_INET6:
			ke2 = (struct pfr_kentry *)rn_match(&tmp6,
			    kt->pfrkt_ip6);
			break;
#endif	/* INET6 */
		default:
			unhandled_af(af);
		}
		if (ke2 == ke) {
			/* lookup return the same block - perfect */
			if (rpool->addr.type == PF_ADDR_DYNIFTL &&
			    pfr_islinklocal(af, addr))
				goto _next_entry;
			pf_addrcpy(counter, addr, af);
			rpool->tblidx = idx;
			kt->pfrkt_match++;
			rpool->states = 0;
			if (ke->pfrke_counters != NULL)
				rpool->states = ke->pfrke_counters->states;
			switch (ke->pfrke_type) {
			case PFRKE_COST:
				rpool->weight =
				    ((struct pfr_kentry_cost *)ke)->weight;
				/* FALLTHROUGH */
			case PFRKE_ROUTE:
				rpool->kif = ((struct pfr_kentry_route *)ke)->kif;
				break;
			default:
				rpool->weight = 1;
				break;
			}
			return (0);
		}
_next_entry:
		/* we need to increase the counter past the nested block */
		pfr_prepare_network(&mask, AF_INET, ke2->pfrke_net);
		pf_poolmask(addr, addr, SUNION2PF(&mask, af), &pfr_ffaddr, af);
		pf_addr_inc(addr, af);
		if (!pf_match_addr(0, *raddr, *rmask, addr, af)) {
			/* ok, we reached the end of our main block */
			/* go to next block in table */
			idx++;
			use_counter = 0;
			goto _next_block;
		}
	}
}

struct pfr_kentry *
pfr_kentry_byidx(struct pfr_ktable *kt, int idx, int af)
{
	struct pfr_walktree	w;

	bzero(&w, sizeof(w));
	w.pfrw_op = PFRW_POOL_GET;
	w.pfrw_cnt = idx;

	switch (af) {
	case AF_INET:
		rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w);
		return (w.pfrw_kentry);
#ifdef INET6
	case AF_INET6:
		rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w);
		return (w.pfrw_kentry);
#endif /* INET6 */
	default:
		return (NULL);
	}
}

/* Added for load balancing state counter use. */
int
pfr_states_increase(struct pfr_ktable *kt, struct pf_addr *addr, int af)
{
	struct pfr_kentry *ke;

	ke = pfr_kentry_byaddr(kt, addr, af, 1);
	if (ke == NULL)
		return (-1);

	if (ke->pfrke_counters == NULL)
		ke->pfrke_counters = pool_get(&pfr_kcounters_pl,
		    PR_NOWAIT | PR_ZERO);
	if (ke->pfrke_counters == NULL)
		return (-1);

	ke->pfrke_counters->states++;
	return ke->pfrke_counters->states;
}

/* Added for load balancing state counter use. */
int
pfr_states_decrease(struct pfr_ktable *kt, struct pf_addr *addr, int af)
{
	struct pfr_kentry *ke;

	ke = pfr_kentry_byaddr(kt, addr, af, 1);
	if (ke == NULL)
		return (-1);

	if (ke->pfrke_counters == NULL)
		ke->pfrke_counters = pool_get(&pfr_kcounters_pl,
		    PR_NOWAIT | PR_ZERO);
	if (ke->pfrke_counters == NULL)
		return (-1);

	if (ke->pfrke_counters->states > 0)
		ke->pfrke_counters->states--;
	else
		DPFPRINTF(LOG_DEBUG,
		    "pfr_states_decrease: states-- when states <= 0");

	return ke->pfrke_counters->states;
}

void
pfr_dynaddr_update(struct pfr_ktable *kt, struct pfi_dynaddr *dyn)
{
	struct pfr_walktree	w;

	bzero(&w, sizeof(w));
	w.pfrw_op = PFRW_DYNADDR_UPDATE;
	w.pfrw_dyn = dyn;

	dyn->pfid_acnt4 = 0;
	dyn->pfid_acnt6 = 0;
	switch (dyn->pfid_af) {
	case AF_UNSPEC:	/* look up all both addresses IPv4 + IPv6 */
		rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w);
		rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w);
		break;
	case AF_INET:
		rn_walktree(kt->pfrkt_ip4, pfr_walktree, &w);
		break;
#ifdef	INET6
	case AF_INET6:
		rn_walktree(kt->pfrkt_ip6, pfr_walktree, &w);
		break;
#endif	/* INET6 */
	default:
		unhandled_af(dyn->pfid_af);
	}
}

void
pfr_ktable_winfo_update(struct pfr_ktable *kt, struct pfr_kentry *p) {
	/*
	 * If cost flag is set,
	 * gcdweight is needed for round-robin.
	 */
	if (kt->pfrkt_refcntcost > 0) {
		u_int16_t weight;

		weight = (p->pfrke_type == PFRKE_COST) ?
		    ((struct pfr_kentry_cost *)p)->weight : 1;

		if (kt->pfrkt_gcdweight == 0)
			kt->pfrkt_gcdweight = weight;

		kt->pfrkt_gcdweight =
			pfr_gcd(weight, kt->pfrkt_gcdweight);

		if (kt->pfrkt_maxweight < weight)
			kt->pfrkt_maxweight = weight;
	}
}

struct pfr_ktable *
pfr_ktable_select_active(struct pfr_ktable *kt)
{
	if (!(kt->pfrkt_flags & PFR_TFLAG_ACTIVE))
		return (NULL);

	return (kt);
}

u_int32_t
pfr_get_ktable_version(struct pfr_ktable *ktt)
{
	struct pfr_ktable	*kt;
	u_int32_t		 version;
	struct pf_ruleset	*rs;
	struct pf_anchor	*a;

	NET_LOCK();
	PF_LOCK();
	/*
	 * XXX: never use pf_find_ruleset() under netlock
	 */
	rs = pf_find_ruleset(&pf_global, ktt->pfrkt_anchor);
	if (rs == NULL) {
		PF_UNLOCK();
		NET_UNLOCK();
		KASSERT(ktt->pfrkt_rs->rules.version == 0);
		return (0);
	}

	if (rs->anchor == NULL)
		a = &pf_main_anchor;
	else
		a = rs->anchor;

	kt = pfr_lookup_table(a, (struct pfr_table *)ktt);
	if (kt != NULL)
		version = kt->pfrkt_version;
	else
		version = 0;
	PF_UNLOCK();
	NET_UNLOCK();
	log(LOG_ERR, "%s found for %s@%s, version: %d\n",
	    __func__, ktt->pfrkt_name, ktt->pfrkt_anchor, version);

	return (version);
}

void
pfr_addtables_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable *kt, *ktw, *exists;

	RB_FOREACH_SAFE(kt, pfr_ktablehead, &ta->ktables, ktw) {
		RB_REMOVE(pfr_ktablehead, &ta->ktables, kt);
		ta->tables--;
		if (t->pft_ioflags & PFR_FLAG_DUMMY) {
			exists = RB_FIND(pfr_ktablehead, &a->ktables, kt);
			if (exists == NULL)
				t->pfttab_nadd++;
			/*
			 * force kt to be always moved to garbage qieie
			 * when running in dry/dummy mode.
			 */
			exists = kt;
		} else {
			exists = RB_INSERT(pfr_ktablehead, &a->ktables, kt);
			if (exists == NULL) {
				t->pfttab_nadd++;
				a->tables++;
			}
		}

		if (exists == NULL) {
			kt->pfrkt_flags |= PFR_TFLAG_ACTIVE;
			kt->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
			KASSERT(kt->pfrkt_version == 0);
			pf_walk_anchor_subtree(a, (void *)kt,
			    pfr_update_tablerefs_anchor);
			kt->pfrkt_version++;
		} else
			SLIST_INSERT_HEAD(&t->pfttab_kt_garbage, kt,
			    pfrkt_workq);
	}
}

void
pfr_deltables_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable *kt_ta, *kt_a;

	RB_FOREACH(kt_ta, pfr_ktablehead, &ta->ktables) {
		kt_a = RB_FIND(pfr_ktablehead, &a->ktables, kt_ta);
		KASSERT(kt_a != NULL);

		if (kt_a->pfrkt_flags & PFR_TFLAG_ACTIVE)
			t->pfttab_ndel++;

		if (t->pft_ioflags & PFR_FLAG_DUMMY)
			continue;

		kt_a->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
		kt_a->pfrkt_flags |= PFR_TFLAG_INACTIVE;

		if (a == &pf_main_anchor) {
			if (kt_a->pfrkt_refcnt == 0) {
				RB_REMOVE(pfr_ktablehead, &a->ktables, kt_a);
				SLIST_INSERT_HEAD(&t->pfttab_kt_garbage, kt_a,
				    pfrkt_workq);
				KASSERT(a->tables > 0);
				a->tables--;
			}
		} else {
			RB_REMOVE(pfr_ktablehead, &a->ktables, kt_a);
			KASSERT(a->tables > 0);
			a->tables--;
			kt_a = pfr_promote_table(a, kt_a);
			if (kt_a != NULL)
				SLIST_INSERT_HEAD(&t->pfttab_kt_garbage, kt_a,
				    pfrkt_workq);
		}
	}
}

void
pfr_clrtstats_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable *kt_ta, *kt_a;
	time_t tzero = gettime();

	RB_FOREACH(kt_ta, pfr_ktablehead, &ta->ktables) {
		if (kt_ta->pfrkt_version == 0)
			continue;
		kt_a = RB_FIND(pfr_ktablehead, &a->ktables, kt_ta);
		KASSERT(kt_a != NULL);
		if ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0)
			pfr_clstats_ktable(kt_a, tzero,
			    t->pft_ioflags & PFR_FLAG_ADDRSTOO);
		t->pfttab_nzero++;
	}
}

void
pfr_settflags_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable *kt_ta, *kt_a;
	int current_flags, new_flags;

	RB_FOREACH(kt_ta, pfr_ktablehead, &ta->ktables) {
		if (kt_ta->pfrkt_version == 0)
			continue;
		kt_a = RB_FIND(pfr_ktablehead, &a->ktables, kt_ta);
		KASSERT(kt_a != NULL);
		current_flags = kt_a->pfrkt_flags;
		new_flags = (kt_a->pfrkt_flags | t->pfttab_setf);
		new_flags &= ~t->pfttab_clrf;

		if ((current_flags & PFR_TFLAG_PERSIST) == 0 &&
		    (new_flags & PFR_TFLAG_PERSIST)  == 0 &&
		    (new_flags & PFR_TFLAG_REFERENCED) == 0)
			t->pfttab_ndel++;
		else
			t->pfttab_nchg++;

		if (t->pft_ioflags & PFR_FLAG_DUMMY)
			continue;

		kt_a->pfrkt_flags = new_flags;
		kt_a->pfrkt_version++;
		if (kt_a->pfrkt_flags &
		    (PFR_TFLAG_PERSIST|PFR_TFLAG_CONST|PFR_TFLAG_REFERENCED))
			continue;

		KASSERT(kt_a->pfrkt_refcnt == 0);

		RB_REMOVE(pfr_ktablehead, &a->ktables, kt_a);
		SLIST_INSERT_HEAD(&t->pfttab_kt_garbage, kt_a, pfrkt_workq);
	}
}

void
pfr_deladdrs_commit(struct pf_trans *t, struct pf_anchor *ta, struct pf_anchor *a)
{
	struct pfr_ktable *ktt, *kt;
	struct pfr_kentry *ket, *ke;
	int i, lg;

	KASSERT(ta->tables == 1);
	ktt = RB_ROOT(&ta->ktables);

	kt = RB_FIND(pfr_ktablehead, &a->ktables, ktt);
	KASSERT(kt != NULL);
	KASSERT(kt->pfrkt_version == ktt->pfrkt_version);

	/*
	 * there are two algorithms to choose from here.
	 * with:
	 *   n: number of addresses to delete
	 *   N: number of addresses in the table
	 *
	 * one is O(N) and is better for large 'n'
	 * one is O(n*LOG(N)) and is better for small 'n'
	 *
	 * following code try to decide which one is best.
	 */
	lg = 1;
	for (i = kt->pfrkt_cnt; i > 0; i >>= 1)
		lg++;
	if (t->pfttab_ke_ioq_len > kt->pfrkt_cnt/lg) {
		/* full table scan */
		pfr_mark_addrs(kt);
	} else {
		/* iterate over addresses to delete */
		SLIST_FOREACH(ket, &t->pfttab_ke_ioq, pfrke_ioq) {
			if (ket->pfrke_fb == PFR_FB_DUPLICATE)
				continue;

			ke = pfr_lookup_kentry(kt, ket, 1);
			if (ke != NULL)
				ke->pfrke_flags &= PFRKE_FLAG_MARK;
		}
	}

	SLIST_FOREACH(ket, &t->pfttab_ke_ioq, pfrke_ioq) {
		if (ket->pfrke_fb == PFR_FB_DUPLICATE)
			continue;

		ke = pfr_lookup_kentry(kt, ket, 1);
		if (ke == NULL)
			ket->pfrke_fb = PFR_FB_NONE;
		else if ((ke->pfrke_flags & PFRKE_FLAG_NOT) !=
		    (ket->pfrke_flags & PFRKE_FLAG_NOT))
			ket->pfrke_fb = PFR_FB_CONFLICT;
		else if (t->pft_ioflags & PFR_FLAG_DUMMY) {
			ket->pfrke_fb = PFR_FB_DELETED;
			t->pfttab_ndel++;
		} else {
			SLIST_INSERT_HEAD(&t->pfttab_ke_garbage, ke,
			    pfrke_workq);
			pfr_unroute_kentry(kt, ke);
			kt->pfrkt_cnt--;
			ket->pfrke_fb = PFR_FB_DELETED;
			t->pfttab_ndel++;
		}
	}

	if ((t->pfttab_ndel != 0) && ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0))
		kt->pfrkt_version++;
}

void
pfr_setaddrs_commit(struct pf_trans *t, struct pf_anchor *ta, struct pf_anchor *a)
{
	struct pfr_ktable *ktt, *kt;
	struct pfr_kentry *ket, *exists;
	struct pfr_kentryworkq changeq, addrq;
	time_t tzero = gettime();
	int e;

	KASSERT(ta->tables == 1);
	ktt = RB_ROOT(&ta->ktables);

	kt = RB_FIND(pfr_ktablehead, &a->ktables, ktt);
	KASSERT(kt != NULL);
	KASSERT(kt->pfrkt_version == ktt->pfrkt_version);

	SLIST_INIT(&changeq);
	SLIST_INIT(&addrq);

	pfr_mark_addrs(kt);

	SLIST_FOREACH(ket, &t->pfttab_ke_ioq, pfrke_ioq) {
		if (ket->pfrke_fb == PFR_FB_DUPLICATE)
			continue;

		exists = pfr_lookup_kentry(kt, ket, 1);
		if (exists != NULL) {
			exists->pfrke_flags |= PFRKE_FLAG_MARK;
			if ((exists->pfrke_flags & PFRKE_FLAG_NOT) !=
			    (ket->pfrke_flags & PFRKE_FLAG_NOT)) {
				ket->pfrke_fb = PFR_FB_CHANGED;
				t->pfttab_nchg++;
				SLIST_INSERT_HEAD(&changeq, exists,
				    pfrke_workq);
			}
		} else {
			pfr_kentry_kif_ref(ket);
			ket->pfrke_fb = PFR_FB_ADDED;
			t->pfttab_nadd++;
		}
	}

	pfr_enqueue_addrs(kt, &t->pfttab_ke_garbage, &t->pfttab_ndel,
	    ENQUEUE_UNMARKED_ONLY);

	if ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0) {
		/* add kentries */
		SLIST_FOREACH(ket, &t->pfttab_ke_ioq, pfrke_ioq) {
			if (ket->pfrke_fb != PFR_FB_ADDED)
				continue;

			e = pfr_route_kentry(kt, ket);
			if (e != 0) {
				ket->pfrke_fb = PFR_FB_NONE;
				t->pfttab_nadd--;
				log(LOG_ERR,
				    "%s cannot route entry (code=%d)\n",
				    __func__, e);
			} else {
				kt->pfrkt_cnt++;
				if (ket->pfrke_type == PFRKE_COST)
					kt->pfrkt_refcntcost++;
				pfr_ktable_winfo_update(kt, ket);
				kt->pfrkt_tzero = tzero;
			}
		}

		/* remove kentries (just unroute them) */
		SLIST_FOREACH(ket, &t->pfttab_ke_garbage, pfrke_workq) {
			pfr_unroute_kentry(kt, ket);
			ket->pfrke_fb = PFR_FB_DELETED;
			kt->pfrkt_cnt--;
			if (ket->pfrke_type == PFRKE_COST)
				kt->pfrkt_refcntcost--;
		}
		if (kt->pfrkt_refcntcost > 0) {
			kt->pfrkt_gcdweight = 0;
			kt->pfrkt_maxweight = 1;
			pfr_enqueue_addrs(kt, &addrq, NULL, 0);
			SLIST_FOREACH(ket, &addrq, pfrke_workq)
				pfr_ktable_winfo_update(kt, ket);
		}

		/* change kentries */
		SLIST_FOREACH(ket, &changeq, pfrke_workq) {
			ket->pfrke_flags ^= PFRKE_FLAG_NOT;
			if (ket->pfrke_counters) {
				pool_put(&pfr_kcounters_pl, ket->pfrke_counters);
				ket->pfrke_counters = NULL;
			}
			kt->pfrkt_tzero = tzero;
		}
	}
}

void
pfr_clraddrs_commit(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktable	*kt, *ktt;
	struct pfr_kentryworkq	 workq;

	KASSERT(ta->tables == 1);
	ktt = RB_ROOT(&ta->ktables);
	if (ktt->pfrkt_version == 0)
		return;

	kt = RB_FIND(pfr_ktablehead, &a->ktables, ktt);
	if (kt == NULL)
		return;

	KASSERT(kt->pfrkt_version == ktt->pfrkt_version);

	SLIST_INIT(&workq);
	pfr_enqueue_addrs(kt, &workq, &t->pfttab_ndel, 0);

	if ((t->pft_ioflags & PFR_FLAG_DUMMY) == 0) {
		pfr_remove_kentries(kt, &workq);
		if (kt->pfrkt_cnt) {
			DPFPRINTF(LOG_NOTICE,
			    "pfr_clr_addrs: corruption detected (%d).",
			    kt->pfrkt_cnt);
			kt->pfrkt_cnt = 0;
		}
	}
}
