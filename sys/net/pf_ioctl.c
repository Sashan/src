/*	$OpenBSD: pf_ioctl.c,v 1.415 2023/07/06 04:55:05 dlg Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2018 Henning Brauer <henning@openbsd.org>
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
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include "pfsync.h"
#include "pflog.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/time.h>
#include <sys/timeout.h>
#include <sys/pool.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/syslog.h>
#include <sys/specdev.h>
#include <uvm/uvm_extern.h>

#include <crypto/md5.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/hfsc.h>
#include <net/fq_codel.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif /* INET6 */

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

#if NPFSYNC > 0
#include <netinet/ip_ipsp.h>
#include <net/if_pfsync.h>
#endif /* NPFSYNC > 0 */

struct pool		 pf_tag_pl;

void			 pfattach(int);
void			 pf_thread_create(void *);
int			 pfopen(dev_t, int, int, struct proc *);
int			 pfclose(dev_t, int, int, struct proc *);
int			 pfioctl(dev_t, u_long, caddr_t, int, struct proc *);
int			 pf_begin_rules(struct pf_trans *, const char *);
void			 pf_rollback_rules(u_int32_t, char *);
void			 pf_remove_queues(void);
int			 pf_commit_queues(void);
void			 pf_free_queues(struct pf_queuehead *);
void			 pf_calc_chksum(struct pf_ruleset *);
void			 pf_hash_rule(MD5_CTX *, struct pf_rule *);
void			 pf_hash_rule_addr(MD5_CTX *, struct pf_rule_addr *);
int			 pf_commit_rules(u_int32_t, char *);
int			 pf_addr_setup(struct pf_trans *t, struct pf_ruleset *,
			    struct pf_addr_wrap *, sa_family_t);
struct pfi_kif		*pf_kif_setup(struct pfi_kif *);
void			 pf_addr_copyout(struct pf_addr_wrap *);
void			 pf_trans_set_commit(struct pf_opts *);
void			 pf_pool_copyin(struct pf_pool *, struct pf_pool *);
int			 pf_validate_range(u_int8_t, u_int16_t[2], int);
int			 pf_rule_copyin(struct pf_rule *, struct pf_rule *);
int			 pf_rule_checkaf(struct pf_rule *);
u_int16_t		 pf_qname2qid(char *, int);
void			 pf_qid2qname(u_int16_t, char *);
void			 pf_qid_unref(u_int16_t);
int			 pf_states_clr(struct pfioc_state_kill *);
int			 pf_states_get(struct pfioc_states *);

struct pf_trans		*pf_open_trans(uint32_t);
struct pf_trans		*pf_find_trans(uint32_t, uint64_t);
void			 pf_free_trans(struct pf_trans *);
void			 pf_rollback_trans(struct pf_trans *);
void			 pf_commit_trans(struct pf_trans *);

void			 pf_init_tgetrule(struct pf_trans *,
			    struct pf_anchor *, uint32_t, struct pf_rule *);
void			 pf_cleanup_tgetrule(struct pf_trans *t);

struct pf_rule		 pf_default_rule, pf_default_rule_new;


void			 pf_init_tina(struct pf_trans *);
void			 pf_cleanup_tina(struct pf_trans *);
void			 pf_swap_anchors(struct pf_trans *, struct pf_anchor *,
			    struct pf_anchor *);
int			 pf_trans_in_conflict(struct pf_trans *, const char *);
int			 pf_ina_check(struct pf_anchor *, struct pf_anchor *);
void			 pf_ina_commit(struct pf_trans *);

void			 pf_init_ttab(struct pf_trans *);
int			 pf_tab_check(struct pf_anchor *, struct pf_anchor *);
void			 pf_cleanup_ttab(struct pf_trans *);
void			 pf_tab_commit(struct pf_trans *);

struct pf_rule		 pf_default_rule;
uint32_t		 pf_default_vers = 1;

#define	TAGID_MAX	 50000
TAILQ_HEAD(pf_tags, pf_tagname)	pf_tags = TAILQ_HEAD_INITIALIZER(pf_tags),
				pf_qids = TAILQ_HEAD_INITIALIZER(pf_qids);

/*
 * pf_lock protects consistency of PF data structures, which don't have
 * their dedicated lock yet. The pf_lock currently protects:
 *	- rules,
 *	- radix tables,
 *	- source nodes
 * All callers must grab pf_lock exclusively.
 *
 * pf_state_lock protects consistency of state table. Packets, which do state
 * look up grab the lock as readers. If packet must create state, then it must
 * grab the lock as writer. Whenever packet creates state it grabs pf_lock
 * first then it locks pf_state_lock as the writer.
 */
struct rwlock		 pf_lock = RWLOCK_INITIALIZER("pf_lock");
struct rwlock		 pf_state_lock = RWLOCK_INITIALIZER("pf_state_lock");
struct rwlock		 pfioctl_rw = RWLOCK_INITIALIZER("pfioctl_rw");

struct cpumem *pf_anchor_stack;

#if (PF_QNAME_SIZE != PF_TAG_NAME_SIZE)
#error PF_QNAME_SIZE must be equal to PF_TAG_NAME_SIZE
#endif
u_int16_t		 tagname2tag(struct pf_tags *, char *, int);
void			 tag2tagname(struct pf_tags *, u_int16_t, char *);
void			 tag_unref(struct pf_tags *, u_int16_t);
int			 pf_rtlabel_add(struct pf_addr_wrap *);
void			 pf_rtlabel_remove(struct pf_addr_wrap *);
void			 pf_rtlabel_copyout(struct pf_addr_wrap *);

LIST_HEAD(, pf_trans)	pf_ioctl_trans = LIST_HEAD_INITIALIZER(pf_trans);

#define PF_ANCHOR_PATH(_a_)	\
	(((_a_)->path[0] == '\0') ? "/" : (_a_)->path)

/* counts transactions opened by a device */
unsigned int pf_tcount[CLONE_MAPSZ * NBBY];
#define pf_unit2idx(_unit_)	((_unit_) >> CLONE_SHIFT)

void
pfattach(int num)
{
	u_int32_t *timeout = pf_default_rule.timeout;
	struct pf_anchor_stackframe *sf;
	struct cpumem_iter cmi;

	pool_init(&pf_rule_pl, sizeof(struct pf_rule), 0,
	    IPL_SOFTNET, 0, "pfrule", NULL);
	pool_init(&pf_src_tree_pl, sizeof(struct pf_src_node), 0,
	    IPL_SOFTNET, 0, "pfsrctr", NULL);
	pool_init(&pf_sn_item_pl, sizeof(struct pf_sn_item), 0,
	    IPL_SOFTNET, 0, "pfsnitem", NULL);
	pool_init(&pf_state_pl, sizeof(struct pf_state), 0,
	    IPL_SOFTNET, 0, "pfstate", NULL);
	pool_init(&pf_state_key_pl, sizeof(struct pf_state_key), 0,
	    IPL_SOFTNET, 0, "pfstkey", NULL);
	pool_init(&pf_state_item_pl, sizeof(struct pf_state_item), 0,
	    IPL_SOFTNET, 0, "pfstitem", NULL);
	pool_init(&pf_rule_item_pl, sizeof(struct pf_rule_item), 0,
	    IPL_SOFTNET, 0, "pfruleitem", NULL);
	pool_init(&pf_queue_pl, sizeof(struct pf_queuespec), 0,
	    IPL_SOFTNET, 0, "pfqueue", NULL);
	pool_init(&pf_tag_pl, sizeof(struct pf_tagname), 0,
	    IPL_SOFTNET, 0, "pftag", NULL);
	pool_init(&pf_pktdelay_pl, sizeof(struct pf_pktdelay), 0,
	    IPL_SOFTNET, 0, "pfpktdelay", NULL);
	pool_init(&pf_anchor_pl, sizeof(struct pf_anchor), 0,
	    IPL_SOFTNET, 0, "pfanchor", NULL);

	hfsc_initialize();
	pfr_initialize();
	pfi_initialize();
	pf_osfp_initialize();
	pf_syncookies_init();

	pool_sethardlimit(pf_pool_limits[PF_LIMIT_STATES].pp,
	    pf_pool_limits[PF_LIMIT_STATES].limit, NULL, 0);
	pool_sethardlimit(pf_pool_limits[PF_LIMIT_ANCHORS].pp,
	    pf_pool_limits[PF_LIMIT_ANCHORS].limit, NULL, 0);

	if (physmem <= atop(100*1024*1024))
		pf_pool_limits[PF_LIMIT_TABLE_ENTRIES].limit =
		    PFR_KENTRY_HIWAT_SMALL;

	RB_INIT(&tree_src_tracking);
	RB_INIT(&pf_anchors);
	pf_init_ruleset(&pf_main_ruleset);
	TAILQ_INIT(&pf_queues[0]);
	TAILQ_INIT(&pf_queues[1]);
	pf_queues_active = &pf_queues[0];
	pf_queues_inactive = &pf_queues[1];

	/* default rule should never be garbage collected */
	pf_default_rule.entries.tqe_prev = &pf_default_rule.entries.tqe_next;
	pf_default_rule.action = PF_PASS;
	pf_default_rule.nr = (u_int32_t)-1;
	pf_default_rule.rtableid = -1;

	/* initialize default timeouts */
	timeout[PFTM_TCP_FIRST_PACKET] = PFTM_TCP_FIRST_PACKET_VAL;
	timeout[PFTM_TCP_OPENING] = PFTM_TCP_OPENING_VAL;
	timeout[PFTM_TCP_ESTABLISHED] = PFTM_TCP_ESTABLISHED_VAL;
	timeout[PFTM_TCP_CLOSING] = PFTM_TCP_CLOSING_VAL;
	timeout[PFTM_TCP_FIN_WAIT] = PFTM_TCP_FIN_WAIT_VAL;
	timeout[PFTM_TCP_CLOSED] = PFTM_TCP_CLOSED_VAL;
	timeout[PFTM_UDP_FIRST_PACKET] = PFTM_UDP_FIRST_PACKET_VAL;
	timeout[PFTM_UDP_SINGLE] = PFTM_UDP_SINGLE_VAL;
	timeout[PFTM_UDP_MULTIPLE] = PFTM_UDP_MULTIPLE_VAL;
	timeout[PFTM_ICMP_FIRST_PACKET] = PFTM_ICMP_FIRST_PACKET_VAL;
	timeout[PFTM_ICMP_ERROR_REPLY] = PFTM_ICMP_ERROR_REPLY_VAL;
	timeout[PFTM_OTHER_FIRST_PACKET] = PFTM_OTHER_FIRST_PACKET_VAL;
	timeout[PFTM_OTHER_SINGLE] = PFTM_OTHER_SINGLE_VAL;
	timeout[PFTM_OTHER_MULTIPLE] = PFTM_OTHER_MULTIPLE_VAL;
	timeout[PFTM_FRAG] = PFTM_FRAG_VAL;
	timeout[PFTM_INTERVAL] = PFTM_INTERVAL_VAL;
	timeout[PFTM_SRC_NODE] = PFTM_SRC_NODE_VAL;
	timeout[PFTM_TS_DIFF] = PFTM_TS_DIFF_VAL;
	timeout[PFTM_ADAPTIVE_START] = PFSTATE_ADAPT_START;
	timeout[PFTM_ADAPTIVE_END] = PFSTATE_ADAPT_END;

	pf_default_rule.src.addr.type =  PF_ADDR_ADDRMASK;
	pf_default_rule.dst.addr.type =  PF_ADDR_ADDRMASK;
	pf_default_rule.rdr.addr.type =  PF_ADDR_NONE;
	pf_default_rule.nat.addr.type =  PF_ADDR_NONE;
	pf_default_rule.route.addr.type =  PF_ADDR_NONE;

	pf_normalize_init();
	memset(&pf_status, 0, sizeof(pf_status));
	pf_status.debug = LOG_ERR;
	pf_status.reass = PF_REASS_ENABLED;

	/* XXX do our best to avoid a conflict */
	pf_status.hostid = arc4random();

	pf_main_ruleset.rules.version = 1;

	/*
	 * we waste two stack frames as meta-data.
	 * frame[0] always presents a top, which can not be used for data
	 * frame[PF_ANCHOR_STACK_MAX] denotes a bottom of the stack and keeps
	 * the pointer to currently used stack frame.
	 */
	pf_anchor_stack = cpumem_malloc(
	    sizeof(struct pf_anchor_stackframe) * (PF_ANCHOR_STACK_MAX + 2),
	    M_WAITOK|M_ZERO);
	CPUMEM_FOREACH(sf, &cmi, pf_anchor_stack)
		sf[PF_ANCHOR_STACK_MAX].sf_stack_top = &sf[0];
}

int
pfopen(dev_t dev, int flags, int fmt, struct proc *p)
{
	int unit = minor(dev);

	if (unit & ((1 << CLONE_SHIFT) - 1))
		return (ENXIO);

	return (0);
}

int
pfclose(dev_t dev, int flags, int fmt, struct proc *p)
{
	struct pf_trans *w, *s;
	LIST_HEAD(, pf_trans)	tmp_list;
	uint32_t unit = minor(dev);

	LIST_INIT(&tmp_list);
	rw_enter_write(&pfioctl_rw);
	LIST_FOREACH_SAFE(w, &pf_ioctl_trans, pft_entry, s) {
		if (w->pft_unit == unit) {
			LIST_REMOVE(w, pft_entry);
			LIST_INSERT_HEAD(&tmp_list, w, pft_entry);
		}
	}
	rw_exit_write(&pfioctl_rw);

	while ((w = LIST_FIRST(&tmp_list)) != NULL) {
		LIST_REMOVE(w, pft_entry);
		pf_free_trans(w);
	}

	return (0);
}

void
pf_rule_free(struct pf_rule *rule)
{
	if (rule == NULL)
		return;

	pfi_kif_free(rule->kif);
	pfi_kif_free(rule->rcv_kif);
	pfi_kif_free(rule->rdr.kif);
	pfi_kif_free(rule->nat.kif);
	pfi_kif_free(rule->route.kif);

	pool_put(&pf_rule_pl, rule);
}

void
pf_rm_rule(struct pf_rulequeue *rulequeue, struct pf_rule *rule)
{
	if (rulequeue != NULL) {
		if (rule->states_cur == 0 && rule->src_nodes == 0) {
			/*
			 * XXX - we need to remove the table *before* detaching
			 * the rule to make sure the table code does not delete
			 * the anchor under our feet.
			 */
			pf_tbladdr_remove(&rule->src.addr);
			pf_tbladdr_remove(&rule->dst.addr);
			pf_tbladdr_remove(&rule->rdr.addr);
			pf_tbladdr_remove(&rule->nat.addr);
			pf_tbladdr_remove(&rule->route.addr);
			if (rule->overload_tbl)
				pfr_detach_table(rule->overload_tbl);
		}
		TAILQ_REMOVE(rulequeue, rule, entries);
		rule->entries.tqe_prev = NULL;
		rule->nr = (u_int32_t)-1;
	}

	if (rule->states_cur > 0 || rule->src_nodes > 0 ||
	    rule->entries.tqe_prev != NULL)
		return;
	pf_tag_unref(rule->tag);
	pf_tag_unref(rule->match_tag);
	pf_rtlabel_remove(&rule->src.addr);
	pf_rtlabel_remove(&rule->dst.addr);
	pfi_dynaddr_remove(&rule->src.addr);
	pfi_dynaddr_remove(&rule->dst.addr);
	pfi_dynaddr_remove(&rule->rdr.addr);
	pfi_dynaddr_remove(&rule->nat.addr);
	pfi_dynaddr_remove(&rule->route.addr);
	if (rulequeue == NULL) {
		pf_tbladdr_remove(&rule->src.addr);
		pf_tbladdr_remove(&rule->dst.addr);
		pf_tbladdr_remove(&rule->rdr.addr);
		pf_tbladdr_remove(&rule->nat.addr);
		pf_tbladdr_remove(&rule->route.addr);
		if (rule->overload_tbl)
			pfr_detach_table(rule->overload_tbl);
	}
	pfi_kif_unref(rule->rcv_kif, PFI_KIF_REF_RULE);
	pfi_kif_unref(rule->kif, PFI_KIF_REF_RULE);
	pfi_kif_unref(rule->rdr.kif, PFI_KIF_REF_RULE);
	pfi_kif_unref(rule->nat.kif, PFI_KIF_REF_RULE);
	pfi_kif_unref(rule->route.kif, PFI_KIF_REF_RULE);
	pf_remove_anchor(rule);
	pool_put(&pf_rule_pl, rule);
}

u_int16_t
tagname2tag(struct pf_tags *head, char *tagname, int create)
{
	struct pf_tagname	*tag, *p = NULL;
	u_int16_t		 new_tagid = 1;

	TAILQ_FOREACH(tag, head, entries)
		if (strcmp(tagname, tag->name) == 0) {
			tag->ref++;
			return (tag->tag);
		}

	if (!create)
		return (0);

	/*
	 * to avoid fragmentation, we do a linear search from the beginning
	 * and take the first free slot we find. if there is none or the list
	 * is empty, append a new entry at the end.
	 */

	/* new entry */
	TAILQ_FOREACH(p, head, entries) {
		if (p->tag != new_tagid)
			break;
		new_tagid = p->tag + 1;
	}

	if (new_tagid > TAGID_MAX)
		return (0);

	/* allocate and fill new struct pf_tagname */
	tag = pool_get(&pf_tag_pl, PR_NOWAIT | PR_ZERO);
	if (tag == NULL)
		return (0);
	strlcpy(tag->name, tagname, sizeof(tag->name));
	tag->tag = new_tagid;
	tag->ref++;

	if (p != NULL)	/* insert new entry before p */
		TAILQ_INSERT_BEFORE(p, tag, entries);
	else	/* either list empty or no free slot in between */
		TAILQ_INSERT_TAIL(head, tag, entries);

	return (tag->tag);
}

void
tag2tagname(struct pf_tags *head, u_int16_t tagid, char *p)
{
	struct pf_tagname	*tag;

	TAILQ_FOREACH(tag, head, entries)
		if (tag->tag == tagid) {
			strlcpy(p, tag->name, PF_TAG_NAME_SIZE);
			return;
		}
}

void
tag_unref(struct pf_tags *head, u_int16_t tag)
{
	struct pf_tagname	*p, *next;

	if (tag == 0)
		return;

	TAILQ_FOREACH_SAFE(p, head, entries, next) {
		if (tag == p->tag) {
			if (--p->ref == 0) {
				TAILQ_REMOVE(head, p, entries);
				pool_put(&pf_tag_pl, p);
			}
			break;
		}
	}
}

u_int16_t
pf_tagname2tag(char *tagname, int create)
{
	return (tagname2tag(&pf_tags, tagname, create));
}

void
pf_tag2tagname(u_int16_t tagid, char *p)
{
	tag2tagname(&pf_tags, tagid, p);
}

void
pf_tag_ref(u_int16_t tag)
{
	struct pf_tagname *t;

	TAILQ_FOREACH(t, &pf_tags, entries)
		if (t->tag == tag)
			break;
	if (t != NULL)
		t->ref++;
}

void
pf_tag_unref(u_int16_t tag)
{
	tag_unref(&pf_tags, tag);
}

int
pf_rtlabel_add(struct pf_addr_wrap *a)
{
	if (a->type == PF_ADDR_RTLABEL &&
	    (a->v.rtlabel = rtlabel_name2id(a->v.rtlabelname)) == 0)
		return (-1);
	return (0);
}

void
pf_rtlabel_remove(struct pf_addr_wrap *a)
{
	if (a->type == PF_ADDR_RTLABEL)
		rtlabel_unref(a->v.rtlabel);
}

void
pf_rtlabel_copyout(struct pf_addr_wrap *a)
{
	if (a->type == PF_ADDR_RTLABEL && a->v.rtlabel) {
		if (rtlabel_id2name(a->v.rtlabel, a->v.rtlabelname,
		    sizeof(a->v.rtlabelname)) == NULL)
			strlcpy(a->v.rtlabelname, "?",
			    sizeof(a->v.rtlabelname));
	}
}

u_int16_t
pf_qname2qid(char *qname, int create)
{
	return (tagname2tag(&pf_qids, qname, create));
}

void
pf_qid2qname(u_int16_t qid, char *p)
{
	tag2tagname(&pf_qids, qid, p);
}

void
pf_qid_unref(u_int16_t qid)
{
	tag_unref(&pf_qids, (u_int16_t)qid);
}

int
pf_begin_rules(struct pf_trans *t, const char *anchor)
{
	struct pf_ruleset	*rs;

	while (*anchor == '/')
		anchor++;

	if ((rs = pf_find_or_create_ruleset(&t->pftina_rc, anchor)) == NULL)
		return (EINVAL);

	rs->rules.version = pf_get_ruleset_version(
	    (rs == &t->pftina_rc.main_anchor.ruleset) ? "" : rs->anchor->path);
	log(LOG_DEBUG, "%s %s version: %d\n", __func__, anchor,
	    rs->rules.version);

	return (0);
}

void
pf_rollback_rules(u_int32_t version, char *anchor)
{
	/* queue defs only in the main ruleset */
	if (anchor[0])
		return;

	pf_free_queues(pf_queues_inactive);
}

void
pf_free_queues(struct pf_queuehead *where)
{
	struct pf_queuespec	*q, *qtmp;

	TAILQ_FOREACH_SAFE(q, where, entries, qtmp) {
		TAILQ_REMOVE(where, q, entries);
		pfi_kif_unref(q->kif, PFI_KIF_REF_RULE);
		pool_put(&pf_queue_pl, q);
	}
}

void
pf_remove_queues(void)
{
	struct pf_queuespec	*q;
	struct ifnet		*ifp;

	/* put back interfaces in normal queueing mode */
	TAILQ_FOREACH(q, pf_queues_active, entries) {
		if (q->parent_qid != 0)
			continue;

		ifp = q->kif->pfik_ifp;
		if (ifp == NULL)
			continue;

		ifq_attach(&ifp->if_snd, ifq_priq_ops, NULL);
	}
}

struct pf_queue_if {
	struct ifnet		*ifp;
	const struct ifq_ops	*ifqops;
	const struct pfq_ops	*pfqops;
	void			*disc;
	struct pf_queue_if	*next;
};

static inline struct pf_queue_if *
pf_ifp2q(struct pf_queue_if *list, struct ifnet *ifp)
{
	struct pf_queue_if *qif = list;

	while (qif != NULL) {
		if (qif->ifp == ifp)
			return (qif);

		qif = qif->next;
	}

	return (qif);
}

int
pf_create_queues(void)
{
	struct pf_queuespec	*q;
	struct ifnet		*ifp;
	struct pf_queue_if		*list = NULL, *qif;
	int			 error;

	/*
	 * Find root queues and allocate traffic conditioner
	 * private data for these interfaces
	 */
	TAILQ_FOREACH(q, pf_queues_active, entries) {
		if (q->parent_qid != 0)
			continue;

		ifp = q->kif->pfik_ifp;
		if (ifp == NULL)
			continue;

		qif = malloc(sizeof(*qif), M_PF, M_WAITOK);
		qif->ifp = ifp;

		if (q->flags & PFQS_ROOTCLASS) {
			qif->ifqops = ifq_hfsc_ops;
			qif->pfqops = pfq_hfsc_ops;
		} else {
			qif->ifqops = ifq_fqcodel_ops;
			qif->pfqops = pfq_fqcodel_ops;
		}

		qif->disc = qif->pfqops->pfq_alloc(ifp);

		qif->next = list;
		list = qif;
	}

	/* and now everything */
	TAILQ_FOREACH(q, pf_queues_active, entries) {
		ifp = q->kif->pfik_ifp;
		if (ifp == NULL)
			continue;

		qif = pf_ifp2q(list, ifp);
		KASSERT(qif != NULL);

		error = qif->pfqops->pfq_addqueue(qif->disc, q);
		if (error != 0)
			goto error;
	}

	/* find root queues in old list to disable them if necessary */
	TAILQ_FOREACH(q, pf_queues_inactive, entries) {
		if (q->parent_qid != 0)
			continue;

		ifp = q->kif->pfik_ifp;
		if (ifp == NULL)
			continue;

		qif = pf_ifp2q(list, ifp);
		if (qif != NULL)
			continue;

		ifq_attach(&ifp->if_snd, ifq_priq_ops, NULL);
	}

	/* commit the new queues */
	while (list != NULL) {
		qif = list;
		list = qif->next;

		ifp = qif->ifp;

		ifq_attach(&ifp->if_snd, qif->ifqops, qif->disc);
		free(qif, M_PF, sizeof(*qif));
	}

	return (0);

error:
	while (list != NULL) {
		qif = list;
		list = qif->next;

		qif->pfqops->pfq_free(qif->disc);
		free(qif, M_PF, sizeof(*qif));
	}

	return (error);
}

int
pf_commit_queues(void)
{
	struct pf_queuehead	*qswap;
	int error;

	/* swap */
	qswap = pf_queues_active;
	pf_queues_active = pf_queues_inactive;
	pf_queues_inactive = qswap;

	error = pf_create_queues();
	if (error != 0) {
		pf_queues_inactive = pf_queues_active;
		pf_queues_active = qswap;
		return (error);
	}

	pf_free_queues(pf_queues_inactive);

	return (0);
}

const struct pfq_ops *
pf_queue_manager(struct pf_queuespec *q)
{
	if (q->flags & PFQS_FLOWQUEUE)
		return pfq_fqcodel_ops;
	return (/* pfq_default_ops */ NULL);
}

#define PF_MD5_UPD(st, elm)						\
		MD5Update(ctx, (u_int8_t *) &(st)->elm, sizeof((st)->elm))

#define PF_MD5_UPD_STR(st, elm)						\
		MD5Update(ctx, (u_int8_t *) (st)->elm, strlen((st)->elm))

#define PF_MD5_UPD_HTONL(st, elm, stor) do {				\
		(stor) = htonl((st)->elm);				\
		MD5Update(ctx, (u_int8_t *) &(stor), sizeof(u_int32_t));\
} while (0)

#define PF_MD5_UPD_HTONS(st, elm, stor) do {				\
		(stor) = htons((st)->elm);				\
		MD5Update(ctx, (u_int8_t *) &(stor), sizeof(u_int16_t));\
} while (0)

void
pf_hash_rule_addr(MD5_CTX *ctx, struct pf_rule_addr *pfr)
{
	PF_MD5_UPD(pfr, addr.type);
	switch (pfr->addr.type) {
		case PF_ADDR_DYNIFTL:
			PF_MD5_UPD(pfr, addr.v.ifname);
			PF_MD5_UPD(pfr, addr.iflags);
			break;
		case PF_ADDR_TABLE:
			if (strncmp(pfr->addr.v.tblname, PF_OPTIMIZER_TABLE_PFX,
			    strlen(PF_OPTIMIZER_TABLE_PFX)))
				PF_MD5_UPD(pfr, addr.v.tblname);
			break;
		case PF_ADDR_ADDRMASK:
			/* XXX ignore af? */
			PF_MD5_UPD(pfr, addr.v.a.addr.addr32);
			PF_MD5_UPD(pfr, addr.v.a.mask.addr32);
			break;
		case PF_ADDR_RTLABEL:
			PF_MD5_UPD(pfr, addr.v.rtlabelname);
			break;
	}

	PF_MD5_UPD(pfr, port[0]);
	PF_MD5_UPD(pfr, port[1]);
	PF_MD5_UPD(pfr, neg);
	PF_MD5_UPD(pfr, port_op);
}

void
pf_hash_rule(MD5_CTX *ctx, struct pf_rule *rule)
{
	u_int16_t x;
	u_int32_t y;

	pf_hash_rule_addr(ctx, &rule->src);
	pf_hash_rule_addr(ctx, &rule->dst);
	PF_MD5_UPD_STR(rule, label);
	PF_MD5_UPD_STR(rule, ifname);
	PF_MD5_UPD_STR(rule, rcv_ifname);
	PF_MD5_UPD_STR(rule, match_tagname);
	PF_MD5_UPD_HTONS(rule, match_tag, x); /* dup? */
	PF_MD5_UPD_HTONL(rule, os_fingerprint, y);
	PF_MD5_UPD_HTONL(rule, prob, y);
	PF_MD5_UPD_HTONL(rule, uid.uid[0], y);
	PF_MD5_UPD_HTONL(rule, uid.uid[1], y);
	PF_MD5_UPD(rule, uid.op);
	PF_MD5_UPD_HTONL(rule, gid.gid[0], y);
	PF_MD5_UPD_HTONL(rule, gid.gid[1], y);
	PF_MD5_UPD(rule, gid.op);
	PF_MD5_UPD_HTONL(rule, rule_flag, y);
	PF_MD5_UPD(rule, action);
	PF_MD5_UPD(rule, direction);
	PF_MD5_UPD(rule, af);
	PF_MD5_UPD(rule, quick);
	PF_MD5_UPD(rule, ifnot);
	PF_MD5_UPD(rule, rcvifnot);
	PF_MD5_UPD(rule, match_tag_not);
	PF_MD5_UPD(rule, keep_state);
	PF_MD5_UPD(rule, proto);
	PF_MD5_UPD(rule, type);
	PF_MD5_UPD(rule, code);
	PF_MD5_UPD(rule, flags);
	PF_MD5_UPD(rule, flagset);
	PF_MD5_UPD(rule, allow_opts);
	PF_MD5_UPD(rule, rt);
	PF_MD5_UPD(rule, tos);
}

int
pf_commit_rules(u_int32_t version, char *anchor)
{
#if 0
	struct pf_ruleset	*rs;
	struct pf_rule		*rule;
	struct pf_rulequeue	*old_rules;
	u_int32_t		 old_rcount;

	rs = pf_find_ruleset(&pf_global, anchor);

	if (rs == NULL || !rs->rules.inactive.open ||
	    ticket != rs->rules.inactive.version)
		return (EBUSY);

	if (rs == &pf_main_ruleset)
		pf_calc_chksum(rs);

	/* Swap rules, keep the old. */
	old_rules = rs->rules.active.ptr;
	old_rcount = rs->rules.active.rcount;

	rs->rules.active.ptr = rs->rules.inactive.ptr;
	rs->rules.active.rcount = rs->rules.inactive.rcount;
	rs->rules.inactive.ptr = old_rules;
	rs->rules.inactive.rcount = old_rcount;

	rs->rules.active.version = rs->rules.inactive.version;
	pf_calc_skip_steps(rs->rules.active.ptr);


	/* Purge the old rule list. */
	while ((rule = TAILQ_FIRST(old_rules)) != NULL)
		pf_rm_rule(old_rules, rule);
	rs->rules.inactive.rcount = 0;
	rs->rules.inactive.open = 0;
	pf_remove_if_empty_ruleset(&pf_global, rs);

	/* queue defs only in the main ruleset */
	if (anchor[0])
		return (0);
	return (pf_commit_queues());
#endif
	return (0);
}

void
pf_calc_chksum(struct pf_ruleset *rs)
{
	MD5_CTX			 ctx;
	struct pf_rule		*rule;
	u_int8_t		 digest[PF_MD5_DIGEST_LENGTH];

	MD5Init(&ctx);

	if (rs->rules.rcount) {
		TAILQ_FOREACH(rule, rs->rules.ptr, entries) {
			pf_hash_rule(&ctx, rule);
		}
	}

	MD5Final(digest, &ctx);
	memcpy(pf_status.pf_chksum, digest, sizeof(pf_status.pf_chksum));
}

int
pf_addr_setup(struct pf_trans *t, struct pf_ruleset *ruleset,
    struct pf_addr_wrap *addr, sa_family_t af)
{
	if (pfi_dynaddr_setup(addr, af, PR_WAITOK) ||
	    pf_tbladdr_setup(t, ruleset, addr, PR_WAITOK) ||
	    pf_rtlabel_add(addr))
		return (EINVAL);

	return (0);
}

void
pf_addr_update(struct pf_trans *t, struct pf_ruleset *grs,
    struct pf_addr_wrap *addr)
{
	struct pf_anchor *a;
	struct pfr_ktable *kt;

	a = (grs->anchor == NULL) ? &pf_main_anchor : grs->anchor;

	if (addr->type != PF_ADDR_TABLE)
		return;

	/*
	 * Similar to pfr_attach_table(), we just want to find desired table in
	 * ancestor anchor. The difference is the anchor must 
	 */
	kt = NULL;
	while ((kt == NULL) && (a != NULL)) {
		kt = pfr_lookup_table(a, (struct pfr_table *)addr->p.tbl);
		a = a->parent;
	}
	if (kt == NULL)
		kt = pfr_lookup_table(&pf_main_anchor,
		    (struct pfr_table *)addr->p.tbl);

	/*
	 * pf_addr_update() must find table in root ruleset.
	 */
	KASSERT(kt != NULL);

	/*
	 * In case the pf.conf defines a table too, then
	 * rule already refers to the table. However if we
	 * just adding rule to existing runtime ruleset, then
	 * we must update table reference in rule.
	 */
	if (kt != addr->p.tbl) {
		addr->p.tbl->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		/*
		 * p.tbl reference can be safely overwritten here.  the table
		 * will be destroed with transaction.
		 */
		addr->p.tbl = kt;
		addr->p.tbl->pfrkt_refcnt[PFR_REFCNT_RULE]++;
	}
}

struct pfi_kif *
pf_kif_setup(struct pfi_kif *kif_buf)
{
	struct pfi_kif *kif;

	if (kif_buf == NULL)
		return (NULL);

	KASSERT(kif_buf->pfik_name[0] != '\0');

	kif = pfi_kif_get(kif_buf->pfik_name, &kif_buf);
	if (kif_buf != NULL)
		pfi_kif_free(kif_buf);
	pfi_kif_ref(kif, PFI_KIF_REF_RULE);

	return (kif);
}

void
pf_addr_copyout(struct pf_addr_wrap *addr)
{
	pfi_dynaddr_copyout(addr);
	pf_tbladdr_copyout(addr);
	pf_rtlabel_copyout(addr);
}

int
pf_states_clr(struct pfioc_state_kill *psk)
{
	struct pf_state		*st, *nextst;
	struct pf_state		*head, *tail;
	u_int			 killed = 0;
	int			 error;

	NET_LOCK();

	/* lock against the gc removing an item from the list */
	error = rw_enter(&pf_state_list.pfs_rwl, RW_READ|RW_INTR);
	if (error != 0)
		goto unlock;

	/* get a snapshot view of the ends of the list to traverse between */
	mtx_enter(&pf_state_list.pfs_mtx);
	head = TAILQ_FIRST(&pf_state_list.pfs_list);
	tail = TAILQ_LAST(&pf_state_list.pfs_list, pf_state_queue);
	mtx_leave(&pf_state_list.pfs_mtx);

	st = NULL;
	nextst = head;

	PF_LOCK();
	PF_STATE_ENTER_WRITE();

	while (st != tail) {
		st = nextst;
		nextst = TAILQ_NEXT(st, entry_list);

		if (st->timeout == PFTM_UNLINKED)
			continue;

		if (!psk->psk_ifname[0] || !strcmp(psk->psk_ifname,
		    st->kif->pfik_name)) {
#if NPFSYNC > 0
			/* don't send out individual delete messages */
			SET(st->state_flags, PFSTATE_NOSYNC);
#endif	/* NPFSYNC > 0 */
			pf_remove_state(st);
			killed++;
		}
	}

	PF_STATE_EXIT_WRITE();
	PF_UNLOCK();
	rw_exit(&pf_state_list.pfs_rwl);

	psk->psk_killed = killed;

#if NPFSYNC > 0
	pfsync_clear_states(pf_status.hostid, psk->psk_ifname);
#endif	/* NPFSYNC > 0 */
unlock:
	NET_UNLOCK();

	return (error);
}

int
pf_states_get(struct pfioc_states *ps)
{
	struct pf_state		*st, *nextst;
	struct pf_state		*head, *tail;
	struct pfsync_state	*p, pstore;
	u_int32_t		 nr = 0;
	int			 error;

	if (ps->ps_len == 0) {
		nr = pf_status.states;
		ps->ps_len = sizeof(struct pfsync_state) * nr;
		return (0);
	}

	p = ps->ps_states;

	/* lock against the gc removing an item from the list */
	error = rw_enter(&pf_state_list.pfs_rwl, RW_READ|RW_INTR);
	if (error != 0)
		return (error);

	/* get a snapshot view of the ends of the list to traverse between */
	mtx_enter(&pf_state_list.pfs_mtx);
	head = TAILQ_FIRST(&pf_state_list.pfs_list);
	tail = TAILQ_LAST(&pf_state_list.pfs_list, pf_state_queue);
	mtx_leave(&pf_state_list.pfs_mtx);

	st = NULL;
	nextst = head;

	while (st != tail) {
		st = nextst;
		nextst = TAILQ_NEXT(st, entry_list);

		if (st->timeout == PFTM_UNLINKED)
			continue;

		if ((nr+1) * sizeof(*p) > ps->ps_len)
			break;

		pf_state_export(&pstore, st);
		error = copyout(&pstore, p, sizeof(*p));
		if (error)
			goto fail;

		p++;
		nr++;
	}
	ps->ps_len = sizeof(struct pfsync_state) * nr;

fail:
	rw_exit(&pf_state_list.pfs_rwl);

	return (error);
}

int
pf_is_anchor_empty(struct pf_anchor *a)
{
	if (!TAILQ_EMPTY(a->ruleset.rules.ptr))
		return (0);

	if (!RB_EMPTY(&a->children))
		return (0);

	/* there is at least 1 rule which still refers to empty anchor */
	if (a->refcnt != 0)
		return (0);

	if (!RB_EMPTY(&a->ktables))
		return (0);

	return (1);
}

void
pf_remove_orphans(struct pf_trans *t)
{
	struct pf_anchor *a,  *aw;

	RB_FOREACH_REVERSE_SAFE(a, pf_anchor_global, &pf_anchors, aw) {
		log(LOG_DEBUG,
		    "%s trying to remove %s (refcnt: %d, rules are "
		    "%s empty, children are %s empty, tables: %d\n",
		    __func__, a->path, a->refcnt,
		    TAILQ_EMPTY(a->ruleset.rules.ptr) ?
			"" : "not",
		    RB_EMPTY(&a->children) ? "" : "not",
		    a->ruleset.anchor->tables);
		if (pf_is_anchor_empty(a)) {
			RB_REMOVE(pf_anchor_global, &pf_anchors, a);
			if (a->parent != NULL)
				RB_REMOVE(pf_anchor_node, &a->parent->children,
				    a);
			TAILQ_INSERT_TAIL(&t->pftina_anchor_list, a, workq);
			log(LOG_DEBUG, "%s %s will be removed\n",
			    __func__, a->path);
		} else
			log(LOG_DEBUG, "%s %s will not be removed\n",
			    __func__, a->path);
	}
}

/*
 * committing tables which are defined along the ruleset (ina)
 * is tricky. This is the behavior we want to preserve:
 *
 *
netlock# cat pf-tab.conf
table <biano>  { 192.168.1.1, 192.168.1.2, 192.168.2.0/24 }

block from <test> to any
anchor foo {
        pass in from any to <test>
}
netlock# pfctl -sT
dup
test
netlock# pfctl -f pf-tab.conf
netlock# pfctl -sT
dup
test
 *
 * pf-tab.,conf does not define table test, the table is left intact because it
 * got defined by 'pfctl -t test -T add ...'
 *
 * table biano did not survive commit operation because there is no rule
 * using it (PFR_REFCNT_RULE is zero).
 *
 * table dup is left intact, because it got defined by 'pfctl -t test -T add'
 *
 * let's modify pf-tab.conf so <dup> becomes defined by ruleset. However 
 * it is still unused:
 *
netlock# cat pf-tab.conf
table <biano>  { 192.168.1.1, 192.168.1.2, 192.168.2.0/24 }
table <dup>  { 192.168.1.1, 192.168.1.2, 192.168.2.0/24 }

block from <test> to any
anchor foo {
        pass in from any to <test>
}
netlock# pfctl -f pf-tab.conf
netlock# pfctl -sT
test
 *
 * table <dup> did not survive commit, because it got redefined by rulest.
 */
#if 0
void
pf_swap_tables_ina(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pfr_ktablehead tmp_tables;
	u_int32_t tmp_tables_cnt = 0;
	struct pfr_ktable *kt, *tkt, *tktw;

	RB_INIT(&tmp_tables);

	/*
	 * Drop all tables which were defined on behalf
	 * of ina and transaction does not define them
	 */
	RB_FOREACH(kt, pfr_ktablehead, &ta->ktables) {
		tkt = RB_FIND(pfr_ktablehead, &a->ktables, tkt);
		if (kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0) {
			RB_REMOVE(pfr_ktablehead, &a->ktables, kt);
			a->tables--;
			RB_INSERT(pfr_ktablehead, &tmp_tables, kt);
			tmp_tables_cnt++;
			pfr_ktable_cnt--;
		} else {
			log(LOG_DEBUG, "%s flushing table %s@%s, "
			    "still referred by %u rules\n",
			    __func__,
			    kt->pfrkt_name,
			    PF_ANCHOR_PATH(kt->pfrkt_anchor),
			    kt->pfrkt_refcnt[PFR_REFCNT_RULE]);
			pfr_flush_table(kt);
			kt->pfrkt_flags |= PFR_TFLAG_INACTIVE;
			kt->pfrkt_flags &= ~PFR_TFLAG_ACTIVE;
		}
	}

	RB_FOREACH_SAFE(tkt, pfr_ktablehead, &ta->ktables, tktw) {
		RB_REMOVE(pfr_ktablehead, &ta->ktables, tkt);
		kt = RB_FIND(pfr_ktablehead, &a->ktables, tkt);
		if (kt != NULL) {
			/*
			 * should be updating table with persistent flags.
			 */
			KASSERT(kt->pfrkt_flags & PFR_TFLAG_PERSIST);
			KASSERT(kt->pfrkt_version == tkt->pfrkt_version);
			RB_REMOVE(pfr_ktablehead, &a->ktables, kt);
			RB_INSERT(pfr_ktablehead, &tmp_tables, kt);
			kt->pfrkt_flags |= PFR_TFLAG_DETACHED;
			RB_INSERT(pfr_ktablehead, &a->ktables, tkt);
			tmp_tables_cnt++;
		} else {
			RB_INSERT(pfr_ktablehead, &a->ktables, tkt);
			a->tables++;
		}
	}

	ta->ktables = tmp_tables;
	ta->tables = tmp_tables_cnt;
}
#endif

void
pf_detach_rule(struct pf_rule *r)
{
	struct pfr_ktable *tmp_kt;

	if (r->anchor != NULL) {
		r->anchor->refcnt--;
		log(LOG_DEBUG, "%s droping reference to %s\n",
		    __func__,
		    r->anchor->path);
		KASSERT(r->anchor->refcnt >= 0);
		r->anchor = NULL;
	}
	if (r->src.addr.type == PF_ADDR_TABLE) {
		tmp_kt = r->src.addr.p.tbl;
		r->src.addr.p.tbl = NULL;
		r->src.addr.type = PF_ADDR_NONE;

		tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		KASSERT(tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] >= 0);
		if (tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0)
			tmp_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
	}
	if (r->dst.addr.type == PF_ADDR_TABLE) {
		tmp_kt = r->dst.addr.p.tbl;
		r->dst.addr.p.tbl = NULL;
		r->dst.addr.type = PF_ADDR_NONE;

		tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		KASSERT(tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] >= 0);
		if (tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0)
			tmp_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
	}
	if (r->rdr.addr.type == PF_ADDR_TABLE) {
		tmp_kt = r->rdr.addr.p.tbl;
		r->rdr.addr.p.tbl = NULL;
		r->rdr.addr.type = PF_ADDR_NONE;

		tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		KASSERT(tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] >= 0);
		if (tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0)
			tmp_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
	}
	if (r->nat.addr.type == PF_ADDR_TABLE) {
		tmp_kt = r->nat.addr.p.tbl;
		r->nat.addr.p.tbl = NULL;
		r->nat.addr.type = PF_ADDR_NONE;

		tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		KASSERT(tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] >= 0);
		if (tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0)
			tmp_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
	}
	if (r->route.addr.type == PF_ADDR_TABLE) {
		tmp_kt = r->route.addr.p.tbl;
		r->route.addr.p.tbl = NULL;
		r->route.addr.type = PF_ADDR_NONE;

		tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE]--;
		KASSERT(tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] >= 0);
		if (tmp_kt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0)
			tmp_kt->pfrkt_flags &= ~PFR_TFLAG_REFERENCED;
	}
}

/*
 * Function swaps rules and tables between global anchor 'a' and
 * transaction anchor 'ta'.
 */
void
pf_swap_anchors_ina(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pf_ruleset tmp_rs;
	struct pf_ruleset *trs, *grs;
	struct pf_rule *r;
	struct pfr_ktablehead tmp_ktables;
	u_int32_t tables;

	trs = &ta->ruleset;
	grs = &a->ruleset;
	KASSERT(grs->rules.version == trs->rules.version);

	pf_init_ruleset(&tmp_rs);
	tmp_rs.rules.rcount = trs->rules.rcount;
	TAILQ_CONCAT(tmp_rs.rules.ptr, trs->rules.ptr, entries);

	/*
	 * swap tables between global and transaction anchor.
	 */
	tmp_ktables = ta->ktables;
	tables = ta->tables;
	ta->ktables = a->ktables;
	ta->tables = a->tables;
	a->ktables = tmp_ktables;
	a->tables = tables;

	/*
	 * We move rules from global anchor to transaction anchor, we also must
	 * drop references to global objects referred by rule.
	 */
	trs->rules.rcount = grs->rules.rcount;
	TAILQ_CONCAT(trs->rules.ptr, grs->rules.ptr, entries);
	/*
	 * Detach anchor rules and tables from rules which are moved to
	 * transaction anchor (read: replaced by commit operation).
	 */
	TAILQ_FOREACH(r, trs->rules.ptr, entries)
		pf_detach_rule(r);
	/*
	 * Drop references to tables we are going to remove by transaction.
	 * Tables to remove are kept in 'ta' anchor.
	 */
	pfr_drop_table_refs(a, ta);

	grs->rules.rcount = tmp_rs.rules.rcount;
	TAILQ_CONCAT(grs->rules.ptr, tmp_rs.rules.ptr, entries);
	
	TAILQ_FOREACH(r, grs->rules.ptr, entries) {
		if (r->anchor != NULL) {
			struct pf_anchor *anchor;
			/*
			 * ->anchor can either refer to anchor found
			 * transaction or to anchor found in pf_anchors.
			 * If ->anchor is found in pf_anchors, then we
			 * are done.
			 */

			anchor = RB_FIND(pf_anchor_global, &pf_anchors,
			    r->anchor);
			if (anchor != r->anchor) {
				/*
				 * if anchor is not found, then it must be
				 * found in transaction, waiting to be
				 * committed. No action for us then.  If
				 * different anchor is found in pf_anchors for
				 * r->anchor, then we must update reference.
				 */
				if (anchor == NULL) {
					anchor = RB_FIND(pf_anchor_global,
					    &t->pftina_rc.anchors, r->anchor);
					if (anchor == NULL)
						panic(
						    "%s dangling anchor %s",
						    __func__,
						    r->anchor->path);
				} else {
					r->anchor->refcnt--;
					KASSERT(r->anchor->refcnt >= 0);
					r->anchor = anchor;
					r->anchor->refcnt++;
					log(LOG_DEBUG, "%s %s->refcnt: %u\n",
					    __func__,
					    r->anchor->path,
					    r->anchor->refcnt);
				}
			}
			
		}
	}

	pfr_update_table_refs(a);

	grs->rules.version++;
}

void
pf_drop_unused_tables(struct pf_trans *t)
{
	struct pf_anchor	*ta;
	struct pfr_ktable	*tkt, *tktw;

	/*
	 * clean up non-persistent tables which are not used
	 * (referred by rules).
	 */
	RB_FOREACH_SAFE(tkt, pfr_ktablehead, &t->pftina_rc.main_anchor.ktables,
	    tktw) {
		if ((tkt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0) &&
		    (tkt->pfrkt_flags & PFR_TFLAG_PERSIST) == 0) {
			RB_REMOVE(pfr_ktablehead,
			    &t->pftina_rc.main_anchor.ktables, tkt);
			t->pftina_rc.main_anchor.tables--;
			SLIST_INSERT_HEAD(&t->pftina_garbage, tkt, pfrkt_workq);
		}
	}
	RB_FOREACH(ta, pf_anchor_global, &t->pftina_rc.anchors) {
		RB_FOREACH_SAFE(tkt, pfr_ktablehead, &ta->ktables, tktw) {
			log(LOG_DEBUG, "%s %s@%s [%d] ", __func__,
			    tkt->pfrkt_name, ta->path,
			    tkt->pfrkt_refcnt[PFR_REFCNT_RULE]);
			if (tkt->pfrkt_refcnt[PFR_REFCNT_RULE] == 0 &&
			    (tkt->pfrkt_flags & PFR_TFLAG_PERSIST) == 0) {
				log(LOG_DEBUG, "removed");
				RB_REMOVE(pfr_ktablehead, &ta->ktables, tkt);
				ta->tables--;
				SLIST_INSERT_HEAD(&t->pftina_garbage, tkt,
				    pfrkt_workq);
			}
			log(LOG_DEBUG, "\n");
		}
	}
}

int
pfioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
	int			 error = 0;

	/* XXX keep in sync with switch() below */
	if (securelevel > 1)
		switch (cmd) {
		case DIOCGETRULES:
		case DIOCGETRULE:
		case DIOCGETSTATE:
		case DIOCSETSTATUSIF:
		case DIOCGETSTATUS:
		case DIOCCLRSTATUS:
		case DIOCNATLOOK:
		case DIOCSETDEBUG:
		case DIOCGETSTATES:
		case DIOCGETTIMEOUT:
		case DIOCGETLIMIT:
		case DIOCGETRULESETS:
		case DIOCGETRULESET:
		case DIOCGETQUEUES:
		case DIOCGETQUEUE:
		case DIOCGETQSTATS:
		case DIOCRGETTABLES:
		case DIOCRGETTSTATS:
		case DIOCRCLRTSTATS:
		case DIOCRCLRADDRS:
		case DIOCRADDADDRS:
		case DIOCRDELADDRS:
		case DIOCRSETADDRS:
		case DIOCRGETADDRS:
		case DIOCRGETASTATS:
		case DIOCRCLRASTATS:
		case DIOCRTSTADDRS:
		case DIOCOSFPGET:
		case DIOCGETSRCNODES:
		case DIOCCLRSRCNODES:
		case DIOCIGETIFACES:
		case DIOCSETIFFLAG:
		case DIOCCLRIFFLAG:
		case DIOCGETSYNFLWATS:
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRSETTFLAGS:
			if (((struct pfioc_table *)addr)->pfrio_flags &
			    PFR_FLAG_DUMMY)
				break; /* dummy operation ok */
			return (EPERM);
		default:
			return (EPERM);
		}

	if (!(flags & FWRITE))
		switch (cmd) {
		case DIOCGETRULES:
		case DIOCGETSTATE:
		case DIOCGETSTATUS:
		case DIOCGETSTATES:
		case DIOCGETTIMEOUT:
		case DIOCGETLIMIT:
		case DIOCGETRULESETS:
		case DIOCGETRULESET:
		case DIOCGETQUEUES:
		case DIOCGETQUEUE:
		case DIOCGETQSTATS:
		case DIOCNATLOOK:
		case DIOCRGETTABLES:
		case DIOCRGETTSTATS:
		case DIOCRGETADDRS:
		case DIOCRGETASTATS:
		case DIOCRTSTADDRS:
		case DIOCOSFPGET:
		case DIOCGETSRCNODES:
		case DIOCIGETIFACES:
		case DIOCGETSYNFLWATS:
		case DIOCXEND:
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRCLRTSTATS:
		case DIOCRCLRADDRS:
		case DIOCRADDADDRS:
		case DIOCRDELADDRS:
		case DIOCRSETADDRS:
		case DIOCRSETTFLAGS:
			if (((struct pfioc_table *)addr)->pfrio_flags &
			    PFR_FLAG_DUMMY) {
				flags |= FWRITE; /* need write lock for dummy */
				break; /* dummy operation ok */
			}
			return (EACCES);
		case DIOCGETRULE:
			if (((struct pfioc_rule *)addr)->action ==
			    PF_GET_CLR_CNTR)
				return (EACCES);
			break;
		default:
			return (EACCES);
		}

	rw_enter_write(&pfioctl_rw);

	switch (cmd) {

	case DIOCSTART:
		NET_LOCK();
		PF_LOCK();
		if (pf_status.running)
			error = EEXIST;
		else {
			pf_status.running = 1;
			pf_status.since = getuptime();
			if (pf_status.stateid == 0) {
				pf_status.stateid = gettime();
				pf_status.stateid = pf_status.stateid << 32;
			}
			timeout_add_sec(&pf_purge_states_to, 1);
			timeout_add_sec(&pf_purge_to, 1);
			pf_create_queues();
			DPFPRINTF(LOG_NOTICE, "pf: started");
		}
		PF_UNLOCK();
		NET_UNLOCK();
		break;

	case DIOCSTOP:
		NET_LOCK();
		PF_LOCK();
		if (!pf_status.running)
			error = ENOENT;
		else {
			pf_status.running = 0;
			pf_status.since = getuptime();
			pf_remove_queues();
			DPFPRINTF(LOG_NOTICE, "pf: stopped");
		}
		PF_UNLOCK();
		NET_UNLOCK();
		break;

	case DIOCGETQUEUES: {
		struct pfioc_queue	*pq = (struct pfioc_queue *)addr;
		struct pf_queuespec	*qs;
		u_int32_t		 nr = 0;

		PF_LOCK();
		pq->ticket = pf_main_ruleset.rules.version;

		/* save state to not run over them all each time? */
		qs = TAILQ_FIRST(pf_queues_active);
		while (qs != NULL) {
			qs = TAILQ_NEXT(qs, entries);
			nr++;
		}
		pq->nr = nr;
		PF_UNLOCK();
		break;
	}

	case DIOCGETQUEUE: {
		struct pfioc_queue	*pq = (struct pfioc_queue *)addr;
		struct pf_queuespec	*qs;
		u_int32_t		 nr = 0;

		PF_LOCK();
		if (pq->ticket != pf_main_ruleset.rules.version) {
			error = EBUSY;
			PF_UNLOCK();
			goto fail;
		}

		/* save state to not run over them all each time? */
		qs = TAILQ_FIRST(pf_queues_active);
		while ((qs != NULL) && (nr++ < pq->nr))
			qs = TAILQ_NEXT(qs, entries);
		if (qs == NULL) {
			error = EBUSY;
			PF_UNLOCK();
			goto fail;
		}
		memcpy(&pq->queue, qs, sizeof(pq->queue));
		PF_UNLOCK();
		break;
	}

	case DIOCGETQSTATS: {
		struct pfioc_qstats	*pq = (struct pfioc_qstats *)addr;
		struct pf_queuespec	*qs;
		u_int32_t		 nr;
		int			 nbytes;

		NET_LOCK();
		PF_LOCK();
		if (pq->ticket != pf_main_ruleset.rules.version) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		nbytes = pq->nbytes;
		nr = 0;

		/* save state to not run over them all each time? */
		qs = TAILQ_FIRST(pf_queues_active);
		while ((qs != NULL) && (nr++ < pq->nr))
			qs = TAILQ_NEXT(qs, entries);
		if (qs == NULL) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		memcpy(&pq->queue, qs, sizeof(pq->queue));
		/* It's a root flow queue but is not an HFSC root class */
		if ((qs->flags & PFQS_FLOWQUEUE) && qs->parent_qid == 0 &&
		    !(qs->flags & PFQS_ROOTCLASS))
			error = pfq_fqcodel_ops->pfq_qstats(qs, pq->buf,
			    &nbytes);
		else
			error = pfq_hfsc_ops->pfq_qstats(qs, pq->buf,
			    &nbytes);
		if (error == 0)
			pq->nbytes = nbytes;
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCADDQUEUE: {
		struct pfioc_queue	*q = (struct pfioc_queue *)addr;
		struct pf_queuespec	*qs;

		qs = pool_get(&pf_queue_pl, PR_WAITOK|PR_LIMITFAIL|PR_ZERO);
		if (qs == NULL) {
			error = ENOMEM;
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();
		if (q->ticket != pf_main_ruleset.rules.version) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			pool_put(&pf_queue_pl, qs);
			goto fail;
		}
		memcpy(qs, &q->queue, sizeof(*qs));
		qs->qid = pf_qname2qid(qs->qname, 1);
		if (qs->qid == 0) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			pool_put(&pf_queue_pl, qs);
			goto fail;
		}
		if (qs->parent[0] && (qs->parent_qid =
		    pf_qname2qid(qs->parent, 0)) == 0) {
			error = ESRCH;
			PF_UNLOCK();
			NET_UNLOCK();
			pool_put(&pf_queue_pl, qs);
			goto fail;
		}
		qs->kif = pfi_kif_get(qs->ifname, NULL);
		if (qs->kif == NULL) {
			error = ESRCH;
			PF_UNLOCK();
			NET_UNLOCK();
			pool_put(&pf_queue_pl, qs);
			goto fail;
		}
		/* XXX resolve bw percentage specs */
		pfi_kif_ref(qs->kif, PFI_KIF_REF_RULE);

		TAILQ_INSERT_TAIL(pf_queues_inactive, qs, entries);
		PF_UNLOCK();
		NET_UNLOCK();

		break;
	}

	case DIOCADDRULE: {
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule, *tail;
		struct pf_trans		*t;

		t = pf_find_trans(minor(dev), pr->ticket);
		if (t == NULL) {
			error = EBUSY;
			goto fail;
		}

		rule = pool_get(&pf_rule_pl, PR_WAITOK|PR_LIMITFAIL|PR_ZERO);
		if (rule == NULL) {
			error = ENOMEM;
			goto fail;
		}

		if ((error = pf_rule_copyin(&pr->rule, rule))) {
			pf_rule_free(rule);
			rule = NULL;
			goto fail;
		}

		if (pr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
			error = EINVAL;
			pf_rule_free(rule);
			rule = NULL;
			goto fail;
		}
		if ((error = pf_rule_checkaf(rule))) {
			pf_rule_free(rule);
			rule = NULL;
			goto fail;
		}
		if (rule->src.addr.type == PF_ADDR_NONE ||
		    rule->dst.addr.type == PF_ADDR_NONE) {
			error = EINVAL;
			pf_rule_free(rule);
			rule = NULL;
			goto fail;
		}

		if (rule->rt && !rule->direction) {
			error = EINVAL;
			pf_rule_free(rule);
			rule = NULL;
			goto fail;
		}

		pr->anchor[sizeof(pr->anchor) - 1] = '\0';
		ruleset = pf_find_ruleset(&t->pftina_rc, pr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			pf_rule_free(rule);
			goto fail;
		}
		rule->cuid = p->p_ucred->cr_ruid;
		rule->cpid = p->p_p->ps_pid;

		tail = TAILQ_LAST(ruleset->rules.ptr, pf_rulequeue);
		if (tail)
			rule->nr = tail->nr + 1;
		else
			rule->nr = 0;

		rule->kif = pf_kif_setup(rule->kif);
		rule->rcv_kif = pf_kif_setup(rule->rcv_kif);
		rule->rdr.kif = pf_kif_setup(rule->rdr.kif);
		rule->nat.kif = pf_kif_setup(rule->nat.kif);
		rule->route.kif = pf_kif_setup(rule->route.kif);

		if (rule->overload_tblname[0]) {
			if ((rule->overload_tbl = pfr_attach_table(&t->pftina_rc,
			    ruleset, rule->overload_tblname,
			    PR_WAITOK)) == NULL)
				error = EINVAL;
			else
				rule->overload_tbl->pfrkt_flags |=
				    PFR_TFLAG_ACTIVE;
		}

		if (pf_addr_setup(t, ruleset, &rule->src.addr, rule->af))
			error = EINVAL;
		if (pf_addr_setup(t, ruleset, &rule->dst.addr, rule->af))
			error = EINVAL;
		if (pf_addr_setup(t, ruleset, &rule->rdr.addr, rule->af))
			error = EINVAL;
		if (pf_addr_setup(t, ruleset, &rule->nat.addr, rule->af))
			error = EINVAL;
		if (pf_addr_setup(t, ruleset, &rule->route.addr, rule->af))
			error = EINVAL;
		if (pf_anchor_setup(&t->pftina_rc, rule, ruleset,
		    pr->anchor_call))
			error = EINVAL;

		if (error) {
			pf_rm_rule(NULL, rule);
			goto fail;
		}
		TAILQ_INSERT_TAIL(ruleset->rules.ptr, rule, entries);
		break;
	}

	case DIOCGETRULES: {
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule;
		struct pf_trans		*t;
		u_int32_t		 ruleset_version;

		NET_LOCK();
		PF_LOCK();
		pr->anchor[sizeof(pr->anchor) - 1] = '\0';
		ruleset = pf_find_ruleset(&pf_global, pr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		rule = TAILQ_LAST(ruleset->rules.ptr, pf_rulequeue);
		if (rule)
			pr->nr = rule->nr + 1;
		else
			pr->nr = 0;
		ruleset_version = ruleset->rules.version;
		pf_anchor_take(ruleset->anchor);
		rule = TAILQ_FIRST(ruleset->rules.ptr);
		PF_UNLOCK();
		NET_UNLOCK();

		t = pf_open_trans(minor(dev));
		if (t == NULL) {
			error = EBUSY;
			goto fail;
		}
		pf_init_tgetrule(t, ruleset->anchor, ruleset_version, rule);
		pr->ticket = t->pft_ticket;

		break;
	}

	case DIOCGETRULE: {
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule;
		struct pf_trans		*t;
		int			 i;

		t = pf_find_trans(minor(dev), pr->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}
		KASSERT(t->pft_unit == minor(dev));
		if (t->pft_type != PF_TRANS_GETRULE) {
			error = EINVAL;
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();
		KASSERT(t->pftgr_anchor != NULL);
		ruleset = &t->pftgr_anchor->ruleset;
		if (t->pftgr_version != ruleset->rules.version) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		rule = t->pftgr_rule;
		if (rule == NULL) {
			error = ENOENT;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		memcpy(&pr->rule, rule, sizeof(struct pf_rule));
		memset(&pr->rule.entries, 0, sizeof(pr->rule.entries));
		pr->rule.kif = NULL;
		pr->rule.nat.kif = NULL;
		pr->rule.rdr.kif = NULL;
		pr->rule.route.kif = NULL;
		pr->rule.rcv_kif = NULL;
		pr->rule.anchor = NULL;
		pr->rule.overload_tbl = NULL;
		pr->rule.pktrate.limit /= PF_THRESHOLD_MULT;
		if (pf_anchor_copyout(ruleset, rule, pr)) {
			error = EBUSY;
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}
		pf_addr_copyout(&pr->rule.src.addr);
		pf_addr_copyout(&pr->rule.dst.addr);
		pf_addr_copyout(&pr->rule.rdr.addr);
		pf_addr_copyout(&pr->rule.nat.addr);
		pf_addr_copyout(&pr->rule.route.addr);
		for (i = 0; i < PF_SKIP_COUNT; ++i)
			if (rule->skip[i].ptr == NULL)
				pr->rule.skip[i].nr = (u_int32_t)-1;
			else
				pr->rule.skip[i].nr =
				    rule->skip[i].ptr->nr;

		if (pr->action == PF_GET_CLR_CNTR) {
			rule->evaluations = 0;
			rule->packets[0] = rule->packets[1] = 0;
			rule->bytes[0] = rule->bytes[1] = 0;
			rule->states_tot = 0;
		}
		pr->nr = rule->nr;
		t->pftgr_rule = TAILQ_NEXT(rule, entries);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCCHANGERULE: {
		/*
		 * TODO: this must be rewrittern so it will use transactions,
		 * for rules we are adding/changing. Remove action must bump
		 * ruleset version number
		 */
		struct pfioc_rule	*pcr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*oldrule = NULL, *newrule = NULL;
		u_int32_t		 nr = 0;

		if (pcr->action < PF_CHANGE_ADD_HEAD ||
		    pcr->action > PF_CHANGE_GET_TICKET) {
			error = EINVAL;
			goto fail;
		}

		if (pcr->action == PF_CHANGE_GET_TICKET) {
			NET_LOCK();
			PF_LOCK();

			ruleset = pf_find_ruleset(&pf_global, pcr->anchor);
			if (ruleset == NULL)
				error = EINVAL;
			else
				pcr->ticket = ++ruleset->rules.version;

			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}

		if (pcr->action != PF_CHANGE_REMOVE) {
			newrule = pool_get(&pf_rule_pl,
			    PR_WAITOK|PR_LIMITFAIL|PR_ZERO);
			if (newrule == NULL) {
				error = ENOMEM;
				goto fail;
			}

			if (pcr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
				error = EINVAL;
				pool_put(&pf_rule_pl, newrule);
				goto fail;
			}
			error = pf_rule_copyin(&pcr->rule, newrule);
			if (error != 0) {
				pf_rule_free(newrule);
				newrule = NULL;
				goto fail;
			}
			if ((error = pf_rule_checkaf(newrule))) {
				pf_rule_free(newrule);
				newrule = NULL;
				goto fail;
			}
			if (newrule->rt && !newrule->direction) {
				pf_rule_free(newrule);
				error = EINVAL;
				newrule = NULL;
				goto fail;
			}
		}

		NET_LOCK();
		PF_LOCK();
		ruleset = pf_find_ruleset(&pf_global, pcr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			PF_UNLOCK();
			NET_UNLOCK();
			pf_rule_free(newrule);
			goto fail;
		}

		if (pcr->ticket != ruleset->rules.version) {
			error = EINVAL;
			PF_UNLOCK();
			NET_UNLOCK();
			pf_rule_free(newrule);
			goto fail;
		}

		if (pcr->action != PF_CHANGE_REMOVE) {
			/* FixMe: here we need a proper transaction */
			struct pf_trans *t = NULL;

			KASSERT(newrule != NULL);
			newrule->cuid = p->p_ucred->cr_ruid;
			newrule->cpid = p->p_p->ps_pid;

			newrule->kif = pf_kif_setup(newrule->kif);
			newrule->rcv_kif = pf_kif_setup(newrule->rcv_kif);
			newrule->rdr.kif = pf_kif_setup(newrule->rdr.kif);
			newrule->nat.kif = pf_kif_setup(newrule->nat.kif);
			newrule->route.kif = pf_kif_setup(newrule->route.kif);

			if (newrule->overload_tblname[0]) {
				newrule->overload_tbl = pfr_attach_table(
				    &t->pftina_rc, ruleset,
				    newrule->overload_tblname, PR_WAITOK);
				if (newrule->overload_tbl == NULL)
					error = EINVAL;
				else
					newrule->overload_tbl->pfrkt_flags |=
					    PFR_TFLAG_ACTIVE;
			}

			if (pf_addr_setup(t, ruleset, &newrule->src.addr,
			    newrule->af))
				error = EINVAL;
			if (pf_addr_setup(t, ruleset, &newrule->dst.addr,
			    newrule->af))
				error = EINVAL;
			if (pf_addr_setup(t, ruleset, &newrule->rdr.addr,
			    newrule->af))
				error = EINVAL;
			if (pf_addr_setup(t, ruleset, &newrule->nat.addr,
			    newrule->af))
				error = EINVAL;
			if (pf_addr_setup(t, ruleset, &newrule->route.addr,
			    newrule->af))
				error = EINVAL;
			/*
			 * TODO: we have to ensure no ruleset/anchors get
			 * 0 created here.
			 */
			if (pf_anchor_setup(&pf_global, newrule, ruleset,
			    pcr->anchor_call))
				error = EINVAL;

			if (error) {
				pf_rm_rule(NULL, newrule);
				PF_UNLOCK();
				NET_UNLOCK();
				goto fail;
			}
		}

		if (pcr->action == PF_CHANGE_ADD_HEAD)
			oldrule = TAILQ_FIRST(ruleset->rules.ptr);
		else if (pcr->action == PF_CHANGE_ADD_TAIL)
			oldrule = TAILQ_LAST(ruleset->rules.ptr,
			    pf_rulequeue);
		else {
			oldrule = TAILQ_FIRST(ruleset->rules.ptr);
			while ((oldrule != NULL) && (oldrule->nr != pcr->nr))
				oldrule = TAILQ_NEXT(oldrule, entries);
			if (oldrule == NULL) {
				if (newrule != NULL)
					pf_rm_rule(NULL, newrule);
				error = EINVAL;
				PF_UNLOCK();
				NET_UNLOCK();
				goto fail;
			}
		}

		if (pcr->action == PF_CHANGE_REMOVE) {
			pf_rm_rule(ruleset->rules.ptr, oldrule);
			ruleset->rules.rcount--;
		} else {
			if (oldrule == NULL)
				TAILQ_INSERT_TAIL(
				    ruleset->rules.ptr,
				    newrule, entries);
			else if (pcr->action == PF_CHANGE_ADD_HEAD ||
			    pcr->action == PF_CHANGE_ADD_BEFORE)
				TAILQ_INSERT_BEFORE(oldrule, newrule, entries);
			else
				TAILQ_INSERT_AFTER(
				    ruleset->rules.ptr,
				    oldrule, newrule, entries);
			ruleset->rules.rcount++;
		}

		nr = 0;
		TAILQ_FOREACH(oldrule, ruleset->rules.ptr, entries)
			oldrule->nr = nr++;

		ruleset->rules.version++;

		pf_calc_skip_steps(ruleset->rules.ptr);
		pf_remove_if_empty_ruleset(&pf_global, ruleset);

		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCCLRSTATES:
		error = pf_states_clr((struct pfioc_state_kill *)addr);
		break;

	case DIOCKILLSTATES: {
		struct pf_state		*st, *nextst;
		struct pf_state_item	*si, *sit;
		struct pf_state_key	*sk, key;
		struct pf_addr		*srcaddr, *dstaddr;
		u_int16_t		 srcport, dstport;
		struct pfioc_state_kill	*psk = (struct pfioc_state_kill *)addr;
		u_int			 i, killed = 0;
		const int		 dirs[] = { PF_IN, PF_OUT };
		int			 sidx, didx;

		if (psk->psk_pfcmp.id) {
			if (psk->psk_pfcmp.creatorid == 0)
				psk->psk_pfcmp.creatorid = pf_status.hostid;
			NET_LOCK();
			PF_LOCK();
			PF_STATE_ENTER_WRITE();
			if ((st = pf_find_state_byid(&psk->psk_pfcmp))) {
				pf_remove_state(st);
				psk->psk_killed = 1;
			}
			PF_STATE_EXIT_WRITE();
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}

		if (psk->psk_af && psk->psk_proto &&
		    psk->psk_src.port_op == PF_OP_EQ &&
		    psk->psk_dst.port_op == PF_OP_EQ) {

			key.af = psk->psk_af;
			key.proto = psk->psk_proto;
			key.rdomain = psk->psk_rdomain;

			NET_LOCK();
			PF_LOCK();
			PF_STATE_ENTER_WRITE();
			for (i = 0; i < nitems(dirs); i++) {
				if (dirs[i] == PF_IN) {
					sidx = 0;
					didx = 1;
				} else {
					sidx = 1;
					didx = 0;
				}
				pf_addrcpy(&key.addr[sidx],
				    &psk->psk_src.addr.v.a.addr, key.af);
				pf_addrcpy(&key.addr[didx],
				    &psk->psk_dst.addr.v.a.addr, key.af);
				key.port[sidx] = psk->psk_src.port[0];
				key.port[didx] = psk->psk_dst.port[0];

				sk = RBT_FIND(pf_state_tree, &pf_statetbl,
				    &key);
				if (sk == NULL)
					continue;

				TAILQ_FOREACH_SAFE(si, &sk->sk_states,
				    si_entry, sit) {
					struct pf_state *sist = si->si_st;
					if (((sist->key[PF_SK_WIRE]->af ==
					    sist->key[PF_SK_STACK]->af &&
					    sk == (dirs[i] == PF_IN ?
					    sist->key[PF_SK_WIRE] :
					    sist->key[PF_SK_STACK])) ||
					    (sist->key[PF_SK_WIRE]->af !=
					    sist->key[PF_SK_STACK]->af &&
					    dirs[i] == PF_IN &&
					    (sk == sist->key[PF_SK_STACK] ||
					    sk == sist->key[PF_SK_WIRE]))) &&
					    (!psk->psk_ifname[0] ||
					    (sist->kif != pfi_all &&
					    !strcmp(psk->psk_ifname,
					    sist->kif->pfik_name)))) {
						pf_remove_state(sist);
						killed++;
					}
				}
			}
			if (killed)
				psk->psk_killed = killed;
			PF_STATE_EXIT_WRITE();
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();
		PF_STATE_ENTER_WRITE();
		RBT_FOREACH_SAFE(st, pf_state_tree_id, &tree_id, nextst) {
			if (st->direction == PF_OUT) {
				sk = st->key[PF_SK_STACK];
				srcaddr = &sk->addr[1];
				dstaddr = &sk->addr[0];
				srcport = sk->port[1];
				dstport = sk->port[0];
			} else {
				sk = st->key[PF_SK_WIRE];
				srcaddr = &sk->addr[0];
				dstaddr = &sk->addr[1];
				srcport = sk->port[0];
				dstport = sk->port[1];
			}
			if ((!psk->psk_af || sk->af == psk->psk_af)
			    && (!psk->psk_proto || psk->psk_proto ==
			    sk->proto) && psk->psk_rdomain == sk->rdomain &&
			    pf_match_addr(psk->psk_src.neg,
			    &psk->psk_src.addr.v.a.addr,
			    &psk->psk_src.addr.v.a.mask,
			    srcaddr, sk->af) &&
			    pf_match_addr(psk->psk_dst.neg,
			    &psk->psk_dst.addr.v.a.addr,
			    &psk->psk_dst.addr.v.a.mask,
			    dstaddr, sk->af) &&
			    (psk->psk_src.port_op == 0 ||
			    pf_match_port(psk->psk_src.port_op,
			    psk->psk_src.port[0], psk->psk_src.port[1],
			    srcport)) &&
			    (psk->psk_dst.port_op == 0 ||
			    pf_match_port(psk->psk_dst.port_op,
			    psk->psk_dst.port[0], psk->psk_dst.port[1],
			    dstport)) &&
			    (!psk->psk_label[0] || (st->rule.ptr->label[0] &&
			    !strcmp(psk->psk_label, st->rule.ptr->label))) &&
			    (!psk->psk_ifname[0] || !strcmp(psk->psk_ifname,
			    st->kif->pfik_name))) {
				pf_remove_state(st);
				killed++;
			}
		}
		psk->psk_killed = killed;
		PF_STATE_EXIT_WRITE();
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

#if NPFSYNC > 0
	case DIOCADDSTATE: {
		struct pfioc_state	*ps = (struct pfioc_state *)addr;
		struct pfsync_state	*sp = &ps->state;

		if (sp->timeout >= PFTM_MAX) {
			error = EINVAL;
			goto fail;
		}
		NET_LOCK();
		PF_LOCK();
		error = pf_state_import(sp, PFSYNC_SI_IOCTL);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}
#endif	/* NPFSYNC > 0 */

	case DIOCGETSTATE: {
		struct pfioc_state	*ps = (struct pfioc_state *)addr;
		struct pf_state		*st;
		struct pf_state_cmp	 id_key;

		memset(&id_key, 0, sizeof(id_key));
		id_key.id = ps->state.id;
		id_key.creatorid = ps->state.creatorid;

		NET_LOCK();
		PF_STATE_ENTER_READ();
		st = pf_find_state_byid(&id_key);
		st = pf_state_ref(st);
		PF_STATE_EXIT_READ();
		NET_UNLOCK();
		if (st == NULL) {
			error = ENOENT;
			goto fail;
		}

		pf_state_export(&ps->state, st);
		pf_state_unref(st);
		break;
	}

	case DIOCGETSTATES: 
		error = pf_states_get((struct pfioc_states *)addr);
		break;

	case DIOCGETSTATUS: {
		struct pf_status *s = (struct pf_status *)addr;
		NET_LOCK();
		PF_LOCK();
		memcpy(s, &pf_status, sizeof(struct pf_status));
		pfi_update_status(s->ifname, s);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCSETSTATUSIF: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans		*t;
		struct pfioc_iface	 pi;

		if (io->esize != sizeof(pi) || io->size != 1) {
			error = ENODEV;
			log(LOG_ERR, "%s DIOCSETSTATUSIF\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &pi, sizeof(pi))) {
			error = EFAULT;
			goto fail;
		}

		strlcpy(t->pftina_opts.statusif, pi.pfiio_name, IFNAMSIZ);
		t->pftina_opts.mask |= PF_TSET_STATUSIF;
		t->pftina_modify_defaults = 1;

		break;
	}

	case DIOCCLRSTATUS: {
		struct pfioc_iface	*pi = (struct pfioc_iface *)addr;

		NET_LOCK();
		PF_LOCK();
		/* if ifname is specified, clear counters there only */
		if (pi->pfiio_name[0]) {
			pfi_update_status(pi->pfiio_name, NULL);
			PF_UNLOCK();
			NET_UNLOCK();
			goto fail;
		}

		memset(pf_status.counters, 0, sizeof(pf_status.counters));
		memset(pf_status.fcounters, 0, sizeof(pf_status.fcounters));
		memset(pf_status.scounters, 0, sizeof(pf_status.scounters));
		pf_status.since = getuptime();

		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCNATLOOK: {
		struct pfioc_natlook	*pnl = (struct pfioc_natlook *)addr;
		struct pf_state_key	*sk;
		struct pf_state		*st;
		struct pf_state_key_cmp	 key;
		int			 m = 0, direction = pnl->direction;
		int			 sidx, didx;

		switch (pnl->af) {
		case AF_INET:
			break;
#ifdef INET6
		case AF_INET6:
			break;
#endif /* INET6 */
		default:
			error = EAFNOSUPPORT;
			goto fail;
		}

		/* NATLOOK src and dst are reversed, so reverse sidx/didx */
		sidx = (direction == PF_IN) ? 1 : 0;
		didx = (direction == PF_IN) ? 0 : 1;

		if (!pnl->proto ||
		    PF_AZERO(&pnl->saddr, pnl->af) ||
		    PF_AZERO(&pnl->daddr, pnl->af) ||
		    ((pnl->proto == IPPROTO_TCP ||
		    pnl->proto == IPPROTO_UDP) &&
		    (!pnl->dport || !pnl->sport)) ||
		    pnl->rdomain > RT_TABLEID_MAX)
			error = EINVAL;
		else {
			key.af = pnl->af;
			key.proto = pnl->proto;
			key.rdomain = pnl->rdomain;
			pf_addrcpy(&key.addr[sidx], &pnl->saddr, pnl->af);
			key.port[sidx] = pnl->sport;
			pf_addrcpy(&key.addr[didx], &pnl->daddr, pnl->af);
			key.port[didx] = pnl->dport;

			NET_LOCK();
			PF_STATE_ENTER_READ();
			st = pf_find_state_all(&key, direction, &m);
			st = pf_state_ref(st);
			PF_STATE_EXIT_READ();
			NET_UNLOCK();

			if (m > 1)
				error = E2BIG;	/* more than one state */
			else if (st != NULL) {
				sk = st->key[sidx];
				pf_addrcpy(&pnl->rsaddr, &sk->addr[sidx],
				    sk->af);
				pnl->rsport = sk->port[sidx];
				pf_addrcpy(&pnl->rdaddr, &sk->addr[didx],
				    sk->af);
				pnl->rdport = sk->port[didx];
				pnl->rrdomain = sk->rdomain;
			} else
				error = ENOENT;
			pf_state_unref(st);
		}
		break;
	}

	case DIOCSETTIMEOUT: {
		struct pfioc_trans *io = (struct pfioc_trans *)addr;
		struct pfioc_tm	 pt;
		struct pf_trans *t;

		if ((io->esize != sizeof(pt)) || (io->size != 1)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCSETTIMEOUT\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &pt, sizeof(pt)) != 0) {
			error = EFAULT;
			goto fail;
		}

		if (pt.timeout < 0 || pt.timeout >= PFTM_MAX ||
		    pt.seconds < 0) {
			error = EINVAL;
			goto fail;
		}
		if (pt.timeout == PFTM_INTERVAL && pt.seconds == 0)
			pt.seconds = 1;
		t->pftina_default_rule.timeout[pt.timeout] = pt.seconds;
		t->pftina_modify_defaults = 1;

		pt.seconds = pf_default_rule.timeout[pt.timeout];

		break;
	}

	case DIOCGETTIMEOUT: {
		struct pfioc_tm	*pt = (struct pfioc_tm *)addr;

		if (pt->timeout < 0 || pt->timeout >= PFTM_MAX) {
			error = EINVAL;
			goto fail;
		}
		PF_LOCK();
		pt->seconds = pf_default_rule.timeout[pt->timeout];
		PF_UNLOCK();
		break;
	}

	case DIOCGETLIMIT: {
		struct pfioc_limit *pl = (struct pfioc_limit *)addr;

		if (pl->index < 0 || pl->index >= PF_LIMIT_MAX) {
			error = EINVAL;
			goto fail;
		}
		PF_LOCK();
		pl->limit = pf_pool_limits[pl->index].limit;
		PF_UNLOCK();
		break;
	}

	case DIOCSETLIMIT: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans		*t;
		struct pfioc_limit	 pl;

		if (io->esize != sizeof(pl) || io->size != 1) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCSETLIMIT\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			log(LOG_DEBUG,
			    "%s DIOCSETLIMIT no transaction for %llu\n",
			    __func__, io->ticket);
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &pl, sizeof(pl)) != 0) {
			error = EFAULT;
			goto fail;
		}

		PF_LOCK();
		if (pl.index < 0 || pl.index >= PF_LIMIT_MAX) {
			error = EINVAL;
			PF_UNLOCK();
			goto fail;
		}
		if (((struct pool *)pf_pool_limits[pl.index].pp)->pr_nout >
		    pl.limit) {
			error = EBUSY;
			PF_UNLOCK();
			goto fail;
		}
		/* Fragments reference mbuf clusters. */
		if (pl.index == PF_LIMIT_FRAGS && pl.limit > nmbclust) {
			error = EINVAL;
			PF_UNLOCK();
			goto fail;
		}

		t->pftina_pool_limits[pl.index] = pl.limit;
		t->pftina_modify_defaults = 1;
		pl.limit = pf_pool_limits[pl.index].limit;
		PF_UNLOCK();
		break;
	}

	case DIOCSETDEBUG: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans	*t;
		u_int32_t	 level;

		if (io->esize != sizeof(level) || io->size != 1) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCSETDEBUG\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &level, sizeof(level))) {
			error = EFAULT;
			goto fail;
		}

		t->pftina_opts.debug = level;
		t->pftina_opts.mask |= PF_TSET_DEBUG;
		t->pftina_modify_defaults = 1;

		break;
	}

	case DIOCGETRULESETS: {
		struct pfioc_ruleset	*pr = (struct pfioc_ruleset *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;

		PF_LOCK();
		pr->path[sizeof(pr->path) - 1] = '\0';
		if ((ruleset = pf_find_ruleset(&pf_global, pr->path)) == NULL) {
			error = EINVAL;
			PF_UNLOCK();
			goto fail;
		}
		pr->nr = 0;
		if (ruleset == &pf_main_ruleset) {
			RB_FOREACH(anchor, pf_anchor_global, &pf_anchors)
				if (anchor->parent == NULL)
					pr->nr++;
		} else {
			RB_FOREACH(anchor, pf_anchor_node,
			    &ruleset->anchor->children)
				pr->nr++;
		}
		PF_UNLOCK();
		break;
	}

	case DIOCGETRULESET: {
		struct pfioc_ruleset	*pr = (struct pfioc_ruleset *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;
		u_int32_t		 nr = 0;

		PF_LOCK();
		pr->path[sizeof(pr->path) - 1] = '\0';
		if ((ruleset = pf_find_ruleset(&pf_global, pr->path)) == NULL) {
			error = EINVAL;
			PF_UNLOCK();
			goto fail;
		}
		pr->name[0] = '\0';
		if (ruleset == &pf_main_ruleset) {
			RB_FOREACH(anchor, pf_anchor_global, &pf_anchors)
				if (anchor->parent == NULL && nr++ == pr->nr) {
					strlcpy(pr->name, anchor->name,
					    sizeof(pr->name));
					break;
				}
		} else {
			RB_FOREACH(anchor, pf_anchor_node,
			    &ruleset->anchor->children)
				if (nr++ == pr->nr) {
					strlcpy(pr->name, anchor->name,
					    sizeof(pr->name));
					break;
				}
		}
		PF_UNLOCK();
		if (!pr->name[0])
			error = EBUSY;
		break;
	}

	case DIOCRCLRTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;
		char *path;

		if (io->pfrio_esize != 0) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRCLRTABLES\n", __func__);
			goto fail;
		}
		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;
		if ((t->pft_ioflags & PFR_FLAG_ALLRSETS) == 0) {
			path = io->pfrio_table.pfrt_anchor;
			while (*path == '/')
				path++;
			strlcpy(t->pfttab_anchor_key.path, path,
			    sizeof(t->pfttab_anchor_key.path));
		}

		NET_LOCK();
		PF_LOCK();

		error = pfr_clr_tables(t);

		PF_UNLOCK();
		NET_UNLOCK();

		if (error == 0)
			io->pfrio_ndel = t->pfttab_ndel;

		pf_rollback_trans(t);
		break;
	}

	case DIOCRADDTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_table)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRADDTABLES\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_tables(t, io->pfrio_buffer, io->pfrio_size);
		if (error != 0) {
			log(LOG_DEBUG, "%s DIOCRADDTABLES error in "
			    "pfr_add_tables\n", __func__);
			pf_rollback_trans(t);
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();

		if (pf_trans_in_conflict(t, "DIOCRADDTABLES") != 0) {
			PF_UNLOCK();
			NET_UNLOCK();
			log(LOG_DEBUG, "%s DIOCRADDTABLES conflict\n",
			    __func__);
			error = EBUSY;
			pf_rollback_trans(t);
			goto fail;
		}

		pf_commit_trans(t);

		PF_UNLOCK();
		NET_UNLOCK();

		io->pfrio_nadd = t->pfttab_nadd;

		pf_rollback_trans(t);
		break;
	}

	case DIOCRDELTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_table)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRDELTABLES\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_tables(t, io->pfrio_buffer, io->pfrio_size);
		if (error != 0) {
			log(LOG_DEBUG, "%s DIOCRDELTABLES error in "
			    "pfr_del_tables\n", __func__);
			pf_rollback_trans(t);
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();

		if (pf_trans_in_conflict(t, "DIOCRDELTABLES") != 0) {
			PF_UNLOCK();
			NET_UNLOCK();
			log(LOG_DEBUG, "%s DIOCRDELTABLES conflict\n",
			    __func__);
			pf_rollback_trans(t);
			goto fail;
		}

		pf_commit_trans(t);

		PF_UNLOCK();
		NET_UNLOCK();

		io->pfrio_ndel = t->pfttab_ndel;

		pf_rollback_trans(t);
		break;
	}

	case DIOCRGETTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;
		char *path;

		if (io->pfrio_esize != sizeof(struct pfr_table)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRGETTABLES\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;
		t->pfttab_size = io->pfrio_size;
		if (io->pfrio_size != 0) {
			t->pfttab_kbuf_sz =
			    io->pfrio_size * sizeof(struct pfr_table);
			t->pfttab_kbuf = malloc(t->pfttab_kbuf_sz, M_PF,
			    M_WAITOK);
		}

		if ((t->pft_ioflags & PFR_FLAG_ALLRSETS) == 0) {
			path = io->pfrio_table.pfrt_anchor;
			while (*path == '/')
				path++;
			strlcpy(t->pfttab_anchor_key.path, path,
			    sizeof(t->pfttab_anchor_key.path));
		}

		NET_LOCK();
		PF_LOCK();

		error = pfr_get_tables(t);

		PF_UNLOCK();
		NET_UNLOCK();

		if ((error == 0) && (t->pfttab_size <= io->pfrio_size))
			error = copyout(t->pfttab_kbuf, io->pfrio_buffer,
			    io->pfrio_size * sizeof(struct pfr_table));

		io->pfrio_size = t->pfttab_size;

		pf_rollback_trans(t);
		break;
	}

	case DIOCRGETTSTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;
		char *path;

		if (io->pfrio_esize != sizeof(struct pfr_tstats)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRGETTSTATS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;
		t->pfttab_size = io->pfrio_size;
		if (io->pfrio_size != 0) {
			t->pfttab_kbuf_sz =
			    io->pfrio_size * sizeof(struct pfr_tstats);
			t->pfttab_kbuf = malloc(t->pfttab_kbuf_sz, M_PF,
			    M_WAITOK);
		}

		if ((io->pfrio_flags & PFR_FLAG_ALLRSETS) == 0) {
			path = io->pfrio_table.pfrt_anchor;
			while (*path == '/')
				path++;
			strlcpy(t->pfttab_anchor_key.path, path,
			    sizeof(t->pfttab_anchor_key.path));
		}

		NET_LOCK();
		PF_LOCK();

		error = pfr_get_tstats(t);

		PF_UNLOCK();
		NET_UNLOCK();

		error = copyout(t->pfttab_kbuf, io->pfrio_buffer,
		    io->pfrio_size * sizeof(struct pfr_tstats));

		pf_rollback_trans(t);

		break;
	}

	case DIOCRCLRTSTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_table)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRCLRTSTATS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_tables(t, io->pfrio_buffer, io->pfrio_size);

		if (error == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRCLRTSTATS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			PF_UNLOCK();
			NET_UNLOCK();
		}

		if (error == 0)
			io->pfrio_nzero = t->pfttab_nzero;

		pf_rollback_trans(t);

		break;
	}

	case DIOCRSETTFLAGS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_table)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRSETTFLAGS\n", __func__);
			goto fail;
		}

		if ((io->pfrio_setflag & ~PFR_TFLAG_USRMASK) ||
		    (io->pfrio_clrflag & ~PFR_TFLAG_USRMASK) ||
		    (io->pfrio_setflag & io->pfrio_clrflag)) {
			error = EINVAL;
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags;

		t->pfttab_setf = io->pfrio_setflag;
		t->pfttab_clrf = io->pfrio_clrflag;
		error = pfr_copyin_tables(t, io->pfrio_buffer, io->pfrio_size);

		if (error == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRSETTFLAGS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			PF_UNLOCK();
			NET_UNLOCK();
		}

		if (error == 0) {
			io->pfrio_ndel = t->pfttab_ndel;
			io->pfrio_nchange = t->pfttab_nchg;
		}

		pf_rollback_trans(t);
		break;
	}

	case DIOCRCLRADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;
		struct pfr_ktable *ktt;

		if (io->pfrio_esize != 0) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRCLRADDRS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags;
		ktt = pfr_create_ktable(&t->pfttab_rc, &io->pfrio_table,
		    gettime(), PR_WAITOK);
		if (ktt == NULL) {
			error = EINVAL;
			goto fail;
		}
		if (ktt->pfrkt_version == 0) {
			error = ESRCH;
			goto fail;
		}

		if ((io->pfrio_flags & PFR_FLAG_DUMMY) == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRCLRADDRS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			PF_UNLOCK();
			NET_UNLOCK();
		}

		break;
	}

	case DIOCRADDADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRADDADDRS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_addrs(t, &io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size);

		if (error == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRADDADDRS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			NET_UNLOCK();
			PF_UNLOCK();

			error = pfr_addrs_feedback(t, io->pfrio_buffer,
			    io->pfrio_size, PFR_IOQ_ONLY);
			io->pfrio_nadd = t->pfttab_nadd;
		}

		pf_rollback_trans(t);

		break;
	}

	case DIOCRDELADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRDELADDRS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_addrs(t, &io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size);

		if (error == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRDELADDRS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			PF_UNLOCK();
			NET_UNLOCK();

			error = pfr_addrs_feedback(t, io->pfrio_buffer,
			    io->pfrio_size, PFR_IOQ_ONLY);
			io->pfrio_ndel = t->pfttab_ndel;
		}

		pf_rollback_trans(t);
		break;
	}

	case DIOCRSETADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRSETADDRS\n", __func__);
			goto fail;
		}

		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pfttab_iocmd = cmd;
		t->pft_ioflags = io->pfrio_flags | PFR_FLAG_USERIOCTL;

		error = pfr_copyin_addrs(t, &io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size);

		if (error == 0) {
			NET_LOCK();
			PF_LOCK();

			if (pf_trans_in_conflict(t, "DIOCRSETADDRS"))
				error = EBUSY;
			else
				pf_commit_trans(t);

			PF_UNLOCK();
			NET_UNLOCK();

			pfr_addrs_feedback(t, io->pfrio_buffer, io->pfrio_size,
			    PFR_GARBAGE_TOO);
			io->pfrio_nadd = t->pfttab_nadd;
			io->pfrio_ndel = t->pfttab_ndel;
			io->pfrio_nchange = t->pfttab_nchg;

			/*
			 * forget deleted addresses, so pf_rollback_trans()
			 * won't purge them
			 */
			if (io->pfrio_flags & PFR_FLAG_DUMMY)
				SLIST_INIT(&t->pfttab_ke_garbage);
		}

		pf_rollback_trans(t);

		break;
	}

	case DIOCRGETADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRGETADDRS\n", __func__);
			goto fail;
		}
		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pft_ioflags = io->pfrio_flags;
		t->pfttab_iocmd = cmd;
		NET_LOCK();
		PF_LOCK();
		error = pfr_get_addrs(t, &io->pfrio_table, &io->pfrio_size);
		PF_UNLOCK();
		NET_UNLOCK();

		if (error == 0)
			error = pfr_copyout_addrs(t, io->pfrio_buffer);
		/*
		 * forget entries we copied out so pf_rollback_trans() won't
		 * attempt to free them.
		 */
		SLIST_INIT(&t->pfttab_ke_ioq);
		pf_rollback_trans(t);
		break;
	}

	case DIOCRGETASTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_astats)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRGETASTATS\n", __func__);
			goto fail;
		}
		t = pf_open_trans(minor(dev));
		pf_init_ttab(t);
		t->pft_ioflags = io->pfrio_flags;
		t->pfttab_iocmd = DIOCRGETASTATS;
		NET_LOCK();
		PF_LOCK();
		error = pfr_get_astats(t, &io->pfrio_table, &io->pfrio_size);
		PF_UNLOCK();
		NET_UNLOCK();

		if (error == 0)
			error = pfr_copyout_addrs(t, io->pfrio_buffer);
		/*
		 * forget entries we copied out so pf_rollback_trans() won't
		 * attempt to free them.
		 */
		SLIST_INIT(&t->pfttab_ke_ioq);
		pf_rollback_trans(t);
		break;
	}

	case DIOCRCLRASTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRCLRASTATS\n", __func__);
			goto fail;
		}
		NET_LOCK();
		PF_LOCK();
		error = pfr_clr_astats(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nzero, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCRTSTADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRTSTADDRS\n", __func__);
			goto fail;
		}
		NET_LOCK();
		PF_LOCK();
		error = pfr_tst_addrs(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nmatch, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCRINADEFINE: {
		struct pfioc_table *io = (struct pfioc_table *)addr;
		struct pf_trans *t;

		if (io->pfrio_esize != sizeof(struct pfr_addr)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRINADEFINE\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->pfrio_ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		error = pfr_ina_define(t, &io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nadd, &io->pfrio_naddr,
		    io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCOSFPADD: {
		struct pf_osfp_ioctl *io = (struct pf_osfp_ioctl *)addr;
		error = pf_osfp_add(io);
		break;
	}

	case DIOCOSFPGET: {
		struct pf_osfp_ioctl *io = (struct pf_osfp_ioctl *)addr;
		error = pf_osfp_get(io);
		break;
	}

	case DIOCXRULESET: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pfioc_trans_e	*ioe;
		struct pf_trans		*t = NULL;
		struct pfr_table	*table;
		int			 i;

		if (io->esize != sizeof(*ioe)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCRULESET %d != %lu\n", __func__,
			    io->esize, sizeof(*ioe));
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		ioe = malloc(sizeof(*ioe), M_PF, M_WAITOK);
		table = malloc(sizeof(*table), M_PF, M_WAITOK);

		for (i = 0; i < io->size; i++) {
			if (copyin(io->array + (i*sizeof(*ioe)) , ioe,
			    sizeof(*ioe))) {
				free(table, M_PF, sizeof(*table));
				free(ioe, M_PF, sizeof(*ioe));
				pf_rollback_trans(t);
				error = EFAULT;
				goto fail;
			}
			if (strnlen(ioe->anchor, sizeof(ioe->anchor)) ==
			    sizeof(ioe->anchor)) {
				free(table, M_PF, sizeof(*table));
				free(ioe, M_PF, sizeof(*ioe));
				pf_rollback_trans(t);
				error = ENAMETOOLONG;
				goto fail;
			}
			switch (ioe->type) {
			case PF_TRANS_TABLE:
			case PF_TRANS_RULESET:
				error = pf_begin_rules(t, ioe->anchor);
				if (error != 0) {
					free(table, M_PF, sizeof(*table));
					free(ioe, M_PF, sizeof(*ioe));
					pf_rollback_trans(t);
					goto fail;
				}
				break;
			default:
				free(table, M_PF, sizeof(*table));
				free(ioe, M_PF, sizeof(*ioe));
				log(LOG_DEBUG, "%s [i] unknown type\n", __func__);
				error = EINVAL;
				pf_rollback_trans(t);
				goto fail;
			}
		}
		free(table, M_PF, sizeof(*table));
		free(ioe, M_PF, sizeof(*ioe));
		log(LOG_DEBUG, "%s DIOCXRULESET is done\n", __func__);

		break;
	}

	case DIOCXBEGIN: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans		*t = NULL;

		t = pf_open_trans(minor(dev));
		pf_init_tina(t);

		if (io->array != NULL)
			error = copyinstr(io->array, t->pftina_anchor_path,
			    sizeof(t->pftina_anchor_path), NULL);

		log(LOG_DEBUG, "%s transaction: %llu on %s\n", __func__,
		    t->pft_ticket, t->pftina_anchor_path);

		if (error == 0)
			io->ticket = t->pft_ticket;
		break;
	}

	case DIOCXROLLBACK: {
		struct pf_trans		*t;
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;

		t = pf_find_trans(minor(dev), io->ticket);
		if (t != NULL)
			pf_rollback_trans(t);
		else
			error = ENXIO;
		io->ticket = 0;

		break;
	}

	case DIOCXCOMMIT: {
		struct pf_trans		*t;
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;

		/*
		 * Looks like we will have to distinguish various
		 * transaction types:
		 *	DIOCXRULESET/ina_define
		 *
		 * 	DIOCRCLRTSTATS
		 *
		 *	DIOCRADDTABLES
		 *
		 *	DIOCRSETADDRS
		 *
		 *	DIOCRSETTFLAGS
		 *	...
		 *
		 * this kind of hint may make implementation of
		 * commit operation lot easier.
		 *
		 * after thinking more about things:
		 *	I prefer we bump ruleset version iff
		 *	we change rules.
		 *
		 *	tables bound to rulesets carry their own
		 *	version number.
		 *
		 * we should check ruleset version iff and only iff we
		 * will be changing rules. if we will be changing table
		 * bound to ruleset then ruleset version can be ignored.
		 */
		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}
		if (t->pft_type != PF_TRANS_INA) {
			error = EINVAL;
			goto fail;
		}

		NET_LOCK();
		PF_LOCK();
		if (pf_trans_in_conflict(t, "DIOCXCOMMIT"))
			error = EBUSY;
		else {
			pf_drop_unused_tables(t);
			pf_commit_trans(t);
			pfi_xcommit();
		}

		PF_UNLOCK();
		NET_UNLOCK();

		/*
		 * use rollback to release stuff which became invalidated.
		 */
		pf_rollback_trans(t);
		break;
	}

	case DIOCXEND: {
		u_int32_t	*ticket = (u_int32_t *)addr;
		struct pf_trans	*t;

		t = pf_find_trans(minor(dev), *ticket);
		if (t != NULL)
			pf_rollback_trans(t);
		else
			error = ENXIO;
		break;
	}

	case DIOCGETSRCNODES: {
		struct pfioc_src_nodes	*psn = (struct pfioc_src_nodes *)addr;
		struct pf_src_node	*n, *p, *pstore;
		u_int32_t		 nr = 0;
		size_t			 space = psn->psn_len;

		pstore = malloc(sizeof(*pstore), M_PF, M_WAITOK);

		NET_LOCK();
		PF_LOCK();
		if (space == 0) {
			RB_FOREACH(n, pf_src_tree, &tree_src_tracking)
				nr++;
			psn->psn_len = sizeof(struct pf_src_node) * nr;
			PF_UNLOCK();
			NET_UNLOCK();
			free(pstore, M_PF, sizeof(*pstore));
			goto fail;
		}

		p = psn->psn_src_nodes;
		RB_FOREACH(n, pf_src_tree, &tree_src_tracking) {
			int	secs = getuptime(), diff;

			if ((nr + 1) * sizeof(*p) > psn->psn_len)
				break;

			memcpy(pstore, n, sizeof(*pstore));
			memset(&pstore->entry, 0, sizeof(pstore->entry));
			pstore->rule.ptr = NULL;
			pstore->kif = NULL;
			pstore->rule.nr = n->rule.ptr->nr;
			pstore->creation = secs - pstore->creation;
			if (pstore->expire > secs)
				pstore->expire -= secs;
			else
				pstore->expire = 0;

			/* adjust the connection rate estimate */
			diff = secs - n->conn_rate.last;
			if (diff >= n->conn_rate.seconds)
				pstore->conn_rate.count = 0;
			else
				pstore->conn_rate.count -=
				    n->conn_rate.count * diff /
				    n->conn_rate.seconds;

			error = copyout(pstore, p, sizeof(*p));
			if (error) {
				PF_UNLOCK();
				NET_UNLOCK();
				free(pstore, M_PF, sizeof(*pstore));
				goto fail;
			}
			p++;
			nr++;
		}
		psn->psn_len = sizeof(struct pf_src_node) * nr;

		PF_UNLOCK();
		NET_UNLOCK();
		free(pstore, M_PF, sizeof(*pstore));
		break;
	}

	case DIOCCLRSRCNODES: {
		struct pf_src_node	*n;
		struct pf_state		*st;

		NET_LOCK();
		PF_LOCK();
		PF_STATE_ENTER_WRITE();
		RBT_FOREACH(st, pf_state_tree_id, &tree_id)
			pf_src_tree_remove_state(st);
		PF_STATE_EXIT_WRITE();
		RB_FOREACH(n, pf_src_tree, &tree_src_tracking)
			n->expire = 1;
		pf_purge_expired_src_nodes();
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCKILLSRCNODES: {
		struct pf_src_node	*sn;
		struct pf_state		*st;
		struct pfioc_src_node_kill *psnk =
		    (struct pfioc_src_node_kill *)addr;
		u_int			killed = 0;

		NET_LOCK();
		PF_LOCK();
		RB_FOREACH(sn, pf_src_tree, &tree_src_tracking) {
			if (pf_match_addr(psnk->psnk_src.neg,
				&psnk->psnk_src.addr.v.a.addr,
				&psnk->psnk_src.addr.v.a.mask,
				&sn->addr, sn->af) &&
			    pf_match_addr(psnk->psnk_dst.neg,
				&psnk->psnk_dst.addr.v.a.addr,
				&psnk->psnk_dst.addr.v.a.mask,
				&sn->raddr, sn->af)) {
				/* Handle state to src_node linkage */
				if (sn->states != 0) {
					PF_ASSERT_LOCKED();
					PF_STATE_ENTER_WRITE();
					RBT_FOREACH(st, pf_state_tree_id,
					   &tree_id)
						pf_state_rm_src_node(st, sn);
					PF_STATE_EXIT_WRITE();
				}
				sn->expire = 1;
				killed++;
			}
		}

		if (killed > 0)
			pf_purge_expired_src_nodes();

		psnk->psnk_killed = killed;
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCSETHOSTID: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans		*t;
		u_int32_t	hostid;

		if (io->esize != sizeof(hostid) || io->size != 1) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCSETHOSTID\n", __func__);
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &hostid, sizeof(hostid))) {
			error = EFAULT;
			goto fail;
		}

		if (hostid == 0)
			t->pftina_opts.hostid = arc4random();
		else
			t->pftina_opts.hostid = hostid;

		t->pftina_opts.mask |= PF_TSET_HOSTID;
		t->pftina_modify_defaults = 1;

		break;
	}

	case DIOCOSFPFLUSH:
		pf_osfp_flush();
		break;

	case DIOCIGETIFACES: {
		struct pfioc_iface	*io = (struct pfioc_iface *)addr;
		struct pfi_kif		*kif_buf;
		int			 apfiio_size = io->pfiio_size;

		if (io->pfiio_esize != sizeof(struct pfi_kif)) {
			error = ENODEV;
			log(LOG_DEBUG, "%s DIOCIGETIFACES\n", __func__);
			goto fail;
		}

		if ((kif_buf = mallocarray(sizeof(*kif_buf), apfiio_size,
		    M_PF, M_WAITOK|M_CANFAIL)) == NULL) {
			error = EINVAL;
			goto fail;
		}

		NET_LOCK_SHARED();
		PF_LOCK();
		pfi_get_ifaces(io->pfiio_name, kif_buf, &io->pfiio_size);
		PF_UNLOCK();
		NET_UNLOCK_SHARED();
		if (copyout(kif_buf, io->pfiio_buffer, sizeof(*kif_buf) *
		    io->pfiio_size))
			error = EFAULT;
		free(kif_buf, M_PF, sizeof(*kif_buf) * apfiio_size);
		break;
	}

	case DIOCSETIFFLAG: {
		struct pfioc_iface *io = (struct pfioc_iface *)addr;

		if (io == NULL) {
			error = EINVAL;
			goto fail;
		}

		PF_LOCK();
		error = pfi_set_flags(io->pfiio_name, io->pfiio_flags);
		PF_UNLOCK();
		break;
	}

	case DIOCCLRIFFLAG: {
		struct pfioc_iface *io = (struct pfioc_iface *)addr;

		if (io == NULL) {
			error = EINVAL;
			goto fail;
		}

		PF_LOCK();
		error = pfi_clear_flags(io->pfiio_name, io->pfiio_flags);
		PF_UNLOCK();
		break;
	}

	case DIOCSETREASS: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pf_trans		*t;
		u_int32_t	 reass;

		if (io->esize != sizeof(reass) || io->size != 1) {
			error = EINVAL;
			goto fail;
		}

		t = pf_find_trans(minor(dev), io->ticket);
		if (t == NULL) {
			error = ENXIO;
			goto fail;
		}

		if (copyin(io->array, &reass, sizeof(reass))) {
			error = EFAULT;
			goto fail;
		}

		t->pftina_opts.reass = reass;
		t->pftina_opts.mask |= PF_TSET_REASS;
		t->pftina_modify_defaults = 1;

		break;
	}

	case DIOCSETSYNFLWATS: {
		struct pfioc_synflwats *io = (struct pfioc_synflwats *)addr;

		NET_LOCK();
		PF_LOCK();
		error = pf_syncookies_setwats(io->hiwat, io->lowat);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCGETSYNFLWATS: {
		struct pfioc_synflwats *io = (struct pfioc_synflwats *)addr;

		NET_LOCK();
		PF_LOCK();
		error = pf_syncookies_getwats(io);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	case DIOCSETSYNCOOKIES: {
		u_int8_t	*mode = (u_int8_t *)addr;

		NET_LOCK();
		PF_LOCK();
		error = pf_syncookies_setmode(*mode);
		PF_UNLOCK();
		NET_UNLOCK();
		break;
	}

	default:
		error = ENODEV;
		log(LOG_DEBUG, "%s default unknown iocmd (%lx) ]\n",
		    __func__, cmd);
		break;
	}
fail:
	rw_exit_write(&pfioctl_rw);

	return (error);
}

void
pf_trans_set_commit(struct pf_opts *status)
{
	if (status->mask & PF_TSET_STATUSIF) {
		memset(pf_status.ifname, 0, IFNAMSIZ);
		strlcpy(pf_status.ifname, status->statusif, IFNAMSIZ);
	}
	if (status->mask & PF_TSET_DEBUG)
		pf_status.debug = status->debug;
	if (status->mask & PF_TSET_HOSTID)
		pf_status.hostid = status->hostid;
	if (status->mask & PF_TSET_REASS)
		pf_status.reass = status->reass;
}

void
pf_pool_copyin(struct pf_pool *from, struct pf_pool *to)
{
	memmove(to, from, sizeof(*to));
	to->kif = NULL;
	to->addr.p.tbl = NULL;
}

int
pf_validate_range(u_int8_t op, u_int16_t port[2], int order)
{
	u_int16_t a = (order == PF_ORDER_NET) ? ntohs(port[0]) : port[0];
	u_int16_t b = (order == PF_ORDER_NET) ? ntohs(port[1]) : port[1];

	if ((op == PF_OP_RRG && a > b) ||  /* 34:12,  i.e. none */
	    (op == PF_OP_IRG && a >= b) || /* 34><12, i.e. none */
	    (op == PF_OP_XRG && a > b))    /* 34<>22, i.e. all */
		return 1;
	return 0;
}

int
pf_rule_copyin(struct pf_rule *from, struct pf_rule *to)
{
	int i;

	if (from->scrub_flags & PFSTATE_SETPRIO &&
	    (from->set_prio[0] > IFQ_MAXPRIO ||
	    from->set_prio[1] > IFQ_MAXPRIO))
		return (EINVAL);

	to->src = from->src;
	to->src.addr.p.tbl = NULL;
	to->dst = from->dst;
	to->dst.addr.p.tbl = NULL;

	if (pf_validate_range(to->src.port_op, to->src.port, PF_ORDER_NET))
		return (EINVAL);
	if (pf_validate_range(to->dst.port_op, to->dst.port, PF_ORDER_NET))
		return (EINVAL);

	/* XXX union skip[] */

	strlcpy(to->label, from->label, sizeof(to->label));
	strlcpy(to->ifname, from->ifname, sizeof(to->ifname));
	strlcpy(to->rcv_ifname, from->rcv_ifname, sizeof(to->rcv_ifname));
	strlcpy(to->qname, from->qname, sizeof(to->qname));
	strlcpy(to->pqname, from->pqname, sizeof(to->pqname));
	strlcpy(to->tagname, from->tagname, sizeof(to->tagname));
	strlcpy(to->match_tagname, from->match_tagname,
	    sizeof(to->match_tagname));
	strlcpy(to->overload_tblname, from->overload_tblname,
	    sizeof(to->overload_tblname));

	pf_pool_copyin(&from->nat, &to->nat);
	pf_pool_copyin(&from->rdr, &to->rdr);
	pf_pool_copyin(&from->route, &to->route);

	if (pf_validate_range(to->rdr.port_op, to->rdr.proxy_port,
	    PF_ORDER_HOST))
		return (EINVAL);

	to->kif = (to->ifname[0]) ?
	    pfi_kif_alloc(to->ifname, M_WAITOK) : NULL;
	to->rcv_kif = (to->rcv_ifname[0]) ?
	    pfi_kif_alloc(to->rcv_ifname, M_WAITOK) : NULL;
	to->rdr.kif = (to->rdr.ifname[0]) ?
	    pfi_kif_alloc(to->rdr.ifname, M_WAITOK) : NULL;
	to->nat.kif = (to->nat.ifname[0]) ?
	    pfi_kif_alloc(to->nat.ifname, M_WAITOK) : NULL;
	to->route.kif = (to->route.ifname[0]) ?
	    pfi_kif_alloc(to->route.ifname, M_WAITOK) : NULL;

	to->os_fingerprint = from->os_fingerprint;

	to->rtableid = from->rtableid;
	if (to->rtableid >= 0 && !rtable_exists(to->rtableid))
		return (EBUSY);
	to->onrdomain = from->onrdomain;
	if (to->onrdomain != -1 && (to->onrdomain < 0 ||
	    to->onrdomain > RT_TABLEID_MAX))
		return (EINVAL);

	for (i = 0; i < PFTM_MAX; i++)
		to->timeout[i] = from->timeout[i];
	to->states_tot = from->states_tot;
	to->max_states = from->max_states;
	to->max_src_nodes = from->max_src_nodes;
	to->max_src_states = from->max_src_states;
	to->max_src_conn = from->max_src_conn;
	to->max_src_conn_rate.limit = from->max_src_conn_rate.limit;
	to->max_src_conn_rate.seconds = from->max_src_conn_rate.seconds;
	pf_init_threshold(&to->pktrate, from->pktrate.limit,
	    from->pktrate.seconds);

	if (to->qname[0] != 0) {
		if ((to->qid = pf_qname2qid(to->qname, 0)) == 0)
			return (EBUSY);
		if (to->pqname[0] != 0) {
			if ((to->pqid = pf_qname2qid(to->pqname, 0)) == 0)
				return (EBUSY);
		} else
			to->pqid = to->qid;
	}
	to->rt_listid = from->rt_listid;
	to->prob = from->prob;
	to->return_icmp = from->return_icmp;
	to->return_icmp6 = from->return_icmp6;
	to->max_mss = from->max_mss;
	if (to->tagname[0])
		if ((to->tag = pf_tagname2tag(to->tagname, 1)) == 0)
			return (EBUSY);
	if (to->match_tagname[0])
		if ((to->match_tag = pf_tagname2tag(to->match_tagname, 1)) == 0)
			return (EBUSY);
	to->scrub_flags = from->scrub_flags;
	to->delay = from->delay;
	to->uid = from->uid;
	to->gid = from->gid;
	to->rule_flag = from->rule_flag;
	to->action = from->action;
	to->direction = from->direction;
	to->log = from->log;
	to->logif = from->logif;
#if NPFLOG > 0
	if (!to->log)
		to->logif = 0;
#endif	/* NPFLOG > 0 */
	to->quick = from->quick;
	to->ifnot = from->ifnot;
	to->rcvifnot = from->rcvifnot;
	to->match_tag_not = from->match_tag_not;
	to->keep_state = from->keep_state;
	to->af = from->af;
	to->naf = from->naf;
	to->proto = from->proto;
	to->type = from->type;
	to->code = from->code;
	to->flags = from->flags;
	to->flagset = from->flagset;
	to->min_ttl = from->min_ttl;
	to->allow_opts = from->allow_opts;
	to->rt = from->rt;
	to->return_ttl = from->return_ttl;
	to->tos = from->tos;
	to->set_tos = from->set_tos;
	to->anchor_relative = from->anchor_relative; /* XXX */
	to->anchor_wildcard = from->anchor_wildcard; /* XXX */
	to->flush = from->flush;
	to->divert.addr = from->divert.addr;
	to->divert.port = from->divert.port;
	to->divert.type = from->divert.type;
	to->prio = from->prio;
	to->set_prio[0] = from->set_prio[0];
	to->set_prio[1] = from->set_prio[1];

	return (0);
}

int
pf_rule_checkaf(struct pf_rule *r)
{
	switch (r->af) {
	case 0:
		if (r->rule_flag & PFRULE_AFTO)
			return (EPFNOSUPPORT);
		break;
	case AF_INET:
		if ((r->rule_flag & PFRULE_AFTO) && r->naf != AF_INET6)
			return (EPFNOSUPPORT);
		break;
#ifdef INET6
	case AF_INET6:
		if ((r->rule_flag & PFRULE_AFTO) && r->naf != AF_INET)
			return (EPFNOSUPPORT);
		break;
#endif /* INET6 */
	default:
		return (EPFNOSUPPORT);
	}

	if ((r->rule_flag & PFRULE_AFTO) == 0 && r->naf != 0)
		return (EPFNOSUPPORT);

	return (0);
}

int
pf_sysctl(void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	struct pf_status	pfs;

	NET_LOCK_SHARED();
	PF_LOCK();
	memcpy(&pfs, &pf_status, sizeof(struct pf_status));
	pfi_update_status(pfs.ifname, &pfs);
	PF_UNLOCK();
	NET_UNLOCK_SHARED();

	return sysctl_rdstruct(oldp, oldlenp, newp, &pfs, sizeof(pfs));
}

struct pf_trans *
pf_open_trans(uint32_t unit)
{
	static uint64_t ticket = 1;
	struct pf_trans *t;

	rw_assert_wrlock(&pfioctl_rw);

	KASSERT(pf_unit2idx(unit) < nitems(pf_tcount));
	if (pf_tcount[pf_unit2idx(unit)] >= (PF_ANCHOR_STACK_MAX * 8))
		return (NULL);

	t = malloc(sizeof(*t), M_PF, M_WAITOK|M_ZERO);
	t->pft_unit = unit;
	t->pft_ticket = ticket++;
	pf_tcount[pf_unit2idx(unit)]++;

	LIST_INSERT_HEAD(&pf_ioctl_trans, t, pft_entry);

	return (t);
}

struct pf_trans *
pf_find_trans(uint32_t unit, uint64_t ticket)
{
	struct pf_trans	*t;

	rw_assert_anylock(&pfioctl_rw);

	LIST_FOREACH(t, &pf_ioctl_trans, pft_entry) {
		if (t->pft_ticket == ticket && t->pft_unit == unit)
			break;
	}

	return (t);
}

void
pf_init_tgetrule(struct pf_trans *t, struct pf_anchor *a,
    uint32_t rs_version, struct pf_rule *r)
{
	t->pft_type = PF_TRANS_GETRULE;
	if (a == NULL)
		t->pftgr_anchor = &pf_main_anchor;
	else
		t->pftgr_anchor = a;

	t->pftgr_version = rs_version;
	t->pftgr_rule = r;
}

void
pf_cleanup_tgetrule(struct pf_trans *t)
{
	KASSERT(t->pft_type == PF_TRANS_GETRULE);
	pf_anchor_rele(t->pftgr_anchor);
}

int
pf_ina_check(struct pf_anchor *ta, struct pf_anchor *a)
{
	u_int32_t version;
	int conflict;
	struct pfr_ktable *kt, *tkt;

	/*
	 * if anchor does not exist in global tree, then
	 * transaction is about to create/insert new anchor.
	 * in this case we expect to see version 0.
	 *
	 * Same goes to tkt later. If desired table is not
	 * found at global anchor, then we are adding/creating
	 * a new table to anchor. Therefore expected version
	 * must be 0.
	 */
	if (a != NULL)
		version = a->ruleset.rules.version;
	else
		version = 0;

	conflict = (version != ta->ruleset.rules.version);

	if ((conflict == 0) && (a != NULL)) {
		RB_FOREACH(tkt, pfr_ktablehead, &ta->ktables) {
			kt = RB_FIND(pfr_ktablehead, &a->ktables, tkt);
			if (kt == NULL)
				conflict = (tkt->pfrkt_version != 0);
			else
				conflict =
				    (tkt->pfrkt_version != kt->pfrkt_version);

			if (conflict) {
				log(LOG_DEBUG,
				    "%s table (%s@%s) version mismatch "
				    "(%u vs. %u)\n",
				    __func__,
				    tkt->pfrkt_name,
				    PF_ANCHOR_PATH(a),
				    tkt->pfrkt_version,
				    (kt == NULL) ? 0 : kt->pfrkt_version);
				break;
			}
		}
	} else {
		log(LOG_DEBUG,
		    "%s ruleset (%s) version match (%u vs. %u)\n",
		    __func__,
		    PF_ANCHOR_PATH(ta),
		    ta->ruleset.rules.version,
		    (a == NULL) ? 0 : a->ruleset.rules.version);
	}

	return (conflict);
}

int
pf_tab_check(struct pf_anchor *ta, struct pf_anchor *a)
{
	int conflict = 0;
	struct pfr_ktable *kt, *tkt;

	if (a == NULL) {
		RB_FOREACH(tkt, pfr_ktablehead, &ta->ktables) {
			if (tkt->pfrkt_version != 0) {
				log(LOG_DEBUG,
				    "%s table (%s@%s) version mismatch "
				    "(%u vs. 0)\n",
				    __func__,
				    tkt->pfrkt_name,
				    PF_ANCHOR_PATH(a),
				    tkt->pfrkt_version);
				conflict = 1;
				break;
			}
		}
	} else {
		RB_FOREACH(tkt, pfr_ktablehead, &ta->ktables) {
			kt = RB_FIND(pfr_ktablehead, &a->ktables, tkt);
			if (kt == NULL)
				conflict = (tkt->pfrkt_version != 0);
			else
				conflict =
				    (tkt->pfrkt_version != kt->pfrkt_version);

			if (conflict) {
				log(LOG_DEBUG,
				    "%s table (%s@%s) version mismatch "
				    "(%u vs. %u)\n",
				    __func__,
				    tkt->pfrkt_name,
				    PF_ANCHOR_PATH(a),
				    tkt->pfrkt_version,
				    (kt == NULL) ? 0 : kt->pfrkt_version);
				break;
			}
		}
	}

	return (conflict);
}

int
pf_trans_chk_ina(struct pf_trans *t, const char *iocmdname)
{
	int			 i, conflict = 0;
	struct pf_anchor	*ta, *a;
	struct pool		*pp;

	if ((t->pftina_anchor_path[0] == '\0') &&
	    (t->pftina_rc.main_anchor.ruleset.rules.version != 0))
		conflict = pf_ina_check(&t->pftina_rc.main_anchor,
		    &pf_main_anchor);
	
	/* check if defaults can be modified/updated */
	if (conflict == 0 && t->pftina_modify_defaults) {
		conflict = (t->pftina_default_vers != pf_default_vers);
		for (i = 0; i < PF_LIMIT_MAX && conflict == 0; i++) {
			pp = (struct pool *)pf_pool_limits[i].pp;
			if (t->pftina_pool_limits[i] > 0 &&
			    pp->pr_nout > t->pftina_pool_limits[i]) {
				log(LOG_WARNING, "pr_nout (%u) exceeds new "
				    "limit (%u) for %s\n",
				    pp->pr_nout,
				    t->pftina_pool_limits[i],
				    pp->pr_wchan);
				conflict = 1;
			}
		}
	}

	log(LOG_DEBUG, "%s:%s (defaults) conflict == %d\n", __func__,
	    iocmdname, conflict);

	/*
	 * check anchor versions in transaction to match versions found in
	 * global table.
	 */
	if (conflict == 0) {
		RB_FOREACH(ta, pf_anchor_global, &t->pftina_rc.anchors) {
			a = RB_FIND(pf_anchor_global, &pf_global.anchors, ta);
			conflict = pf_ina_check(ta, a);
			if (conflict != 0)
				break;
		}
	}

	return (conflict);
}

int
pf_trans_chk_tab(struct pf_trans *t, const char *iocmdname)
{
	int	conflict = 0;
	struct pf_anchor	*ta, *a;

	conflict = pf_tab_check(&t->pfttab_rc.main_anchor, &pf_main_anchor);

	if (conflict == 0) {
		RB_FOREACH(ta, pf_anchor_global, &t->pfttab_rc.anchors) {
			a = RB_FIND(pf_anchor_global, &pf_global.anchors, ta);
			conflict = pf_tab_check(ta, a);
			if (conflict != 0)
				break;
		}
	}

	return (conflict);
}

int
pf_trans_in_conflict(struct pf_trans *t, const char *iocmdname)
{
	int	conflict = 1;

	switch (t->pft_type) {
	case PF_TRANS_INA:
		conflict = pf_trans_chk_ina(t, iocmdname);
		break;
	case PF_TRANS_TAB:
		conflict = pf_trans_chk_tab(t, iocmdname);
		break;
	default:
		panic("%s unknown transaction type %d", __func__ , t->pft_type);
	}
	return (conflict);
}

const char *
pf_match_root_path(const char *a, const char *b)
{
	const char *wa;

	if (b == NULL || *b == '\0')
		return (a);

	wa = a;
	while (*b && *b == *wa) {
		b++;
		wa++;
	}

	return ((*b == '\0') ? a : NULL);
}

void
pf_update_parent(struct pf_anchor *ta)
{
	struct pf_anchor *parent, *exists;

	if (ta->parent == NULL)
		return;

	parent = RB_FIND(pf_anchor_global, &pf_anchors, ta->parent);
	/*
	 * It's granted the matching parent in global tree
	 * will exist, because we process from root (parents)
	 * towards leaf.
	 *
	 * We only must make sure we refer to parent found
	 * pf_anchors and not in t->anchors.
	 */
	KASSERT(parent != NULL);
	if (parent != ta->parent) {
		/*
		 * The parent in global tree is different
		 */
		log(LOG_DEBUG, "%s parent (%s) found for %s in global tree\n",
		    __func__,
		    PF_ANCHOR_PATH(ta),
		    ta->path);
		RB_REMOVE(pf_anchor_node, &ta->parent->children, ta);
		exists = RB_INSERT(pf_anchor_node, &parent->children, ta);
		KASSERT(exists == NULL);
	} else {
		/*
		 * anchor must be present in parent's children already
		 */
		KASSERT(
		    RB_FIND(pf_anchor_node, &parent->children, ta) != NULL);
		log(LOG_DEBUG,
		    "%s parent (%s) found in pf_anchors, we are good\n",
		    __func__,
		    PF_ANCHOR_PATH(parent));
	}
}

void
pf_ina_commit_anchor(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	struct pf_anchor *exists;

	if (a == NULL) {
		/*
		 * Do not create empty rulesets.
		 */
		if (TAILQ_EMPTY(ta->ruleset.rules.ptr) &&
		    ta->tables == 0 && RB_EMPTY(&ta->children)) {
			log(LOG_DEBUG, "%s will not create empty anchor %s\n",
			    __func__, ta->path);
			/*
			 * removing ourselves from our direct parent is
			 * sufficient the rulesets (RB-tree) is walked from
			 * left to right (MIN -> MAX, parent is always grater
			 * than child).
			 */
			if (ta->parent != NULL)
				RB_REMOVE(pf_anchor_node,
				    &ta->parent->children, ta);
			return;
		}

		RB_REMOVE(pf_anchor_global, &t->pftina_rc.anchors, ta);
		exists = RB_INSERT(pf_anchor_global, &pf_anchors, ta);
		KASSERT(exists == NULL);
		if (ta->parent != NULL)
			pf_update_parent(ta);
		ta->ruleset.rules.version++;
	} else {
		if (pf_match_root_path(a->path, t->pftina_anchor_path) ==
		    a->path)
			pf_swap_anchors_ina(t, ta, a);
		else
			log(LOG_DEBUG, "%s skipping %s\n",
			    __func__, a->path);
	}
}

void
pf_fix_main_children(void)
{
	struct pf_anchor *a, *aw;
	struct pf_rule *r;

	/*
	 * main ruleset is kind of special. We need to walk all rules to
	 * populate children tree with anchor rules.
	 *
	 * We start with flushing all stale entries.
	 */

		/*
		 * pf_fix_main_children() seems not quite right. 
		 * I'm afraid we need to find a better way to populate
		 * 'children'. It should be based on anchor path:
		 *	foo/lame
		 *	bar/tender
		 * anchors foo and bar should be inserted to
		 * main (root) anchor list of children.
		 */
	RB_FOREACH_SAFE(a, pf_anchor_node, &pf_main_anchor.children, aw)
		RB_REMOVE(pf_anchor_node, &pf_main_anchor.children, a);

	TAILQ_FOREACH(r, pf_main_anchor.ruleset.rules.ptr, entries) {
		if (r->anchor)
			RB_INSERT(pf_anchor_node, &pf_main_anchor.children,
			    r->anchor);
	}
}

void
pf_ina_commit(struct pf_trans *t)
{
	struct pf_anchor	*ta, *taw;
	int			 i;

	if (t->pftina_modify_defaults) {
		/*
		 * too late to derail transaction here.  I think
		 * warning we failed to update limit is sufficient
		 * here.
		 */
		for (i = 0; i < PF_LIMIT_MAX; i++) {
			struct pool *pp;

			pp = (struct pool *)pf_pool_limits[i].pp;
			if (pp->pr_nout > t->pftina_pool_limits[i]) {
				log(LOG_WARNING,
				    "pr_nout (%u) exceeds new "
				    "limit (%u) for %s at commit\n",
				    pp->pr_nout,
				    t->pftina_pool_limits[i],
				    pp->pr_wchan);
			} else if (t->pftina_pool_limits[i] !=
			    pf_pool_limits[i].limit &&
			    pool_sethardlimit(pp, t->pftina_pool_limits[i],
			    NULL, 0) != 0) {
				log(LOG_WARNING,
				    "setting limit to %u failed "
				    "for %s at commit\n",
				    t->pftina_pool_limits[i],
				    pp->pr_wchan);
			} else {
				pf_pool_limits[i].limit =
				    t->pftina_pool_limits[i];
			}
		}

		/*
		 * is there a better way to modify default rule?
		 */
		pf_default_rule = t->pftina_default_rule;

		for (i = 0; i < PFTM_MAX; i++) {
			int old = pf_default_rule.timeout[i];

			pf_default_rule.timeout[i] =
			    t->pftina_default_rule.timeout[i];

			if (i == PFTM_INTERVAL &&
			    pf_default_rule.timeout[i] < old)
				task_add(net_tq(0), &pf_purge_task);
		}

		pf_default_vers++;
	}

	/*
	 * Commit non-global rulesets first, so main ruleset
	 * main ruleset can easily refer to children anchors.
	 */
	RB_FOREACH_SAFE(ta, pf_anchor_global, &t->pftina_rc.anchors, taw) {
		pf_ina_commit_anchor(t, ta, RB_FIND(pf_anchor_global,
		    &pf_anchors, ta));
	}

	if (t->pftina_rc.main_anchor.ruleset.rules.version != 0) {
		pf_ina_commit_anchor(t, &t->pftina_rc.main_anchor,
		    &pf_main_anchor);
	}
}

void
pf_tab_do_commit_op(struct pf_trans *t, struct pf_anchor *ta,
    struct pf_anchor *a)
{
	switch (t->pfttab_iocmd) {
	case DIOCRADDTABLES:
		pfr_addtables_commit(t, ta, a);
		break;
	case DIOCRDELTABLES:
		pfr_deltables_commit(t, ta, a);
		break;
	case DIOCRCLRTSTATS:
		pfr_clrtstats_commit(t, ta, a);
		break;
	case DIOCRSETTFLAGS:
		pfr_settflags_commit(t, ta, a);
		break;
	case DIOCRADDADDRS:
		pfr_addaddrs_commit(t, ta, a);
		break;
	case DIOCRDELADDRS:
		pfr_deladdrs_commit(t, ta, a);
		break;
	case DIOCRSETADDRS:
		pfr_setaddrs_commit(t, ta, a);
		break;
	case DIOCRCLRADDRS:
		pfr_clraddrs_commit(t, ta, a);
		break;
	default:
		panic("%s unexpected iocmd for transaction on /",
		    __func__);
	}
}

void
pf_tab_commit(struct pf_trans *t)
{
	struct pf_anchor *ta, *taw, *a, *exists;
	struct pfr_ktable *kt;

	if (!RB_EMPTY(&t->pfttab_rc.main_anchor.ktables))
		pf_tab_do_commit_op(t, &t->pfttab_rc.main_anchor,
		    &pf_main_anchor);

	RB_FOREACH_SAFE(ta, pf_anchor_global, &t->pfttab_rc.anchors, taw) {
		KASSERT(TAILQ_EMPTY(ta->ruleset.rules.ptr));
		a = RB_FIND(pf_anchor_global, &pf_anchors, ta);
		if (a == NULL) {
			if (t->pfttab_iocmd == DIOCRADDTABLES) {
				/*
				 * move table from transaction anchor to global
				 * anchor, if table does not exists in global
				 * anchor.
				 */
				if ((t->pft_ioflags & PFR_FLAG_DUMMY) != 0) {
					RB_FOREACH(kt, pfr_ktablehead,
					    &ta->ktables) {
						t->pfttab_nadd++;
					}
					continue;	/* RB_FOREACH_SAFE() */
				}

				RB_REMOVE(pf_anchor_global,
				    &t->pfttab_rc.anchors, ta);
				exists = RB_INSERT(pf_anchor_global,
				    &pf_anchors, ta);
				KASSERT(exists == NULL);
				if (ta->parent != NULL)
					pf_update_parent(ta);
				RB_FOREACH(kt, pfr_ktablehead, &ta->ktables) {
					kt->pfrkt_version++;
					kt->pfrkt_flags |= PFR_TFLAG_ACTIVE;
					kt->pfrkt_flags &= ~PFR_TFLAG_INACTIVE;
					t->pfttab_nadd++;
				}
				pfr_update_table_refs(ta);
			} else {
				panic("%s ruleset %s to modify does not exists",
				    __func__, ta->path);
			}
		} else if (pf_match_root_path(a->path,
		    t->pfttab_anchor_path) == a->path)
			pf_tab_do_commit_op(t, ta, a);
	}
}

void
pf_commit_trans(struct pf_trans *t)
{
	switch (t->pft_type) {
	case PF_TRANS_INA:
		pf_ina_commit(t);
		break;
	case PF_TRANS_TAB:
		pf_tab_commit(t);
		break;
	default:
		panic("%s unknown transaction type (%d)", __func__, t->pft_type);
	}
		
	pf_trans_set_commit(&t->pftina_opts);
	pf_remove_orphans(t);
}

void
pf_cleanup_tina(struct pf_trans *t)
{
	struct pf_anchor *ta, *tw;
	struct pfr_ktable *tkt, *tktw;
	struct pf_rule *r;
	struct pf_ruleset *rs;

	KASSERT(t->pft_type == PF_TRANS_INA);

	RB_FOREACH_SAFE(ta, pf_anchor_global, &t->pftina_rc.anchors, tw) {
		RB_REMOVE(pf_anchor_global, &t->pftina_rc.anchors, ta);
		while ((r = TAILQ_FIRST(ta->ruleset.rules.ptr)) != NULL) {
			pf_rm_rule(&ta->ruleset.rules.queue, r);
			ta->ruleset.rules.rcount--;
		}

		RB_FOREACH_SAFE(tkt, pfr_ktablehead, &ta->ktables, tktw) {
			RB_REMOVE(pfr_ktablehead, &ta->ktables, tkt);
			pfr_destroy_ktable(tkt, 1);
		}
		/*
		 * Unlike pf_remove_if_empty_ruleset() we don't need to deal
		 * with parents, because all parents are part of transaction
		 * (are found in t->pftina_rc.anchors).
		 */

		pool_put(&pf_anchor_pl, ta);
	}

	rs = &t->pftina_rc.main_anchor.ruleset;
	while ((r = TAILQ_FIRST(rs->rules.ptr)) != NULL) {
		pf_rm_rule(&rs->rules.queue, r);
		rs->rules.rcount--;
	}

	RB_FOREACH_SAFE(tkt, pfr_ktablehead,
	    &t->pftina_rc.main_anchor.ktables, tktw) {
		RB_REMOVE(pfr_ktablehead,
		    &t->pftina_rc.main_anchor.ktables, tkt);
		pfr_destroy_ktable(tkt, 1);
	}

	while ((ta = TAILQ_FIRST(&t->pftina_anchor_list)) != NULL) {
		TAILQ_REMOVE(&t->pftina_anchor_list, ta, workq);
		KASSERT(ta->refcnt == 0);
		KASSERT(ta->tables == 0);
		KASSERT(RB_EMPTY(&ta->children));
		KASSERT(RB_EMPTY(&ta->ktables));
		KASSERT(TAILQ_EMPTY(ta->ruleset.rules.ptr));
		pool_put(&pf_anchor_pl, ta);
	}

	while ((tkt = SLIST_FIRST(&t->pftina_garbage)) != NULL) {
		SLIST_REMOVE_HEAD(&t->pftina_garbage, pfrkt_workq);
		pfr_destroy_ktable(tkt, 1);
	}
}

void
pf_init_tina(struct pf_trans *t)
{
	t->pft_type = PF_TRANS_INA;

	RB_INIT(&t->pftina_rc.anchors);
	TAILQ_INIT(&t->pftina_anchor_list);
	SLIST_INIT(&t->pftina_garbage);
	pf_init_ruleset(&t->pftina_rc.main_anchor.ruleset);
	t->pftina_default_rule = pf_default_rule;
	t->pftina_default_vers = pf_default_vers;
}

void
pf_cleanup_ttab(struct pf_trans *t)
{
	struct pf_anchor *ta, *tw;
	struct pfr_ktable *tkt, *tktw;
	struct pfr_kentry *ke;

	KASSERT(t->pft_type == PF_TRANS_TAB);

	RB_FOREACH_SAFE(ta, pf_anchor_global, &t->pfttab_rc.anchors, tw) {
		RB_REMOVE(pf_anchor_global, &t->pfttab_rc.anchors, ta);
		KASSERT(TAILQ_EMPTY(ta->ruleset.rules.ptr));

		RB_FOREACH_SAFE(tkt, pfr_ktablehead, &ta->ktables, tktw) {
			RB_REMOVE(pfr_ktablehead, &ta->ktables, tkt);
			pfr_destroy_ktable(tkt, 1);
		}
		pool_put(&pf_anchor_pl, ta);
	}

	KASSERT(TAILQ_EMPTY(t->pfttab_rc.main_anchor.ruleset.rules.ptr));

	RB_FOREACH_SAFE(tkt, pfr_ktablehead,
	    &t->pfttab_rc.main_anchor.ktables, tktw) {
		RB_REMOVE(pfr_ktablehead,
		    &t->pfttab_rc.main_anchor.ktables, tkt);
		pfr_destroy_ktable(tkt, 1);
	}

	while ((ta = TAILQ_FIRST(&t->pfttab_anchor_list)) != NULL) {
		TAILQ_REMOVE(&t->pfttab_anchor_list, ta, workq);
		KASSERT(ta->refcnt == 0);
		KASSERT(ta->tables == 0);
		KASSERT(RB_EMPTY(&ta->children));
		KASSERT(RB_EMPTY(&ta->ktables));
		KASSERT(TAILQ_EMPTY(ta->ruleset.rules.ptr));
		pool_put(&pf_anchor_pl, ta);
	}

	while ((tkt = SLIST_FIRST(&t->pfttab_kt_garbage)) != NULL) {
		SLIST_REMOVE_HEAD(&t->pfttab_kt_garbage, pfrkt_workq);
		pfr_destroy_ktable(tkt, 1);
	}

	while ((ke = SLIST_FIRST(&t->pfttab_ke_ioq)) != NULL) {
		SLIST_REMOVE_HEAD(&t->pfttab_ke_ioq, pfrke_ioq);
		switch (ke->pfrke_fb) {
		case PFR_FB_ADDED:
			break;
		default:
			pfr_destroy_kentry(ke);
		}
	}

	while ((ke = SLIST_FIRST(&t->pfttab_ke_garbage)) != NULL) {
		SLIST_REMOVE_HEAD(&t->pfttab_ke_garbage, pfrke_workq);
		pfr_destroy_kentry(ke);
	}

	if (t->pfttab_kbuf_sz != 0)
		free(t->pfttab_kbuf, M_PF, t->pfttab_kbuf_sz);
}

void
pf_init_ttab(struct pf_trans *t)
{
	t->pft_type = PF_TRANS_TAB;

	RB_INIT(&t->pfttab_rc.anchors);
	TAILQ_INIT(&t->pfttab_anchor_list);
	SLIST_INIT(&t->pfttab_ke_ioq);
	SLIST_INIT(&t->pfttab_kt_garbage);
	SLIST_INIT(&t->pfttab_ke_garbage);
	pf_init_ruleset(&t->pfttab_rc.main_anchor.ruleset);
}

void
pf_free_trans(struct pf_trans *t)
{
	switch (t->pft_type) {
	case PF_TRANS_GETRULE:
		pf_cleanup_tgetrule(t);
		break;
	case PF_TRANS_INA:
		pf_cleanup_tina(t);
		break;
	case PF_TRANS_TAB:
		pf_cleanup_ttab(t);
		break;
	default:
		log(LOG_ERR, "%s unknown transaction type: %d\n",
		    __func__, t->pft_type);
	}

	KASSERT(pf_unit2idx(t->pft_unit) < nitems(pf_tcount));
	KASSERT(pf_tcount[pf_unit2idx(t->pft_unit)] >= 1);
	pf_tcount[pf_unit2idx(t->pft_unit)]--;

	free(t, M_PF, sizeof(*t));
}

void
pf_rollback_trans(struct pf_trans *t)
{
	if (t != NULL) {
		rw_assert_wrlock(&pfioctl_rw);
		LIST_REMOVE(t, pft_entry);
		pf_free_trans(t);
	}
}
