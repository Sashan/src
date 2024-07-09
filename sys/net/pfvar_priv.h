/*	$OpenBSD: pfvar_priv.h,v 1.37 2024/06/21 12:51:29 sashan Exp $	*/

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2013 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2016 Alexander Bluhm <bluhm@openbsd.org>
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

#ifndef _NET_PFVAR_PRIV_H_
#define _NET_PFVAR_PRIV_H_

#ifdef _KERNEL

#include <sys/rwlock.h>
#include <sys/mutex.h>
#include <sys/percpu.h>
#include <sys/queue.h>
#include <net/pfvar.h>

/*
 * Locks used to protect struct members in this file:
 *	L	pf_inp_mtx		link pf to inp mutex
 */

struct pfsync_deferral;

/*
 * pf state items - links from pf_state_key to pf_states
 */

struct pf_state_item {
	TAILQ_ENTRY(pf_state_item)
				 si_entry;
	struct pf_state		*si_st;
};

TAILQ_HEAD(pf_statelisthead, pf_state_item);

/*
 * pf state keys - look up states by address
 */

struct pf_state_key {
	struct pf_addr	 addr[2];
	u_int16_t	 port[2];
	u_int16_t	 rdomain;
	u_int16_t	 hash;
	sa_family_t	 af;
	u_int8_t	 proto;

	RB_ENTRY(pf_state_key)	 sk_entry;
	struct pf_statelisthead	 sk_states;
	struct pf_state_key	*sk_reverse;
	struct inpcb		*sk_inp;	/* [L] */
	pf_refcnt_t		 sk_refcnt;
	u_int8_t		 sk_removed;
};

RBT_HEAD(pf_state_tree, pf_state_key);
RBT_PROTOTYPE(pf_state_tree, pf_state_key, sk_entry, pf_state_compare_key);

#define PF_REVERSED_KEY(key, family)				\
	((key[PF_SK_WIRE]->af != key[PF_SK_STACK]->af) &&	\
	 (key[PF_SK_WIRE]->af != (family)))

/*
 * pf state
 *
 * Protection/ownership of pf_state members:
 *	I	immutable after pf_state_insert()
 *	M	pf_state mtx
 *	P	PF_STATE_LOCK
 *	S	pfsync
 *	L	pf_state_list
 *	g	pf_purge gc
 */

struct pf_state {
	u_int64_t		 id;		/* [I] */
	u_int32_t		 creatorid;	/* [I] */
	u_int8_t		 direction;	/* [I] */
	u_int8_t		 pad[3];

	TAILQ_ENTRY(pf_state)	 sync_list;	/* [S] */
	struct pfsync_deferral	*sync_defer;	/* [S] */
	TAILQ_ENTRY(pf_state)	 entry_list;	/* [L] */
	SLIST_ENTRY(pf_state)	 gc_list;	/* [g] */
	RB_ENTRY(pf_state)	 entry_id;	/* [P] */
	struct pf_state_peer	 src;
	struct pf_state_peer	 dst;
	struct pf_rule_slist	 match_rules;	/* [I] */
	union pf_rule_ptr	 rule;		/* [I] */
	union pf_rule_ptr	 anchor;	/* [I] */
	union pf_rule_ptr	 natrule;	/* [I] */
	struct pf_addr		 rt_addr;	/* [I] */
	struct pf_sn_head	 src_nodes;	/* [I] */
	struct pf_state_key	*key[2];	/* [I] stack and wire */
	struct pfi_kif		*kif;		/* [I] */
	struct mutex		 mtx;
	pf_refcnt_t		 refcnt;
	u_int64_t		 packets[2];
	u_int64_t		 bytes[2];
	int32_t			 creation;	/* [I] */
	int32_t			 expire;
	int32_t			 pfsync_time;	/* [S] */
	int			 rtableid[2];	/* [I] stack and wire */
	u_int16_t		 qid;		/* [I] */
	u_int16_t		 pqid;		/* [I] */
	u_int16_t		 tag;		/* [I] */
	u_int16_t		 state_flags;	/* [M] */
	u_int8_t		 log;		/* [I] */
	u_int8_t		 timeout;
	u_int8_t		 sync_state;	/* [S] PFSYNC_S_x */
	u_int8_t		 sync_updates;	/* [S] */
	u_int8_t		 min_ttl;	/* [I] */
	u_int8_t		 set_tos;	/* [I] */
	u_int8_t		 set_prio[2];	/* [I] */
	u_int16_t		 max_mss;	/* [I] */
	u_int16_t		 if_index_in;	/* [I] */
	u_int16_t		 if_index_out;	/* [I] */
	u_int16_t		 delay;		/* [I] */
	u_int8_t		 rt;		/* [I] */
};

RBT_HEAD(pf_state_tree_id, pf_state);
RBT_PROTOTYPE(pf_state_tree_id, pf_state, entry_id, pf_state_compare_id);
extern struct pf_state_tree_id tree_id;

/*
 * states are linked into a global list to support the following
 * functionality:
 *
 * - garbage collection
 * - pfsync bulk send operations
 * - bulk state fetches via the DIOCGETSTATES ioctl
 * - bulk state clearing via the DIOCCLRSTATES ioctl
 * 
 * states are inserted into the global pf_state_list once it has also
 * been successfully added to the various trees that make up the state
 * table. states are only removed from the pf_state_list by the garbage
 * collection process.
 *
 * the pf_state_list head and tail pointers (ie, the pfs_list TAILQ_HEAD
 * structure) and the pointers between the entries on the pf_state_list
 * are locked separately. at a high level, this allows for insertion
 * of new states into the pf_state_list while other contexts (eg, the
 * ioctls) are traversing the state items in the list. for garbage
 * collection to remove items from the pf_state_list, it has to exclude
 * both modifications to the list head and tail pointers, and traversal
 * of the links between the states.
 *
 * the head and tail pointers are protected by a mutex. the pointers
 * between states are protected by an rwlock.
 *
 * because insertions are only made to the end of the list, if we get
 * a snapshot of the head and tail of the list and prevent modifications
 * to the links between states, we can safely traverse between the
 * head and tail entries. subsequent insertions can add entries after
 * our view of the tail, but we don't look past our view.
 *
 * if both locks must be taken, the rwlock protecting the links between
 * states is taken before the mutex protecting the head and tail
 * pointer.
 *
 * insertion into the list follows this pattern:
 *
 *	// serialise list head/tail modifications
 *	mtx_enter(&pf_state_list.pfs_mtx);
 *	TAILQ_INSERT_TAIL(&pf_state_list.pfs_list, state, entry_list);
 *	mtx_leave(&pf_state_list.pfs_mtx);
 *
 * traversal of the list:
 *
 *	// lock against the gc removing an item from the list
 *	rw_enter_read(&pf_state_list.pfs_rwl);
 *
 *	// get a snapshot view of the ends of the list
 *	mtx_enter(&pf_state_list.pfs_mtx);
 *	head = TAILQ_FIRST(&pf_state_list.pfs_list);
 *	tail = TAILQ_LAST(&pf_state_list.pfs_list, pf_state_queue);
 *	mtx_leave(&pf_state_list.pfs_mtx);
 *
 *	state = NULL;
 *	next = head;
 *
 *	while (state != tail) {
 *		state = next;
 *		next = TAILQ_NEXT(state, entry_list);
 *
 *		// look at the state
 *	}
 *
 *	rw_exit_read(&pf_state_list.pfs_rwl);
 *
 * removing an item from the list:
 * 
 *	// wait for iterators (readers) to get out
 *	rw_enter_write(&pf_state_list.pfs_rwl);
 *
 *	// serialise list head/tail modifications
 *	mtx_enter(&pf_state_list.pfs_mtx);
 *	TAILQ_REMOVE(&pf_state_list.pfs_list, state, entry_list);
 *	mtx_leave(&pf_state_list.pfs_mtx);
 *
 *	rw_exit_write(&pf_state_list.pfs_rwl);
 *
 * the lock ordering for pf_state_list locks and the rest of the pf
 * locks are:
 *
 * 1. KERNEL_LOCK
 * 2. NET_LOCK
 * 3. pf_state_list.pfs_rwl
 * 4. PF_LOCK
 * 5. PF_STATE_LOCK
 * 6. pf_state_list.pfs_mtx
 */

struct pf_state_list {
	/* the list of states in the system */
	struct pf_state_queue		pfs_list;

	/* serialise pfs_list head/tail access */
	struct mutex			pfs_mtx;

	/* serialise access to pointers between pfs_list entries */
	struct rwlock			pfs_rwl;
};

#define PF_STATE_LIST_INITIALIZER(_pfs) {				\
	.pfs_list	= TAILQ_HEAD_INITIALIZER(_pfs.pfs_list),	\
	.pfs_mtx	= MUTEX_INITIALIZER(IPL_SOFTNET),		\
	.pfs_rwl	= RWLOCK_INITIALIZER("pfstates"),		\
}

extern struct rwlock pf_lock;

struct pf_pdesc {
	struct {
		int	 done;
		uid_t	 uid;
		gid_t	 gid;
		pid_t	 pid;
	}		 lookup;
	u_int64_t	 tot_len;	/* Make Mickey money */

	struct pf_addr	 nsaddr;	/* src address after NAT */
	struct pf_addr	 ndaddr;	/* dst address after NAT */

	struct pfi_kif	*kif;		/* incoming interface */
	struct mbuf	*m;		/* mbuf containing the packet */
	struct pf_addr	*src;		/* src address */
	struct pf_addr	*dst;		/* dst address */
	u_int16_t	*pcksum;	/* proto cksum */
	u_int16_t	*sport;
	u_int16_t	*dport;
	u_int16_t	 osport;
	u_int16_t	 odport;
	u_int16_t	 hash;
	u_int16_t	 nsport;	/* src port after NAT */
	u_int16_t	 ndport;	/* dst port after NAT */

	u_int32_t	 off;		/* protocol header offset */
	u_int32_t	 hdrlen;	/* protocol header length */
	u_int32_t	 p_len;		/* length of protocol payload */
	u_int32_t	 extoff;	/* extension header offset */
	u_int32_t	 fragoff;	/* fragment header offset */
	u_int32_t	 jumbolen;	/* length from v6 jumbo header */
	u_int32_t	 badopts;	/* v4 options or v6 routing headers */
#define PF_OPT_OTHER		0x0001
#define PF_OPT_JUMBO		0x0002
#define PF_OPT_ROUTER_ALERT	0x0004

	u_int16_t	 rdomain;	/* original routing domain */
	u_int16_t	 virtual_proto;
#define PF_VPROTO_FRAGMENT	256
	sa_family_t	 af;
	sa_family_t	 naf;
	u_int8_t	 proto;
	u_int8_t	 tos;
	u_int8_t	 ttl;
	u_int8_t	 dir;		/* direction */
	u_int8_t	 sidx;		/* key index for source */
	u_int8_t	 didx;		/* key index for destination */
	u_int8_t	 destchg;	/* flag set when destination changed */
	u_int8_t	 pflog;		/* flags for packet logging */
	union {
		struct tcphdr			tcp;
		struct udphdr			udp;
		struct icmp			icmp;
#ifdef INET6
		struct icmp6_hdr		icmp6;
		struct mld_hdr			mld;
		struct nd_neighbor_solicit	nd_ns;
#endif /* INET6 */
	} hdr;
};

struct pf_anchor_stackframe {
	struct pf_ruleset	*sf_rs;
	struct pf_rule		*sf_anchor;
	union {
		struct pf_rule			*u_r;
		struct pf_anchor_stackframe	*u_stack_top;
	} u;
	struct pf_anchor	*sf_child;
	int			 sf_jump_target;
};
#define sf_r		u.u_r
#define sf_stack_top	u.u_stack_top
enum {
	PF_NEXT_RULE,
	PF_NEXT_CHILD
};

extern struct cpumem *pf_anchor_stack;

extern struct pfr_table pfr_nulltable;

struct pf_opts {
	char		statusif[IFNAMSIZ];
	u_int32_t	debug;
	u_int32_t	hostid;
	u_int32_t	reass;
	u_int32_t	mask;
};

#define	PF_ORDER_HOST	0
#define	PF_ORDER_NET	1

#define	PF_TSET_STATUSIF	0x01
#define	PF_TSET_DEBUG		0x02
#define	PF_TSET_HOSTID		0x04
#define	PF_TSET_REASS		0x08

enum pf_trans_type {
	PF_TRANS_NONE,
	PF_TRANS_GETRULE,
	PF_TRANS_INA,
	PF_TRANS_TAB,
	PF_TRANS_MAX
};

struct pf_trans {
	LIST_ENTRY(pf_trans)	pft_entry;
	uint32_t		pft_unit;		/* process id */
	uint64_t		pft_ticket;
	int			pft_ioflags;
	enum pf_trans_type	pft_type;
	union {
		struct {
			u_int32_t		 gr_version;
			struct pf_anchor	*gr_anchor;
			struct pf_rule		*gr_rule;
		} u_getrule;
		struct {
			TAILQ_HEAD(, pf_anchor)	 ina_anchor_list;
			struct pfr_ktableworkq	 ina_garbage;
			struct pf_rules_container
						 ina_rc;
			struct pf_anchor	*ina_reserved_anchor;
			unsigned		 ina_pool_limits[PF_LIMIT_MAX];
			struct pf_rule		 ina_default_rule;
			struct pf_opts		 ina_opts;
			char			 ina_anchor_path[PATH_MAX];
			uint32_t		 ina_default_vers;
			char			 ina_modify_defaults;
			char			 ina_set_limit;
		} u_ina;
		struct {
			unsigned long		 tab_iocmd;
			TAILQ_HEAD(, pf_anchor)	 tab_anchor_list;
			struct pfr_kentryworkq   tab_ke_ioq;
			struct pfr_ktableworkq	 tab_kt_garbage;
			struct pfr_kentryworkq	 tab_ke_garbage;
			struct pf_rules_container
						 tab_rc;
			union {
				char			u_anchor_path[PATH_MAX];
				struct pf_anchor 	u_anchor_key;
			}			 tab_u;
			struct pf_anchor	 tab_anchor_key;
			char			 tab_anchor_path[PATH_MAX];
			char			*tab_kbuf;
			int			 tab_clrf;
			int			 tab_setf;
			uint32_t		 tab_ke_ioq_len;
			uint32_t		 tab_kbuf_sz;
			uint32_t		 tab_size;
			uint32_t		 tab_nadd;
			uint32_t		 tab_ndel;
			uint32_t		 tab_nchg;
			uint32_t		 tab_nzero;
			uint32_t		 tab_nmatch;
			uint32_t		 tab_error;
		} u_tab;
	} u;
};

#define pftgr_version	u.u_getrule.gr_version
#define pftgr_anchor	u.u_getrule.gr_anchor
#define pftgr_rule	u.u_getrule.gr_rule

#define pftina_anchor_list	u.u_ina.ina_anchor_list
#define pftina_garbage		u.u_ina.ina_garbage
#define pftina_rc		u.u_ina.ina_rc
#define pftina_reserved_anchor	u.u_ina.ina_reserved_anchor
#define	pftina_pool_limits	u.u_ina.ina_pool_limits
#define pftina_default_rule	u.u_ina.ina_default_rule
#define pftina_opts		u.u_ina.ina_opts
#define pftina_anchor_path	u.u_ina.ina_anchor_path
#define pftina_default_vers	u.u_ina.ina_default_vers
#define	pftina_modify_defaults	u.u_ina.ina_modify_defaults
#define	pftina_set_limit	u.u_ina.ina_set_limit

#define pfttab_iocmd		u.u_tab.tab_iocmd
#define pfttab_anchor_list	u.u_tab.tab_anchor_list
#define pfttab_ke_ioq		u.u_tab.tab_ke_ioq
#define pfttab_kt_garbage	u.u_tab.tab_kt_garbage
#define pfttab_ke_garbage	u.u_tab.tab_ke_garbage
#define pfttab_rc		u.u_tab.tab_rc
#define pfttab_anchor_path	u.u_tab.tab_u.u_anchor_path
#define pfttab_anchor_key	u.u_tab.tab_u.u_anchor_key
#define pfttab_kbuf		u.u_tab.tab_kbuf
#define pfttab_kbuf_sz		u.u_tab.tab_kbuf_sz
#define pfttab_clrf		u.u_tab.tab_clrf
#define pfttab_setf		u.u_tab.tab_setf
#define pfttab_ke_ioq_len	u.u_tab.tab_ke_ioq_len
#define pfttab_size		u.u_tab.tab_size
#define pfttab_nadd		u.u_tab.tab_nadd
#define pfttab_ndel		u.u_tab.tab_ndel
#define pfttab_nchg		u.u_tab.tab_nchg
#define pfttab_nzero		u.u_tab.tab_nzero
#define pfttab_nmatch		u.u_tab.tab_nmatch
#define pfttab_error		u.u_tab.tab_error

extern struct timeout	pf_purge_states_to;
extern struct task	pf_purge_task;
extern struct timeout	pf_purge_to;

struct pf_state		*pf_state_ref(struct pf_state *);
void			 pf_state_unref(struct pf_state *);

extern struct rwlock	pf_lock;
extern struct rwlock	pf_state_lock;
extern struct mutex	pf_frag_mtx;
extern struct mutex	pf_inp_mtx;

#define PF_LOCK()		do {			\
		rw_enter_write(&pf_lock);		\
	} while (0)

#define PF_UNLOCK()		do {			\
		PF_ASSERT_LOCKED();			\
		rw_exit_write(&pf_lock);		\
	} while (0)

#define PF_ASSERT_LOCKED()	do {			\
		if (rw_status(&pf_lock) != RW_WRITE)	\
			splassert_fail(RW_WRITE,	\
			    rw_status(&pf_lock),__func__);\
	} while (0)

#define PF_ASSERT_UNLOCKED()	do {			\
		if (rw_status(&pf_lock) == RW_WRITE)	\
			splassert_fail(0, rw_status(&pf_lock), __func__);\
	} while (0)

#define PF_STATE_ENTER_READ()	do {			\
		rw_enter_read(&pf_state_lock);		\
	} while (0)

#define PF_STATE_EXIT_READ()	do {			\
		rw_exit_read(&pf_state_lock);		\
	} while (0)

#define PF_STATE_ENTER_WRITE()	do {			\
		rw_enter_write(&pf_state_lock);		\
	} while (0)

#define PF_STATE_EXIT_WRITE()	do {			\
		PF_STATE_ASSERT_LOCKED();		\
		rw_exit_write(&pf_state_lock);		\
	} while (0)

#define PF_STATE_ASSERT_LOCKED()	do {		\
		if (rw_status(&pf_state_lock) != RW_WRITE)\
			splassert_fail(RW_WRITE,	\
			    rw_status(&pf_state_lock), __func__);\
	} while (0)

#define PF_FRAG_LOCK()		mtx_enter(&pf_frag_mtx)
#define PF_FRAG_UNLOCK()	mtx_leave(&pf_frag_mtx)

#define PFR_IOQ_ONLY	0
#define PFR_GARBAGE_TOO	1

#define PF_ANCHOR_PATH(_a_)	\
	(((_a_)->path[0] == '\0') ? "/" : (_a_)->path)

/* for copies to/from network byte order */
void			 pf_state_peer_hton(const struct pf_state_peer *,
			    struct pfsync_state_peer *);
void			 pf_state_peer_ntoh(const struct pfsync_state_peer *,
			    struct pf_state_peer *);
u_int16_t		 pf_pkt_hash(sa_family_t, uint8_t,
			    const struct pf_addr *, const struct pf_addr *,
			    uint16_t, uint16_t);
extern void		 pf_purge_timeout(void *);
extern void		 pf_purge(void *);
extern void		 pf_init_ttab(struct pf_trans *);
extern void		 pf_free_trans(struct pf_trans *);
extern struct pf_anchor	*pf_lookup_anchor(struct pf_anchor *);
extern void		 pf_walk_anchor_subtree(struct pf_anchor *, void *,
			    void(*f)(struct pf_anchor *, void *));
extern struct pfr_ktable
			*pfr_create_ktable(struct pf_rules_container *,
			    struct pfr_table *, time_t, int);
extern void		 pfr_destroy_ktable(struct pfr_ktable *, int);
extern struct pfr_ktable
			*pfr_lookup_table(struct pf_anchor *,
			    struct pfr_table *);
extern struct pfr_kentry
			*pfr_lookup_kentry(struct pfr_ktable *,
			    struct pfr_kentry *, int);
extern int		 pfr_route_kentry(struct pfr_ktable *,
			    struct pfr_kentry *);
extern struct pfr_kentry
			*pfr_create_kentry(struct pfr_addr *, int);
extern void		 pfr_update_table_refs(struct pf_anchor *);
extern int		 pfr_copyin_tables(struct pf_trans *,
			    struct pfr_table *, int);
extern int		 pfr_copyin_addrs(struct pf_trans *, struct pfr_table *,
			    struct pfr_addr *, int);
extern int		 pfr_copyout_addrs(struct pf_trans *, void *iobuf);
extern int		 pfr_addrs_feedback(struct pf_trans *,
			    struct pfr_addr *, int, int);
extern void		 pfr_addtables_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_deltables_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_clrtstats_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_gettstats_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_settflags_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_setaddrs_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_deladdrs_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_setaddrs_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_addaddrs_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_clraddrs_commit(struct pf_trans *,
			    struct pf_anchor *, struct pf_anchor *);
extern void		 pfr_destroy_kentry(struct pfr_kentry *);
void			 pfr_enqueue_addrs(struct pfr_ktable *,
			    struct pfr_kentryworkq *, int *, int);
void			 pfr_remove_kentries(struct pfr_ktable *,
			    struct pfr_kentryworkq *);
void			 pfr_print_table(const char *, struct pf_anchor *,
			    struct pfr_ktable *);

int			 pfi_unmask(void *);

RB_PROTOTYPE(pfr_ktablehead, pfr_ktable, pfrkt_tree, pfr_ktable_compare);
#endif /* _KERNEL */

#endif /* _NET_PFVAR_PRIV_H_ */
