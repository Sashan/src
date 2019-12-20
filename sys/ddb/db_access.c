/*	$OpenBSD: db_access.c,v 1.16 2019/11/07 13:16:25 mpi Exp $	*/
/*	$NetBSD: db_access.c,v 1.8 1994/10/09 08:37:35 mycroft Exp $	*/

/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * the rights to redistribute these changes.
 *
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/mutex.h>

#include <machine/db_machdep.h>		/* type definitions */

#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_output.h>

#define DBSA_HASH_SIZE	32
#define	DBSA_HASH(_k_)	((_k_) & 0x1f)

#define DBSR_MARK_UNUSED(_dbsr_)	do {		\
		(_dbsr_)->dbsr_used = 0;		\
	} while (0)

#define DBSR_CMP_PC(_a_dbsr, _b_dbsr, _lvl)	\
	((_a_dbsr)->dbsr_st.st_pc[(_lvl)] == (_b_dbsr)->dbsr_st.st_pc[(_lvl)])

#define DBSR_STACK_DPETH(_dbsr)	\
	(MIN((_dbsr)->dbsr_my_dbsa->dbsa_depth, (_dbsr)->dbsr_st.st_count))

/*
 * Record is marked as used as long as it is either found in table or
 * in the free list.
 */
#define DBSR_MARK_USED(_dbsr_)	do {		\
		(_dbsr_)->dbsr_used = 1;	\
	} while (0)

struct db_stack_record {
	LIST_ENTRY(db_stack_record)
			 dbsr_le;
	LIST_ENTRY(db_stack_record)
			 dbsr_sorted_le;
	int		 dbsr_used;
	uint64_t	 dbsr_hkey;
	unsigned int	 dbsr_instances;
	struct db_stack_aggr
			*dbsr_my_dbsa;
	struct db_stack_trace	
			 dbsr_st;
};

LIST_HEAD(db_stack_list, db_stack_record);

struct db_stack_aggr {
	unsigned int	dbsa_stacks;
	unsigned int	dbsa_depth;
	unsigned int	dbsa_pool_limit;
	unsigned int	dbsa_pool_used;
	unsigned int	dbsa_fail_alloc;
	struct db_stack_list
			dbsa_hash_dbsr[DBSA_HASH_SIZE];
	struct db_stack_list
			dbsa_free_list;
	struct db_stack_record
			*dbsa_pool;
	struct mutex	dbsa_mtx;
};

/*
 * Access unaligned data items on aligned (longword)
 * boundaries.
 */
db_expr_t
db_get_value(vaddr_t addr, size_t size, int is_signed)
{
	char data[sizeof(db_expr_t)];
	db_expr_t value, extend;
	int i;

#ifdef DIAGNOSTIC
	if (size > sizeof data)
		size = sizeof data;
#endif

	db_read_bytes(addr, size, data);

	value = 0;
	extend = (~(db_expr_t)0) << (size * 8 - 1);
#if BYTE_ORDER == LITTLE_ENDIAN
	for (i = size - 1; i >= 0; i--)
#else /* BYTE_ORDER == BIG_ENDIAN */
	for (i = 0; i < size; i++)
#endif /* BYTE_ORDER */
		value = (value << 8) + (data[i] & 0xFF);

	if (size < sizeof(db_expr_t) && is_signed && (value & extend))
		value |= extend;
	return (value);
}

void
db_put_value(vaddr_t addr, size_t size, db_expr_t value)
{
	char data[sizeof(db_expr_t)];
	int i;

#ifdef DIAGNOSTIC
	if (size > sizeof data)
		size = sizeof data;
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
	for (i = 0; i < size; i++)
#else /* BYTE_ORDER == BIG_ENDIAN */
	for (i = size - 1; i >= 0; i--)
#endif /* BYTE_ORDER */
	{
		data[i] = value & 0xff;
		value >>= 8;
	}

	db_write_bytes(addr, size, data);
}

struct db_stack_aggr *
db_create_stack_aggr(unsigned int stacks, unsigned int stack_depth)
{
	struct db_stack_aggr	*rv_dbsa;
	unsigned int	i;

	rv_dbsa = malloc(sizeof(struct db_stack_aggr),
	    M_TEMP, M_NOWAIT|M_ZERO);
	if (rv_dbsa == NULL)
		return (NULL);

	rv_dbsa->dbsa_stacks = stacks;
	rv_dbsa->dbsa_depth = stack_depth;

	rv_dbsa->dbsa_pool_limit = stacks;
	rv_dbsa->dbsa_pool = mallocarray(stacks, sizeof(struct db_stack_record),
	    M_TEMP, M_NOWAIT|M_ZERO);

	if (rv_dbsa->dbsa_pool == NULL) {
		free(rv_dbsa, M_TEMP, sizeof(struct db_stack_aggr));
		return (NULL);
	}

	for (i = 0; i < DBSA_HASH_SIZE; i++)
		LIST_INIT(&rv_dbsa->dbsa_hash_dbsr[i]);

	LIST_INIT(&rv_dbsa->dbsa_free_list);
	for (i = 0; i < rv_dbsa->dbsa_pool_limit; i++) {
		LIST_INSERT_HEAD(&rv_dbsa->dbsa_free_list,
		    &rv_dbsa->dbsa_pool[i], dbsr_le);
		rv_dbsa->dbsa_pool[i].dbsr_my_dbsa = rv_dbsa;
		DBSR_MARK_USED(&rv_dbsa->dbsa_pool[i]);
	}

	mtx_init(&rv_dbsa->dbsa_mtx, IPL_HIGH);

	return (rv_dbsa);
}

void
db_destroy_stack_aggr(struct db_stack_aggr *dbsa)
{
	free(dbsa->dbsa_pool, M_TEMP,
	    sizeof(struct db_stack_record) * dbsa->dbsa_pool_limit);
	free(dbsa, M_TEMP, sizeof(struct db_stack_aggr));
}

struct db_stack_record *
db_alloc_stack_record(struct db_stack_aggr *dbsa)
{
	struct db_stack_record *rv;

	if (dbsa == NULL)
		return (NULL);

	mtx_enter(&dbsa->dbsa_mtx);
	rv = LIST_FIRST(&dbsa->dbsa_free_list);
	if (rv != NULL) {
		LIST_REMOVE(rv, dbsr_le);
		DBSR_MARK_UNUSED(rv);
		dbsa->dbsa_pool_used++;
	} else
		dbsa->dbsa_fail_alloc++;
	mtx_leave(&dbsa->dbsa_mtx);

	return (rv);
}

void
db_free_stack_record(struct db_stack_record *dbsr)
{
	KASSERT(dbsr->dbsr_my_dbsa != NULL);
	KASSERT(!dbsr->dbsr_used);

	mtx_enter(&dbsr->dbsr_my_dbsa->dbsa_mtx);
	LIST_INSERT_HEAD(&dbsr->dbsr_my_dbsa->dbsa_free_list, dbsr, dbsr_le);
	DBSR_MARK_USED(dbsr);
	dbsr->dbsr_my_dbsa->dbsa_pool_used--;
	mtx_leave(&dbsr->dbsr_my_dbsa->dbsa_mtx);
}

unsigned int
db_get_stack_key(struct db_stack_aggr *dbsa, struct db_stack_record *dbsr)
{
	db_addr_t	rv = (db_addr_t)0xfeedfacefeedface;
	unsigned int	i;

	rv ^= dbsr->dbsr_st.st_count;
	for (i = 0; i < DBSR_STACK_DPETH(dbsr); i++)
		rv ^= dbsr->dbsr_st.st_pc[i];

	return ((unsigned int)rv);
}

struct db_stack_record *
db_insert_stack_record(struct db_stack_aggr *dbsa,
    struct db_stack_record *key_dbsr)
{
	struct db_stack_list	*bucket;
	struct db_stack_record	*dbsr;

	key_dbsr->dbsr_hkey = db_get_stack_key(dbsa, key_dbsr);
	bucket = &dbsa->dbsa_hash_dbsr[dbsr->dbsr_hkey];
	mtx_enter(&dbsa->dbsa_mtx);
	LIST_FOREACH(dbsr, bucket, dbsr_le) {
		if (dbsr->dbsr_hkey == key_dbsr->dbsr_hkey) {
			int	i;

			for (i = 0; i < DBSR_STACK_DPETH(dbsr); i++)
				if (!DBSR_CMP_PC(dbsr, key_dbsr, i))
					break;

			/*
			 * found a match
			 */
			if (i == dbsr->dbsr_st.st_count)
				break;
		} 
	}

	if (dbsr == NULL) {
		LIST_INSERT_HEAD(bucket, key_dbsr, dbsr_le);
		key_dbsr->dbsr_instances = 1;
		DBSR_MARK_USED(key_dbsr);
		dbsr = key_dbsr;
	} else {
		dbsr->dbsr_instances++;
		LIST_INSERT_HEAD(&dbsa->dbsa_free_list, key_dbsr, dbsr_le);
		DBSR_MARK_USED(key_dbsr);
	}

	mtx_leave(&dbsa->dbsa_mtx);

	return (dbsr);
}

struct db_stack_trace *
db_get_stack_trace_aggr(struct db_stack_record *dbsr)
{
	return (&dbsr->dbsr_st);
}

int
db_stack_sort_asc(struct db_stack_record * a_dbsr, struct db_stack_record *b_dbsr)
{
	return (a_dbsr->dbsr_instances > a_dbsr->dbsr_instances);
}

int
db_stack_sort_desc(struct db_stack_record * a_dbsr, struct db_stack_record *b_dbsr)
{
	return (a_dbsr->dbsr_instances < a_dbsr->dbsr_instances);
}


void
db_sort_stack_aggr(struct db_stack_aggr *dbsa, struct db_stack_list *sorted,
    int(*cmp)(struct db_stack_record *, struct db_stack_record *))
{
	struct db_stack_record	*bucket_dbsr, *sorted_dbsr;
	int	i;

	LIST_INIT(sorted);
	for (i = 0; i < DBSA_HASH_SIZE; i++)
		LIST_FOREACH(bucket_dbsr, &dbsa->dbsa_hash_dbsr[i], dbsr_le) {
			LIST_FOREACH(sorted_dbsr, sorted, dbsr_sorted_le)
				if (cmp(bucket_dbsr, sorted_dbsr))
					break;
			if (sorted_dbsr == NULL)
				LIST_INSERT_HEAD(sorted, bucket_dbsr,
				    dbsr_sorted_le);
			else
				LIST_INSERT_AFTER(sorted_dbsr, bucket_dbsr,
				    dbsr_sorted_le);
		}
}

void
db_print_stack_aggr(int(*prnt)(const char *format, ...),
    struct db_stack_aggr *dbsa, int asc, unsigned int top, unsigned int depth)
{
	int(*cmp)(struct db_stack_record *, struct db_stack_record *);
	struct db_stack_list	sorted;
	struct db_stack_record	*dbsr;
	unsigned int	i, j;
	db_expr_t	offset;
	Elf_Sym		*sym;
	char		*name;

	if (asc)
		cmp = db_stack_sort_asc;
	else
		cmp = db_stack_sort_desc;

	db_sort_stack_aggr(dbsa, &sorted, cmp);

	prnt("stack count:\t%u\n", dbsa->dbsa_pool_used);
	i = 0;
	LIST_FOREACH(dbsr, &sorted, dbsr_sorted_le) {
		if ((top != 0) && (i >= top))
			break;

		prnt("callers:\t%u\n", dbsr->dbsr_instances);
		for (j = 0; j < MIN(depth, DBSR_STACK_DPETH(dbsr)); j++) {
			sym = db_search_symbol(dbsr->dbsr_st.st_pc[j],
			    DB_STGY_ANY, &offset);
			db_symbol_values(sym, &name, NULL);
			prnt("\t%s()\t(%p)\n", name,
			    (void *)dbsr->dbsr_st.st_pc[j]);
		}
	}
}
