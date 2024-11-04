/*	$OpenBSD$ */

/*
 * Copyright (c) 2024 sashan@openbsd.org
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


/*
 * Code here is derieved from usr.sbin/procmap/procmap.c.
 */
#include <sys/tree.h>

#include <uvm/uvm.h>
#include <uvm/uvm_device.h>
#include <uvm/uvm_amap.h>
#include <uvm/uvm_vnode.h>

#include <kvm.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

/*
 * stolen (and munged) from #include <uvm/uvm_object.h>
 */
#define UVM_OBJ_IS_VNODE(uobj)	((uobj)->pgops == uvm_vnodeops)
#define UVM_OBJ_IS_AOBJ(uobj)	((uobj)->pgops == aobj_pager)
#define UVM_OBJ_IS_DEVICE(uobj)	((uobj)->pgops == uvm_deviceops)

#define PRINT_VMSPACE		0x00000001
#define PRINT_VM_MAP		0x00000002
#define PRINT_VM_MAP_HEADER	0x00000004
#define PRINT_VM_MAP_ENTRY	0x00000008
#define DUMP_NAMEI_CACHE	0x00000010

struct cache_entry {
	LIST_ENTRY(cache_entry) ce_next;
	struct vnode *ce_vp, *ce_pvp;
	u_long ce_cid, ce_pcid;
	unsigned int ce_nlen;
	char ce_name[256];
};

static LIST_HEAD(cache_head, cache_entry) lcache;
static TAILQ_HEAD(namecache_head, namecache) nclruhead;
LIST_HEAD(procmap_head, procmap_entry) bt_procmap;

int namecache_loaded;
void *uvm_vnodeops, *uvm_deviceops, *aobj_pager;
u_long kernel_map_addr, nclruhead_addr;
int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
rlim_t maxssiz;

struct kbit {
	/*
	 * size of data chunk
	 */
	size_t k_size;

	/*
	 * something for printf() and something for kvm_read()
	 */
	union {
		void *k_addr_p;
		u_long k_addr_ul;
	} k_addr;

	/*
	 * where we actually put the "stuff"
	 */
	union {
		char data[1];
		struct vmspace vmspace;
		struct vm_map vm_map;
		struct vm_map_entry vm_map_entry;
		struct uvm_vnode uvm_vnode;
		struct vnode vnode;
		struct uvm_object uvm_object;
		struct mount mount;
		struct inode inode;
		struct iso_node iso_node;
		struct uvm_device uvm_device;
		struct vm_amap vm_amap;
	} k_data;
};

/* the size of the object in the kernel */
#define S(x)	((x)->k_size)
/* the address of the object in kernel, two forms */
#define A(x)	((x)->k_addr.k_addr_ul)
#define P(x)	((x)->k_addr.k_addr_p)
/* the data from the kernel */
#define D(x,d)	(&((x)->k_data.d))

/* suck the data from the kernel */
#define _KDEREF(kd, addr, dst, sz) do { \
	ssize_t len; \
	len = kvm_read((kd), (addr), (dst), (sz)); \
	if (len != (sz)) \
		errx(1, "%s == %ld vs. %lu @ %lx", \
		    kvm_geterr(kd), (long)len, (unsigned long)(sz), (addr)); \
} while (0/*CONSTCOND*/)

/* suck the data using the structure */
#define KDEREF(kd, item) _KDEREF((kd), A(item), D(item, data), S(item))

static struct nlist nl[] = {
	{ "_maxsmap" },
#define NL_MAXSSIZ		0
	{ "_uvm_vnodeops" },
#define NL_UVM_VNODEOPS		1
	{ "_uvm_deviceops" },
#define NL_UVM_DEVICEOPS	2
	{ "_aobj_pager" },
#define NL_AOBJ_PAGER		3
	{ "_kernel_map" },
#define NL_KERNEL_MAP		4
	{ "_nclruhead" },
#define NL_NCLRUHEAD		5
	{ NULL }
};

static void load_symbols(kvm_t *);
static struct vm_map_entry *load_vm_map_entries(kvm_t *, struct vm_map_entry *,
    struct vm_map_entry *);
static void unload_vm_map_entries(struct vm_map_entry *);
static size_t process_vm_map_entry(kvm_t *, struct kbit *, struct vm_map_entry *);
static char *findname(kvm_t *, struct kbit *, struct vm_map_entry *, struct kbit *,
    struct kbit *, struct kbit *);
static int search_cache(kvm_t *, struct kbit *, char **, char *, size_t);
static void load_name_cache(kvm_t *);
static void cache_enter(struct namecache *);

/*
 * uvm_map address tree implementation.
 */
static int no_impl(const void *, const void *);
static int
no_impl(const void *p, const void *q)
{
	errx(1, "uvm_map address comparison not implemented");
	return 0;
}

RBT_PROTOTYPE(uvm_map_addr, vm_map_entry, daddrs.addr_entry, no_impl);
RBT_GENERATE(uvm_map_addr, vm_map_entry, daddrs.addr_entry, no_impl);

static void
load_symbols(kvm_t *kd)
{
	int rc, i;

	rc = kvm_nlist(kd, &nl[0]);
	if (rc == -1)
		errx(1, "%s == %d", kvm_geterr(kd), rc);
	for (i = 0; i < sizeof(nl)/sizeof(nl[0]); i++)
		if (nl[i].n_value == 0 && nl[i].n_name)
			printf("%s not found\n", nl[i].n_name);

	uvm_vnodeops =	(void*)nl[NL_UVM_VNODEOPS].n_value;
	uvm_deviceops =	(void*)nl[NL_UVM_DEVICEOPS].n_value;
	aobj_pager =	(void*)nl[NL_AOBJ_PAGER].n_value;

	nclruhead_addr = nl[NL_NCLRUHEAD].n_value;

	_KDEREF(kd, nl[NL_MAXSSIZ].n_value, &maxssiz,
	    sizeof(maxssiz));
	_KDEREF(kd, nl[NL_KERNEL_MAP].n_value, &kernel_map_addr,
	    sizeof(kernel_map_addr));
}

/*
 * Recreate the addr tree of vm_map in local memory.
 */
static struct vm_map_entry *
load_vm_map_entries(kvm_t *kd, struct vm_map_entry *kptr,
    struct vm_map_entry *parent)
{
	static struct kbit map_ent;
	struct vm_map_entry *result, *ld;

	if (kptr == NULL)
		return NULL;

	A(&map_ent) = (u_long)kptr;
	S(&map_ent) = sizeof(struct vm_map_entry);
	KDEREF(kd, &map_ent);

	result = malloc(sizeof(*result));
	if (result == NULL)
		err(1, "malloc");
	memcpy(result, D(&map_ent, vm_map_entry), sizeof(struct vm_map_entry));

	/*
	 * Recurse to download rest of the tree.
	 */

	/* RBTs point at rb_entries inside nodes */
	ld = load_vm_map_entries(kd, RBT_LEFT(uvm_map_addr, result), result);
	result->daddrs.addr_entry.rbt_left = &ld->daddrs.addr_entry;
	ld = load_vm_map_entries(kd, RBT_RIGHT(uvm_map_addr, result), result);
	result->daddrs.addr_entry.rbt_right = &ld->daddrs.addr_entry;
	result->daddrs.addr_entry.rbt_parent = &parent->daddrs.addr_entry;

	return result;
}

/*
 * Release the addr tree of vm_map.
 */
static void
unload_vm_map_entries(struct vm_map_entry *ent)
{
	if (ent == NULL)
		return;

	unload_vm_map_entries(RBT_LEFT(uvm_map_addr, ent));
	unload_vm_map_entries(RBT_RIGHT(uvm_map_addr, ent));
	free(ent);
}


static char *
findname(kvm_t *kd, struct kbit *vmspace,
    struct vm_map_entry *vme, struct kbit *vp,
    struct kbit *vfs, struct kbit *uvm_obj)
{
	static char buf[1024], *name;
	size_t l;

	if (UVM_ET_ISOBJ(vme)) {
		if (A(vfs)) {
			l = strlen(D(vfs, mount)->mnt_stat.f_mntonname);
			switch (search_cache(kd, vp, &name, buf, sizeof(buf))) {
			case 0: /* found something */
				if (name - (1 + 11 + l) < buf)
					break;
				name--;
				*name = '/';
				/*FALLTHROUGH*/
			case 2: /* found nothing */
				name -= 11;
				memcpy(name, " -unknown- ", (size_t)11);
				name -= l;
				memcpy(name,
				    D(vfs, mount)->mnt_stat.f_mntonname, l);
				break;
			case 1: /* all is well */
				if (name - (1 + l) < buf)
					break;
				name--;
				*name = '/';
				if (l != 1) {
					name -= l;
					memcpy(name,
					    D(vfs, mount)->mnt_stat.f_mntonname, l);
				}
				break;
			}
		} else if (UVM_OBJ_IS_DEVICE(D(uvm_obj, uvm_object))) {
			struct kbit kdev;
			dev_t dev;

			P(&kdev) = P(uvm_obj);
			S(&kdev) = sizeof(struct uvm_device);
			KDEREF(kd, &kdev);
			dev = D(&kdev, uvm_device)->u_device;
			name = devname(dev, S_IFCHR);
			if (name != NULL)
				snprintf(buf, sizeof(buf), "/dev/%s", name);
			else
				snprintf(buf, sizeof(buf), "  [ device %u,%u ]",
				    major(dev), minor(dev));
			name = buf;
		} else if (UVM_OBJ_IS_AOBJ(D(uvm_obj, uvm_object)))
			name = "  [ uvm_aobj ]";
		else if (UVM_OBJ_IS_VNODE(D(uvm_obj, uvm_object)))
			name = "  [ ?VNODE? ]";
		else {
			snprintf(buf, sizeof(buf), "  [ unknown (%p) ]",
			    D(uvm_obj, uvm_object)->pgops);
			name = buf;
		}
	} else if (D(vmspace, vmspace)->vm_maxsaddr <= (caddr_t)vme->start &&
	    (D(vmspace, vmspace)->vm_maxsaddr + (size_t)maxssiz) >=
	    (caddr_t)vme->end) {
		name = "  [ stack ]";
	} else if (UVM_ET_ISHOLE(vme))
		name = "  [ hole ]";
	else
		name = "  [ anon ]";

	return (name);
}

static int
search_cache(kvm_t *kd, struct kbit *vp, char **name, char *buf, size_t blen)
{
	struct cache_entry *ce;
	struct kbit svp;
	char *o, *e;
	u_long cid;

	if (!namecache_loaded)
		load_name_cache(kd);

	P(&svp) = P(vp);
	S(&svp) = sizeof(struct vnode);
	cid = D(vp, vnode)->v_id;

	e = &buf[blen - 1];
	o = e;
	do {
		LIST_FOREACH(ce, &lcache, ce_next)
			if (ce->ce_vp == P(&svp) && ce->ce_cid == cid)
				break;
		if (ce && ce->ce_vp == P(&svp) && ce->ce_cid == cid) {
			if (o != e) {
				if (o <= buf)
					break;
				*(--o) = '/';
			}
			if (o - ce->ce_nlen <= buf)
				break;
			o -= ce->ce_nlen;
			memcpy(o, ce->ce_name, ce->ce_nlen);
			P(&svp) = ce->ce_pvp;
			cid = ce->ce_pcid;
		} else
			break;
	} while (1/*CONSTCOND*/);
	*e = '\0';
	*name = o;

	if (e == o)
		return (2);

	KDEREF(kd, &svp);
	return (D(&svp, vnode)->v_flag & VROOT);
}

static void
load_name_cache(kvm_t *kd)
{
	struct namecache n, *tmp;
	struct namecache_head nchead;

	LIST_INIT(&lcache);
	_KDEREF(kd, nclruhead_addr, &nchead, sizeof(nchead));
	tmp = TAILQ_FIRST(&nchead);
	while (tmp != NULL) {
		_KDEREF(kd, (u_long)tmp, &n, sizeof(n));

		if (n.nc_nlen > 0) {
			if (n.nc_nlen > 2 ||
			    n.nc_name[0] != '.' ||
			    (n.nc_nlen != 1 && n.nc_name[1] != '.'))
				cache_enter(&n);
		}
		tmp = TAILQ_NEXT(&n, nc_lru);
	}

	namecache_loaded = 1;
}

static void
cache_enter(struct namecache *ncp)
{
	struct cache_entry *ce;

	ce = malloc(sizeof(struct cache_entry));
	if (ce == NULL)
		err(1, "cache_enter");

	ce->ce_vp = ncp->nc_vp;
	ce->ce_pvp = ncp->nc_dvp;
	ce->ce_cid = ncp->nc_vpid;
	ce->ce_pcid = ncp->nc_dvpid;
	ce->ce_nlen = (unsigned)ncp->nc_nlen;
	strlcpy(ce->ce_name, ncp->nc_name, sizeof(ce->ce_name));

	LIST_INSERT_HEAD(&lcache, ce, ce_next);
}

static void
process_vm_map_entry(kvm_t *kd, struct kbit *vmspace,
    struct vm_map_entry *vme)
{
	struct kbit kbit[5], *uvm_obj, *vp, *vfs, *amap, *uvn;
	ino_t inode = 0;
	dev_t dev = 0;
	size_t sz = 0;
	char *name;
	static u_long prevend;
	struct procmap_entry *pe;

	/*
	 * We are building symbol map of functions so we can resolve the stack.
	 * Functions are found in executable memory.
	 */
	if ((vms->max_protection & PROT_EXEC) == NULL)
		return;

	uvm_obj = &kbit[0];
	vp = &kbit[1];
	vfs = &kbit[2];
	amap = &kbit[3];
	uvn = &kbit[4];

	A(uvm_obj) = 0;
	A(vp) = 0;
	A(vfs) = 0;
	A(uvn) = 0;

	A(vp) = 0;
	A(uvm_obj) = 0;

	if (vme->object.uvm_obj != NULL) {
		P(uvm_obj) = vme->object.uvm_obj;
		S(uvm_obj) = sizeof(struct uvm_object);
		KDEREF(kd, uvm_obj);
		if (UVM_ET_ISOBJ(vme) &&
		    UVM_OBJ_IS_VNODE(D(uvm_obj, uvm_object))) {
			P(uvn) = P(uvm_obj);
			S(uvn) = sizeof(struct uvm_vnode);
			KDEREF(kd, uvn);

			P(vp) = D(uvn, uvm_vnode)->u_vnode;
			S(vp) = sizeof(struct vnode);
			KDEREF(kd, vp);
		}
	}

	if (vme->aref.ar_amap != NULL) {
		P(amap) = vme->aref.ar_amap;
		S(amap) = sizeof(struct vm_amap);
		KDEREF(kd, amap);
	}

	A(vfs) = 0;

	if (P(vp) != NULL && D(vp, vnode)->v_mount != NULL) {
		P(vfs) = D(vp, vnode)->v_mount;
		S(vfs) = sizeof(struct mount);
		KDEREF(kd, vfs);
		D(vp, vnode)->v_mount = D(vfs, mount);
	}

	/*
	 * dig out the device number and inode number from certain
	 * file system types.
	 */
#define V_DATA_IS(vp, type, d, i) do { \
	struct kbit data; \
	P(&data) = D(vp, vnode)->v_data; \
	S(&data) = sizeof(*D(&data, type)); \
	KDEREF(kd, &data); \
	dev = D(&data, type)->d; \
	inode = D(&data, type)->i; \
} while (0/*CONSTCOND*/)

	if (A(vp) &&
	    D(vp, vnode)->v_type == VREG &&
	    D(vp, vnode)->v_data != NULL) {
		switch (D(vp, vnode)->v_tag) {
		case VT_UFS:
		case VT_EXT2FS:
			V_DATA_IS(vp, inode, i_dev, i_number);
			break;
		case VT_ISOFS:
			V_DATA_IS(vp, iso_node, i_dev, i_number);
			break;
		case VT_NON:
		case VT_NFS:
		case VT_MFS:
		case VT_MSDOSFS:
		default:
			break;
		}
	}

	name = findname(kd, vmspace, vme, vp, vfs, uvm_obj);
	if (name == NULL)
		return;

	pe = malloc(sizeof (struct procmap_entry));
	if (pe == NULL)
		return;

	strncpy(pe->pe_name, name, sizeof (pe->pe_name));
	pe->pe_start = vme->start;
	pe->pe_end = vme->end;
	pe->pe_sz = vme->end - vme->start;

	LIST_INSERT_HEAD(&procmap, pe, pe_next);

	return;
}

int
procmap_init(pid_t pid)
{
	kvm_t *kd;
	struct kbit kbit[3], *vmspace, *vm_map;
	struct vm_map_entry *vm_map_entry;
	struct kinfo_proc *kproc;
	char errbuf[_POSIX2_LINE_MAX];
	git_t gid = getgid();
	uid_t uid;
	struct bt_procmap_entry *pe;

	LIST_INIT(&bt_procmap);

	/* start by opening libkvm */
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);

	if (setresgid(gid, gid, gid) == -1)
		err(1, "setresgid");

	if (kd == NULL)
		errx(1, "%s", errbuf);

	/* get "bootstrap" addresses from kernel */
	load_symbols(kd);

	kproc = kvm_getprocs(kd, KERN_PROC_PID, pid,
	    sizeof(struct kinfo_proc), &rc);
	if (kproc == NULL || rc == 0)
		errx(1, "%s", kvm_geterr(kd));

	if (uid = getuid()) {
		if (prco->p_uid != uid)
			errx("not owner of traced process");
	}

	/* these are the "sub entries" */
	vm_map_entry = load_vm_map_entries(kd,
	    RBT_ROOT(uvm_map_addr, &D(vm_map, vm_map)->addr), NULL);
	if (vm_map_entry != NULL) {
		/* RBTs point at rb_entries inside nodes */
		D(vm_map, vm_map)->addr.rbh_root.rbt_root =
		    &vm_map_entry->daddrs.addr_entry;
	} else
		RBT_INIT(uvm_map_addr, &D(vm_map, vm_map)->addr);

	RBT_FOREACH(vm_map_entry, uvm_map_addr, &D(vm_map, vm_map)->addr)
		dump_vm_map_entry(kd, vmspace, vm_map_entry);
	unload_vm_map_entries(RBT_ROOT(uvm_map_addr, &D(vm_map, vm_map)->addr));

	return (0);
}

void
procmap_fini(void)
{
	struct bt_procmap_entry *pe, *pe_w;

	LIST_FOREACH_SAFE(pe, &bt_procmap, pe_next, pe_w)
		free(pe);
}
