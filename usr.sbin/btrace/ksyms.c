/*	$OpenBSD: ksyms.c,v 1.10 2024/04/01 22:49:04 jsg Exp $ */

/*
 * Copyright (c) 2016 Martin Pieuchot <mpi@openbsd.org>
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

#define _DYN_LOADER	/* needed for AuxInfo */

#include <sys/types.h>
#include <sys/symhint.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <limits.h>
#include <dev/dt/dtvar.h>

#include "btrace.h"

struct sym {
	char *sym_name;
	unsigned long sym_value;	/* from st_value */
	unsigned long sym_size;		/* from st_size */
};

struct syms {
	struct sym *table;
	size_t nsymb;
};

int sym_compare_search(const void *, const void *);
int sym_compare_sort(const void *, const void *);

struct syms *
kelf_open(struct sym_hint *sh, struct syms *syms)
{
	char *name;
	Elf *elf;
	Elf_Data *data = NULL;
	Elf_Scn	*scn = NULL, *symtab = NULL;
	GElf_Sym sym;
	GElf_Shdr shdr;
	size_t i, shstrndx, strtabndx = SIZE_MAX, symtab_size;
	unsigned long diff;
	struct sym *tmp;
	int fd;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "elf_version: %s", elf_errmsg(-1));

	fd = open(&sh->sh_path, O_RDONLY);
	if (fd == -1) {
		warn("open: %s", &sh->sh_path);
		return syms;
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		warnx("elf_begin: %s", elf_errmsg(-1));
		goto bad;
	}

	if (elf_kind(elf) != ELF_K_ELF)
		goto bad;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		warnx("elf_getshdrstrndx: %s", elf_errmsg(-1));
		goto bad;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			warnx("elf_getshdr: %s", elf_errmsg(-1));
			goto bad;
		}
		if ((name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL) {
			warnx("elf_strptr: %s", elf_errmsg(-1));
			goto bad;
		}
		if (strcmp(name, ELF_SYMTAB) == 0 &&
		    shdr.sh_type == SHT_SYMTAB && shdr.sh_entsize != 0) {
			symtab = scn;
			symtab_size = shdr.sh_size / shdr.sh_entsize;
		}
		if (strcmp(name, ELF_STRTAB) == 0 &&
		    shdr.sh_type == SHT_STRTAB) {
			strtabndx = elf_ndxscn(scn);
		}
	}
	if (symtab == NULL) {
		warnx("%s: %s: section not found", &sh->sh_path, ELF_SYMTAB);
		goto bad;
	}
	if (strtabndx == SIZE_MAX) {
		warnx("%s: %s: section not found", &sh->sh_path, ELF_STRTAB);
		goto bad;
	}

	data = elf_rawdata(symtab, data);
	if (data == NULL) {
		warnx("%s elf_rwadata() unable to read syms from: %s\n",
		    __func__, &sh->sh_path);
		goto bad;
	}

	if (syms == NULL) {
		if ((syms = calloc(1, sizeof *syms)) == NULL)
			err(1, NULL);
		syms->table = calloc(symtab_size, sizeof *syms->table);
		if (syms->table == NULL)
			err(1, NULL);
	} else {
		tmp = reallocarray(syms->table, syms->nsymb + symtab_size,
		    sizeof *syms->table);
		if (tmp == NULL)
			err(1, NULL);
		syms->table = tmp;
		symtab_size += syms->nsymb;
	}

	for (i = syms->nsymb; i < symtab_size; i++) {
		if (gelf_getsym(data, i, &sym) == NULL)
			continue;
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
			continue;
		name = elf_strptr(elf, strtabndx, sym.st_name);
		if (name == NULL)
			continue;
		syms->table[syms->nsymb].sym_name = strdup(name);
		if (syms->table[syms->nsymb].sym_name == NULL)
			err(1, NULL);
		syms->table[syms->nsymb].sym_value = sym.st_value +
		    (intptr_t)sh->sh_start;
		syms->table[syms->nsymb].sym_size = sym.st_size;
		syms->nsymb++;
	}
	tmp = reallocarray(syms->table, syms->nsymb, sizeof *syms->table);
	if (tmp == NULL)
		err(1, NULL);
	syms->table = tmp;

	/* Sort symbols in ascending order by address. */
	qsort(syms->table, syms->nsymb, sizeof *syms->table, sym_compare_sort);

	/*
	 * Some functions, particularly those written in assembly, have an
	 * st_size of zero.  We can approximate a size for these by assuming
	 * that they extend from their st_value to that of the next function.
	 */
	for (i = 0; i < syms->nsymb; i++) {
		if (syms->table[i].sym_size != 0)
			continue;
		/* Can't do anything for the last symbol. */
		if (i + 1 == syms->nsymb)
			continue;
		diff = syms->table[i + 1].sym_value - syms->table[i].sym_value;
		syms->table[i].sym_size = diff;
	}

bad:
	elf_end(elf);
	close(fd);
	return syms;
}

void
kelf_close(struct syms *syms)
{
	size_t i;

	if (syms == NULL)
		return;

	for (i = 0; i < syms->nsymb; i++)
		free(syms->table[i].sym_name);
	free(syms->table);
	free(syms);
}

int
kelf_snprintsym(struct syms *syms, char *str, size_t size, unsigned long pc,
    unsigned long off)
{
	struct sym key = { .sym_value = pc + off };
	struct sym *entry;
	Elf_Addr offset;

	if (syms == NULL)
		goto fallback;

	entry = bsearch(&key, syms->table, syms->nsymb, sizeof *syms->table,
	    sym_compare_search);
	if (entry == NULL)
		goto fallback;

	offset = pc - (entry->sym_value + off);
	if (offset != 0) {
		return snprintf(str, size, "\n%s+0x%llx",
		    entry->sym_name, (unsigned long long)offset);
	}

	return snprintf(str, size, "\n%s", entry->sym_name);

fallback:
	return snprintf(str, size, "\n0x%lx", pc);
}

int
sym_compare_sort(const void *ap, const void *bp)
{
	const struct sym *a = ap, *b = bp;

	if (a->sym_value < b->sym_value)
		return -1;
	return a->sym_value > b->sym_value;
}

int
sym_compare_search(const void *keyp, const void *entryp)
{
	const struct sym *entry = entryp, *key = keyp;

	if (key->sym_value < entry->sym_value)
		return -1;
	return key->sym_value >= entry->sym_value + entry->sym_size;
}

/*
 * runtime linker does not know path to executable, we need get path
 * to executable from '-p' option.
 */
static struct syms *
kelf_open_exec(struct syms *syms, const struct sym_hint *sh,
    const char *exec_path)
{
	struct sym_hint *tmp_sh;
	size_t path_len;
	struct syms *syms_new;

	if (exec_path == NULL)
		return syms;

	path_len = strlen(exec_path);
	tmp_sh = malloc(sizeof(struct sym_hint) + path_len);
	if (sh == NULL)
		return syms;

	tmp_sh->sh_start = sh->sh_start;
	strlcpy(&tmp_sh->sh_path, exec_path, path_len + 1);

	syms_new = kelf_open(tmp_sh, syms);
	if (syms_new != NULL)
		syms = syms_new;

	free(tmp_sh);

	return syms;
}

struct syms *
kelf_open_kernel(const char *path)
{
	struct sym_hint *sh;
	size_t path_len = strlen(path);
	struct syms *syms;

	sh = malloc(sizeof(struct sym_hint) + path_len);
	if (sh == NULL)
		return NULL;

	sh->sh_start = 0;
	strlcpy(&sh->sh_path, path, path_len + 1);

	syms = kelf_open(sh, NULL);

	free(sh);

	return syms;
}

struct syms *
kelf_load_syms(struct dtioc_getsymhint *dtgs, struct syms *syms,
    const char *exec_path)
{
	struct sym_hint *sh;
	char *p, *end;

	/*
	 * There ae no shared libs in statically linked binary. We load
	 * symbols from exec_path using 0 as a base address.
	 */
	if (dtgs == NULL) {
		struct sym_hint tmp_sh;

		memset(&tmp_sh, 0, sizeof (struct sym_hint));
		return kelf_open_exec(syms, &tmp_sh, exec_path);
	}

	end = (char *)dtgs->dtgs_symhint;
	end += dtgs->dtgs_symhint_sz;

	sh = (struct sym_hint *)dtgs->dtgs_symhint;
	do {
		if (strcmp(&sh->sh_path, "\xff\xff") == 0)
			syms = kelf_open_exec(syms, sh, exec_path);
		else
			syms = kelf_open(sh, syms);

		p = &sh->sh_path;
		/*
		 * find next map entry in array. it starts right
		 * after current. we need to find the end of
		 * sh_path string and move to next byte.
		 */
		while (*p)
			p++;
		p++;

		sh = (struct sym_hint *)p;
	} while (p < end);

	return syms;
}
