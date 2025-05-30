/*      $OpenBSD: whois.c,v 1.65 2025/05/01 10:18:51 sthen Exp $   */

/*
 * Copyright (c) 1980, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	NICHOST		"whois.crsnic.net"
#define	INICHOST	"whois.internic.net"
#define	DNICHOST	"whois.nic.mil"
#define	GNICHOST	"whois.nic.gov"
#define	ANICHOST	"whois.arin.net"
#define	RNICHOST	"whois.ripe.net"
#define	PNICHOST	"whois.apnic.net"
#define	RUNICHOST	"whois.ripn.net"
#define	MNICHOST	"whois.ra.net"
#define LNICHOST	"whois.lacnic.net"
#define	AFNICHOST	"whois.afrinic.net"
#define BNICHOST	"whois.registro.br"
#define	IANAHOST	"whois.iana.org"
#define	QNICHOST_TAIL	".whois-servers.net"

#define	WHOIS_PORT	"whois"
#define	WHOIS_SERVER_ID	"Registrar WHOIS Server:"

#define WHOIS_RECURSE	0x01
#define WHOIS_QUICK	0x02
#define WHOIS_SPAM_ME	0x04

#define CHOPSPAM	">>> Last update of WHOIS database:"

const char *port_whois = WHOIS_PORT;
const char *ip_whois[] = { LNICHOST, RNICHOST, PNICHOST, BNICHOST,
    AFNICHOST, NULL };

__dead void usage(void);
int whois(const char *, const char *, const char *, int);
char *choose_server(const char *, const char *, char **);

int
main(int argc, char *argv[])
{
	int ch, flags, rval;
	char *host, *name, *country;

	country = host = NULL;
	flags = rval = 0;
	while ((ch = getopt(argc, argv, "aAc:dgh:iIlmp:qQrRS")) != -1)
		switch (ch) {
		case 'a':
			host = ANICHOST;
			break;
		case 'A':
			host = PNICHOST;
			break;
		case 'c':
			country = optarg;
			break;
		case 'd':
			host = DNICHOST;
			break;
		case 'g':
			host = GNICHOST;
			break;
		case 'h':
			host = optarg;
			break;
		case 'i':
			host = INICHOST;
			break;
		case 'I':
			host = IANAHOST;
			break;
		case 'l':
			host = LNICHOST;
			break;
		case 'm':
			host = MNICHOST;
			break;
		case 'p':
			port_whois = optarg;
			break;
		case 'q':
			/* deprecated, now the default */
			break;
		case 'Q':
			flags |= WHOIS_QUICK;
			break;
		case 'r':
			host = RNICHOST;
			break;
		case 'R':
			host = RUNICHOST;
			break;
		case 'S':
			flags |= WHOIS_SPAM_ME;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (!argc || (country != NULL && host != NULL))
		usage();

	if (pledge("stdio dns inet", NULL) == -1)
		err(1, "pledge");

	if (host == NULL && country == NULL && !(flags & WHOIS_QUICK))
		flags |= WHOIS_RECURSE;
	for (name = *argv; (name = *argv) != NULL; argv++) {
		char *tofree = NULL;
		const char *server =
		    host ? host : choose_server(name, country, &tofree);
		rval += whois(name, server, port_whois, flags);
		free(tofree);
	}
	return (rval);
}

int
whois(const char *query, const char *server, const char *port, int flags)
{
	FILE *fp;
	char *p, *nhost, *buf = NULL;
	size_t len, bufsize = 0;
	int i, s, error;
	const char *reason = NULL, *fmt;
	struct addrinfo hints, *res, *ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(server, port, &hints, &res);
	if (error) {
		if (error == EAI_SERVICE)
			warnx("%s: bad port", port);
		else
			warnx("%s: %s", server, gai_strerror(error));
		return (1);
	}

	for (s = -1, ai = res; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1) {
			error = errno;
			reason = "socket";
			continue;
		}
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == -1) {
			error = errno;
			reason = "connect";
			close(s);
			s = -1;
			continue;
		}
		break;	/*okay*/
	}
	freeaddrinfo(res);
	if (s == -1) {
		if (reason) {
			errno = error;
			warn("%s: %s", server, reason);
		} else
			warn("unknown error in connection attempt");
		return (1);
	}

	if (!(flags & WHOIS_SPAM_ME) &&
	    (strcmp(server, "whois.denic.de") == 0 ||
	    strcmp(server, "de" QNICHOST_TAIL) == 0))
		fmt = "-T dn,ace -C ISO-8859-1 %s\r\n";
	else if (!(flags & WHOIS_SPAM_ME) &&
	    (strcmp(server, "whois.dk-hostmaster.dk") == 0 ||
	    strcmp(server, "dk" QNICHOST_TAIL) == 0))
		fmt = "--show-handles %s\r\n";
	else
		fmt = "%s\r\n";

	fp = fdopen(s, "r+");
	if (fp == NULL)
		err(1, "fdopen");
	fprintf(fp, fmt, query);
	fflush(fp);
	nhost = NULL;
	while ((len = getline(&buf, &bufsize, fp)) != (size_t)-1) {
		/* Nominet */
		if (!(flags & WHOIS_SPAM_ME) &&
		    len == 5 && strncmp(buf, "-- \r\n", 5) == 0)
			break;

		p = buf + len - 1;
		while (p > buf && isspace((unsigned char)*p))
			*p-- = '\0';
		puts(buf);

		if (nhost == NULL && (flags & WHOIS_RECURSE)) {
			if ((p = strstr(buf, WHOIS_SERVER_ID))) {
				p += sizeof(WHOIS_SERVER_ID) - 1;
				while (isblank((unsigned char)*p))
					p++;
				if ((len = strcspn(p, " \t\n\r"))) {
					if ((nhost = strndup(p, len)) == NULL)
						err(1, "strndup");
				}
			} else if (strcmp(server, ANICHOST) == 0) {
				for (p = buf; *p != '\0'; p++)
					*p = tolower((unsigned char)*p);
				for (i = 0; ip_whois[i] != NULL; i++) {
					if (strstr(buf, ip_whois[i]) != NULL) {
						nhost = strdup(ip_whois[i]);
						if (nhost == NULL)
							err(1, "strdup");
						break;
					}
				}
			}
		}

		/* Verisign etc. */
		if (!(flags & WHOIS_SPAM_ME) &&
		    (strncasecmp(buf, CHOPSPAM, sizeof(CHOPSPAM)-1) == 0 ||
		     strncasecmp(buf, &CHOPSPAM[4], sizeof(CHOPSPAM)-5) == 0)) {
			printf("\n");
			break;
		}
	}
	fclose(fp);
	free(buf);

	if (nhost != NULL) {
		error = whois(query, nhost, port, 0);
		free(nhost);
	}

	return (error);
}

/*
 * If no country is specified determine the top level domain from the query.
 * If the TLD is a number, query ARIN, otherwise, use TLD.whois-server.net.
 * If the domain does not contain '.', check to see if it is an ASN (starts
 * with AS) or IPv6 address (contains ':').
 * Fall back to NICHOST for the non-handle and non-IPv6 case.
 */
char *
choose_server(const char *name, const char *country, char **tofree)
{
	char *server;
	const char *qhead;
	char *ep;
	struct addrinfo hints, *res = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (country != NULL)
		qhead = country;
	else if ((qhead = strrchr(name, '.')) == NULL) {
		if ((strncasecmp(name, "AS", 2) == 0) &&
		    strtol(name + 2, &ep, 10) > 0 && *ep == '\0')
			return (MNICHOST);
		else if (strchr(name, ':') != NULL) /* IPv6 address */
			return (ANICHOST);
		else
			return (NICHOST);
	} else if (isdigit((unsigned char)*(++qhead)))
		return (ANICHOST);

	/*
	 * Post-2003 ("new") gTLDs are all supposed to have "whois.nic.domain"
	 * (per registry agreement), some older gTLDs also support this...
	 */
	if (asprintf(&server, "whois.nic.%s", qhead) == -1)
		err(1, NULL);

	/* most ccTLDs don't do this, but QNICHOST/whois-servers mostly works */
	if ((strlen(qhead) == 2 ||
	    /* and is required for most of the <=2003 TLDs/gTLDs */
	    strcasecmp(qhead, "org") == 0 ||
	    strcasecmp(qhead, "com") == 0 ||
	    strcasecmp(qhead, "net") == 0 ||
	    strcasecmp(qhead, "cat") == 0 ||
	    strcasecmp(qhead, "pro") == 0 ||
	    strcasecmp(qhead, "info") == 0 ||
	    strcasecmp(qhead, "aero") == 0 ||
	    strcasecmp(qhead, "jobs") == 0 ||
	    strcasecmp(qhead, "mobi") == 0 ||
	    strcasecmp(qhead, "museum") == 0 ||
	     /* for others, if whois.nic.TLD doesn't exist, try whois-servers */
	    getaddrinfo(server, NULL, &hints, &res) != 0)) {
		free(server);
		if (asprintf(&server, "%s%s", qhead, QNICHOST_TAIL) == -1)
			err(1, NULL);
	}
	if (res != NULL)
		freeaddrinfo(res);

	*tofree = server;
	return (server);
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-AadgIilmQRrS] [-c country-code | -h host] "
		"[-p port] name ...\n", __progname);
	exit(1);
}
