#	$OpenBSD: GENERIC.MP,v 1.16 2021/02/09 14:06:19 patrick Exp $

include "arch/amd64/conf/GENERIC"

option	MULTIPROCESSOR
#option	MP_LOCKDEBUG
#option	WITNESS
option	UVIDEO_DEBUG
option	UVIDEO_DUMP
option	XHCI_DEBUG

cpu*		at mainbus?
