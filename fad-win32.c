/*
 * Copyright (c) 1999, 2002
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include <packet32.h>

#include <errno.h>

#ifndef SA_LEN
#ifdef HAVE_SOCKADDR_SA_LEN
#define SA_LEN(addr)	((addr)->sa_len)
#else /* HAVE_SOCKADDR_SA_LEN */
#define SA_LEN(addr)	(sizeof (struct sockaddr))
#endif /* HAVE_SOCKADDR_SA_LEN */
#endif /* SA_LEN */

/*
 * Add an entry to the list of addresses for an interface.
 * "curdev" is the entry for that interface.
 */
static int
add_addr_to_list(pcap_if_t *curdev, struct sockaddr *addr,
    struct sockaddr *netmask, struct sockaddr *broadaddr,
    struct sockaddr *dstaddr, char *errbuf)
{
	pcap_addr_t *curaddr, *prevaddr, *nextaddr;

	/*
	 * Allocate the new entry and fill it in.
	 */
	curaddr = (pcap_addr_t*)malloc(sizeof(pcap_addr_t));
	if (curaddr == NULL) {
		(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "malloc: %s", pcap_strerror(errno));
		return (-1);
	}

	curaddr->next = NULL;
	if (addr != NULL) {
		curaddr->addr = (struct sockaddr*)dup_sockaddr(addr, SA_LEN(addr));
		if (curaddr->addr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->addr = NULL;

	if (netmask != NULL) {
		curaddr->netmask = (struct sockaddr*)dup_sockaddr(netmask, SA_LEN(netmask));
		if (curaddr->netmask == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->netmask = NULL;
		
	if (broadaddr != NULL) {
		curaddr->broadaddr = (struct sockaddr*)dup_sockaddr(broadaddr, SA_LEN(broadaddr));
		if (curaddr->broadaddr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->broadaddr = NULL;
		
	if (dstaddr != NULL) {
		curaddr->dstaddr = (struct sockaddr*)dup_sockaddr(dstaddr, SA_LEN(dstaddr));
		if (curaddr->dstaddr == NULL) {
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "malloc: %s", pcap_strerror(errno));
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->dstaddr = NULL;
		
	/*
	 * Find the end of the list of addresses.
	 */
	for (prevaddr = curdev->addresses; prevaddr != NULL; prevaddr = nextaddr) {
		nextaddr = prevaddr->next;
		if (nextaddr == NULL) {
			/*
			 * This is the end of the list.
			 */
			break;
		}
	}

	if (prevaddr == NULL) {
		/*
		 * The list was empty; this is the first member.
		 */
		curdev->addresses = curaddr;
	} else {
		/*
		 * "prevaddr" is the last member of the list; append
		 * this member to it.
		 */
		prevaddr->next = curaddr;
	}

	return (0);
}


static int
pcap_add_if_win32(pcap_if_t **devlist, char *name, const char *desc,
    char *errbuf)
{
	pcap_if_t *curdev;
	npf_if_addr if_addrs[16];
	LONG if_addr_size;
	int res = 0;
	struct sockaddr_in *addr, *netmask;

	if_addr_size = 16;

	/*
	 * Add an entry for this interface, with no addresses.
	 */
	if (add_or_find_if(&curdev, devlist, (char *)name, 0, (char *)desc,
	    errbuf) == -1) {
		/*
		 * Failure.
		 */
		return (-1);
	}

	/*
	 * Get the list of addresses for the interface.
	 *
	 * XXX - what about IPv6?
	 */
	if (!PacketGetNetInfoEx((void *)name, if_addrs, &if_addr_size)) {
		/*
		 * Failure.
		 */

		addr=(struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
		netmask=(struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = 0;
		netmask->sin_family = AF_INET;
		netmask->sin_addr.s_addr = 0;
	
		return (add_addr_to_list(curdev, 
			(struct sockaddr*)addr,
			(struct sockaddr*)netmask,
			NULL,
			NULL,
			errbuf));
	}

	/*
	 * Now add the addresses.
	 */
	while (if_addr_size-- > 0) {
		/*
		 * "curdev" is an entry for this interface; add an entry for
		 * this address to its list of addresses.
		 */
		if(curdev == NULL)
			break;
		res = add_addr_to_list(curdev,
		    (struct sockaddr *)&if_addrs[if_addr_size].IPAddress,
		    (struct sockaddr *)&if_addrs[if_addr_size].SubnetMask,
		    (struct sockaddr *)&if_addrs[if_addr_size].Broadcast,
		    NULL,
			errbuf);
		if (res == -1) {
			/*
			 * Failure.
			 */
			break;
		}
	}

	return (res);
}


/*
 * Get a list of all interfaces that are up and that we can open.
 * Returns -1 on error, 0 otherwise.
 * The list, as returned through "alldevsp", may be null if no interfaces
 * were up and could be opened.
 *
 * Win32 implementation, based on WinPcap
 */
int
pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	pcap_if_t *devlist = NULL;
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	int ret = 0;
	const char *desc;

	dwVersion = GetVersion();	/* get the OS version */
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4) {
		/*
		 * Windows 95, 98, ME.
		 */
		char AdaptersName[8192];
		ULONG NameLength = 8192;
		char *name;

		if (!PacketGetAdapterNames(AdaptersName, &NameLength)) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "PacketGetAdapterNames: %s",
			    pcap_win32strerror());
			return (-1);
		}

		/*
		 * "PacketGetAdapterNames()" returned a list of
		 * null-terminated ASCII interface name strings,
		 * terminated by a null string, followed by a list
		 * of null-terminated ASCII interface description
		 * strings, terminated by a null string.
		 * This means there are two ASCII nulls at the end
		 * of the first list.
		 *
		 * Find the end of the first list; that's the
		 * beginning of the second list.
		 */
		desc = &AdaptersName[0];
		while (*desc != '\0' || *(desc + 1) != '\0')
			desc++;

		/*
		 * Found it - "desc" points to the first of the two
		 * nulls at the end of the list of names, so the
		 * first byte of the list of descriptions is two bytes
		 * after it.
		 */
		desc += 2;

		/*
		 * Loop over the elements in the first list.
		 */
		name = &AdaptersName[0];
		while (*name != '\0') {
			/*
			 * Add an entry for this interface.
			 */
			if (pcap_add_if_win32(&devlist, name, desc,
			    errbuf) == -1) {
				/*
				 * Failure.
				 */
				ret = -1;
				break;
			}
			name += strlen(name) + 1;
			desc += strlen(desc) + 1;
		}
	} else {
		/*
		 * Windows NT (NT 4.0, W2K, WXP).
		 */
		WCHAR AdaptersName[8192];
		ULONG NameLength = 8192;
		const WCHAR *t;
		WCHAR *uc_name;
		char ascii_name[8192];
		char ascii_desc[8192];
		char *p;

		if (!PacketGetAdapterNames((PTSTR)AdaptersName, &NameLength)) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "PacketGetAdapterNames: %s",
			    pcap_win32strerror());
			return (-1);
		}

		/*
		 * "PacketGetAdapterNames()" returned a list of
		 * null-terminated Unicode interface name strings,
		 * terminated by a null string, followed by a list
		 * of null-terminated ASCII interface description
		 * strings, terminated by a null string.
		 * This means there are two Unicode nulls at the end
		 * of the first list.
		 *
		 * Find the end of the first list; that's the
		 * beginning of the second list.
		 */
		t = &AdaptersName[0];
		while (*t != '\0' || *(t + 1) != '\0')
			t++;

		/*
		 * Found it - "t" points to the first of the two
		 * nulls at the end of the list of names, so the
		 * first byte of the list of descriptions is two wide
		 * characters after it.
		 */
		t += 2;
		desc = (const char *)t;

		/*
		 * Loop over the elements in the first list.
		 *
		 * We assume all characters in the name string are valid
		 * ASCII characters.
		 */
		uc_name = &AdaptersName[0];
		while (*uc_name != '\0') {
			p = ascii_name;
			while ((*p++ = (char)*uc_name++) != '\0')
				;
			p = ascii_desc;
			while ((*p++ = *desc++) != '\0')
				;

			/*
			 * Add an entry for this interface.
			 */
			if (pcap_add_if_win32(&devlist, ascii_name,
			    ascii_desc, errbuf) == -1) {
				/*
				 * Failure.
				 */
				ret = -1;
				break;
			}
		}
	}

	if (ret == -1) {
		/*
		 * We had an error; free the list we've been constructing.
		 */
		if (devlist != NULL) {
			pcap_freealldevs(devlist);
			devlist = NULL;
		}
	}

	*alldevsp = devlist;
	return (ret);
}
