/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003      Abdelkader Lahmadi <Abdelkader.Lahmadi@loria.fr>
 *                         Olivier Festor <Olivier.Festor@loria.fr>
 * Copyright (C) 2003-11   Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "ntop.h"

#if 0 
#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#define SA(saddr)       ((struct sockaddr *)saddr)
#define SA4(saddr)      ((struct sockaddr_in *)saddr)
#define IN4(saddr)      (&SA4(saddr)->sin_addr)
#define SA6(saddr)      ((struct sockaddr_in6 *)saddr)
#define IN6(saddr)      (&SA6(saddr)->sin6_addr)

/* ************************************************* */

static struct in6_addr *in6_cpy(struct in6_addr *dst, struct in6_addr *src) {
  memcpy(dst, src, sizeof(struct in6_addr));
  return(dst);
}

/* ************************************************* */

#if defined(HAVE_IFLIST_SYSCTL) && defined(HAVE_SYSCTL)
static struct in_addr *in4_cpy(struct in_addr *dst, struct in_addr *src) {
  memcpy(dst, src, sizeof(struct in_addr));
  return(dst);
}

/* ************************************************* */

#ifdef LINUX
static void str2in6_addr(char *str, struct in6_addr *addr) {
  int i;
  unsigned int x;

  for (i=0; i < 16; i++){
    sscanf(str + (i*2), "%02x",&x);
    addr->s6_addr[i]= x & 0xff;
  }
}
#endif

/* ************************************************* */

#if defined(HAVE_IFLIST_SYSCTL) && defined(HAVE_SYSCTL)

static int prefixlen(void *val, int size) {
  unsigned char *name = (unsigned char *)val;
  int byte, bit, plen = 0;

  for (byte = 0; byte < size; byte++, plen += 8)
    if (name[byte] != 0xff)
      break;
  if (byte == size)
    return (plen);
  for (bit = 7; bit != 0; bit--, plen++)
    if (!(name[byte] & (1 << bit)))
      break;
  for (; bit != 0; bit--)
    if (name[byte] & (1 << bit))
      return(0);
  byte++;
  for (; byte < size; byte++)
    if (name[byte])
      return(0);
  return (plen);
}

/* ************************************************* */

struct iface_handler *iface_new(void) {
  int		 mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
  char		*buf = NULL;
  char		*lim, *next;
  size_t		 needed;
  struct iface_handler *hdlr = NULL;
  int i;
  int if_pos = 0;
  int addr_pos = 0;
  struct iface_addr	*ia = NULL;

  /* Allocate memory for iface handler
   */
  if (! (hdlr = (struct iface_handler *)calloc(1,sizeof(struct iface_handler)))) {
    errno = ENOMEM;
    goto failed;
  }

  /* Retrieve raw interface information buffer
   */
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    goto failed;
  if (! (buf = malloc(needed))) {
    errno = ENOMEM;
    goto failed;
  }
  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
    goto failed;


  /* Count interfaces and addresses
   */
  lim  = buf + needed;
  next = buf;
  while (next < lim) {
    struct if_msghdr *ifm = (struct if_msghdr *)next;
    if (ifm->ifm_type != RTM_IFINFO)
      goto failed;
    hdlr->if_count++;
    next += ifm->ifm_msglen;
    while (next < lim) {
      struct if_msghdr *nextifm = (struct if_msghdr *)next;
      if (nextifm->ifm_type != RTM_NEWADDR)
	break;
      next += nextifm->ifm_msglen;
      hdlr->addr_count++;
    }
  }


  /* Allocate memory for storing interfaces/addresses lists
   */
  if ((! (hdlr->if_list   = (struct iface_if *)calloc(hdlr->if_count,sizeof(struct iface_if)))) ||
      (! (hdlr->addr_list = (struct iface_addr *)calloc(hdlr->addr_count,sizeof(struct iface_addr))))) {
    errno = ENOMEM;
    goto failed;
  }


  /* Parsing raw buffer
   */
  lim  = buf + needed;
  next = buf;
  while (next < lim) {
    struct iface_if		*ii	= &hdlr->if_list[if_pos];
    struct if_msghdr	*ifm	= (struct if_msghdr *)next;
    struct sockaddr_dl	*sdl	= (struct sockaddr_dl *)(ifm + 1);
    int			 acount	= 0;

    /* Sanity check
     */
    if (ifm->ifm_type != RTM_IFINFO) {
      errno = EACCES;
      goto failed;
    }

    /* Interface name and index
     */
    ii->next = &hdlr->if_list[if_pos+1];

    ii->index = ifm->ifm_index;
    strncpy(ii->name, sdl->sdl_data, sdl->sdl_nlen);
    ii->name[sdl->sdl_nlen] = '\0';

    /* Interface info
     *  UP / BROADCAST / MULTICAST / LOOPBACK / P2P / PROMISC / SIMPLEX
     */
    if (ifm->ifm_flags & IFF_UP)		/* interface is UP	*/
      ii->info |= IFACE_INFO_UP;
    if (ifm->ifm_flags & IFF_LOOPBACK)	/* is a loopback net	*/
      ii->info |= IFACE_INFO_LOOPBACK;
    if (ifm->ifm_flags & IFF_POINTOPOINT)	/* point to point link	*/
      ii->info |= IFACE_INFO_P2P;
    if (ifm->ifm_flags & IFF_BROADCAST)	/* support broadcast	*/
      ii->info |= IFACE_INFO_BROADCAST;
    if (ifm->ifm_flags & IFF_MULTICAST)	/* support multicast	*/
      ii->info |= IFACE_INFO_MULTICAST;
    if (ifm->ifm_flags & IFF_PROMISC)	/* receive all packets	*/
      ii->info |= IFACE_INFO_PROMISC;
    /*if (ifm->ifm_flags & IFF_SIMPLEX)*/	/* can't hear own packets */
    /*	    ii->info |= IFACE_INFO_SIMPLEX;*/

    /* Information about physical interface
     *  type / physaddr / addrlen
     */
    ii->type = sdl->sdl_type; // ::TODO:: type conversion
    if (sdl->sdl_alen > 0) {
      ii->phys.size = sdl->sdl_alen;
      ii->phys.addr = malloc(ii->phys.size);
      if (ii->phys.addr == NULL) {
	errno = ENOMEM;
	goto failed;
      }
      memcpy(ii->phys.addr, LLADDR(sdl), ii->phys.size);
    }

    /* Retrieve addresses
     */
    ii->addrs = &hdlr->addr_list[addr_pos];

    next += ifm->ifm_msglen;
    while (next < lim) {
      struct sockaddr	*sa[RTAX_MAX];
      struct if_msghdr	*nextifm	= (struct if_msghdr *)next;
      struct ifa_msghdr	*ifam		= (struct ifa_msghdr *)nextifm;
      char		*cp		= (char *)(ifam + 1);

      /* Check for end
       */
      if (nextifm->ifm_type != RTM_NEWADDR)
	break;

      /* Unpack address information
       */
      memset(sa, 0, sizeof(sa));
      for (i = 0; (i < RTAX_MAX) && (cp < lim); i++) {
	if ((ifam->ifam_addrs & (1 << i)) == 0)
	  continue;
	sa[i] = SA(cp);
	cp += ROUNDUP(sa[i]->sa_len);
      }

      /* Basic information about interface
       */
      ia		= &hdlr->addr_list[addr_pos];
      ia->family	= -1;
      ia->ifi	= ii;
      ia->next 	= &hdlr->addr_list[addr_pos+1];

      /* Process accroding to address family
       */
      if (sa[RTAX_IFA]) {
	ia->family = sa[RTAX_IFA]->sa_family;
	switch(ia->family) {
	case AF_INET:
	  in4_cpy(&ia->af.inet.addr, IN4(sa[RTAX_IFA]));
	  in4_cpy(&ia->af.inet.bcast,
		  sa[RTAX_BRD]?IN4(sa[RTAX_BRD]):IN4(sa[RTAX_IFA]));
	  ia->af.inet.mask = sa[RTAX_NETMASK]
	    ? prefixlen(IN4(sa[RTAX_NETMASK]),sizeof(struct in_addr))
	    : 8 * sizeof(struct in_addr);
	  break;
	case AF_INET6:
	  in6_cpy(&ia->af.inet6.addr, IN6(sa[RTAX_IFA]));
	  ia->af.inet6.prefixlen = sa[RTAX_NETMASK]
	    ? prefixlen(IN6(sa[RTAX_NETMASK]),sizeof(struct in6_addr))
	    : 8 * sizeof(struct in6_addr);
	  break;
	default:
	  /* Don't know how to process it, so ignore it
	   */
	  break;
	}
      }

      next += nextifm->ifm_msglen;
      acount++;
      addr_pos++;
    }
    ia->next = NULL;
    if (acount == 0)
      ii->addrs = NULL;

    if_pos++;
  }
  hdlr->if_list[hdlr->if_count-1].next = NULL;

  free(buf);
  return hdlr;

 failed:
  iface_destroy(hdlr);
  free(buf);
  return NULL;
}

#else

/* TODO: Using ioctl for getting interface addresses */
#ifdef LINUX
#define PATH_PROC_NET_IF_INET6 "/proc/net/if_inet6"
static int iface_getflags(struct iface_if *ii) {
  int sock;
  struct ifreq lifreq;

  strncpy(lifreq.ifr_name, ii->name,IFNAMSIZ);
  lifreq.ifr_addr.sa_family = AF_INET;
  if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    return -1;
  /* Interface flags */
  if (ioctl(sock, SIOCGIFFLAGS,&lifreq) < 0)
    return -1;
  if (lifreq.ifr_flags & IFF_UP)              /* interface is UP      */
    ii->info |= IFACE_INFO_UP;
  if (lifreq.ifr_flags & IFF_LOOPBACK)        /* is a loopback net    */
    ii->info |= IFACE_INFO_LOOPBACK;
  if (lifreq.ifr_flags & IFF_POINTOPOINT)     /* point to point link  */
    ii->info |= IFACE_INFO_P2P;
  if (lifreq.ifr_flags & IFF_BROADCAST)       /* support broadcast    */
    ii->info |= IFACE_INFO_BROADCAST;
  if (lifreq.ifr_flags & IFF_MULTICAST)       /* support multicast    */
    ii->info |= IFACE_INFO_MULTICAST;
  if (lifreq.ifr_flags & IFF_PROMISC) /* receive all packets  */
    ii->info |= IFACE_INFO_PROMISC;

  close(sock);

  return 1;
}

/* **************************************************** */

struct iface_handler *iface_new(void) {
  char buf[1024];
  char straddr[33];
  char ifname[20];
  int ifindex, plen, scope, status;
  int found = 0;
  struct iface_handler * hdlr;
  FILE *fp;
  int n;
  struct iface_if *ii, *itf;
  struct iface_addr *ia, *it;
  struct in6_addr addr;

  /* Allocate memory for iface handler
   */
  if(!(hdlr = (struct iface_handler *)calloc(1, sizeof(struct iface_handler)))){
    errno = ENOMEM;
    goto failed;
  }

  fp = fopen(PATH_PROC_NET_IF_INET6,"r");
  if (fp == NULL)
    goto failed;
  hdlr->if_list = ii = NULL;
  hdlr->addr_list = ia = NULL;
  while (fgets(buf, 1024, fp) != NULL){
    n = sscanf(buf, "%32s %02x %02x %02x %02x %20s",
	       straddr, &ifindex,&plen, &scope, &status, ifname);
    if (n != 6)
      continue;
    str2in6_addr(straddr, &addr);
    /* search existing interface */
    for (itf = hdlr->if_list;itf; itf= itf->next){
      if (strncmp(itf->name, ifname,IFNAMSIZ) == 0){
	/* update addresses*/
	for (it = itf->addrs;it->next != NULL ; it = it->next);
	ia = (struct iface_addr *)malloc(sizeof(struct iface_addr));
	ia->family = AF_INET6;
	ia->ifi = itf;
	in6_cpy(&ia->af.inet6.addr, &addr);
	ia->af.inet6.prefixlen = plen;
	ia->next = NULL;
	it->next = ia;
	found = 1;
      }
    }
    if (!found){
      /* New interface/ address */
      itf = (struct iface_if *)malloc(sizeof(struct iface_if));
      itf->next = NULL;
      memcpy(itf->name, ifname, IFNAMSIZ);
      itf->index = ifindex;
      iface_getflags(itf);
      it = itf->addrs =(struct iface_addr *) malloc(sizeof(struct iface_addr));
      it->family = AF_INET6;
      it->ifi = itf;
      in6_cpy(&it->af.inet6.addr, &addr);
      it->af.inet6.prefixlen = plen;
      it->next = NULL;
      if(ii == NULL) {
	hdlr->if_list = itf;
	hdlr->addr_list = it;
      } else {
	ii->next = itf;
      }
      ii = itf;
      hdlr->if_count++;

    }
  }

  fclose(fp);
  return hdlr;

 failed:
  iface_destroy(hdlr);
  return NULL;
}
#else

/* != LINUX */
struct iface_handler *iface_new(void) {
  return NULL;
}
#endif
#endif

/* ******************************************************* */

void iface_destroy(struct iface_handler *hdlr) {
  if (hdlr) {
    if (hdlr->addr_list)
      free(hdlr->addr_list);
    if (hdlr->if_list) {
#if defined(HAVE_IFLIST_SYSCTL) && defined(HAVE_SYSCTL)
      int i;
      for (i = 0 ; i < hdlr->if_count ; i++)
	if (hdlr->if_list[i].phys.addr)
	  free(hdlr->if_list[i].phys.addr);
#endif
      free(hdlr->if_list);
    }
    free(hdlr);
  }
}

int iface_addrcount(struct iface_handler *hdlr) {
  return hdlr->addr_count;
}

int iface_ifcount(struct iface_handler *hdlr) {
  return hdlr->if_count;
}

struct iface_if *iface_getif_first(struct iface_handler *hdlr) {
  return hdlr->if_count ? &hdlr->if_list[0] : NULL;
}

struct iface_if *iface_getif_next(struct iface_if *ii) {
  return ii ? ii->next : NULL;
}

int iface_if_addrcount(struct iface_if *ii, int family) {
  struct iface_addr *ia;
  int count = 0;

  for (ia = ii->addrs ; ia ; ia = ia->next)
    if (!family || (ia->family == family))
      count++;
  return count;
}

struct iface_if *iface_getif_byindex(struct iface_handler *hdlr, int idx) {
  int i;

  for (i = 0 ; i < hdlr->if_count ; i++)
    if (hdlr->if_list[i].index == idx)
      return &hdlr->if_list[i];
  return NULL;
}

struct iface_if *iface_getif_byname(struct iface_handler *hdlr, char *name) {
  int i;

  for (i = 0 ; i < hdlr->if_count ; i++)
    if (! strcmp(hdlr->if_list[i].name, name))
      return &hdlr->if_list[i];
  return NULL;
}

char *iface_if_getname(struct iface_if *ii, char *name, int size) {
  if (name) {
    name[size-1] = '\0';
    strncpy(name, ii->name, size);
  } else {
    name = strdup(ii->name);
  }
  return name;
}

int iface_if_getindex(struct iface_if *ii) {
  return ii->index;
}

int iface_if_getinfo(struct iface_if *ii) {
  return ii->info;
}

int iface_if_gettype(struct iface_if *ii) {
  return ii->type;
}

int iface_if_getphys(struct iface_if *ii,int *type,char *addr,int *addrsize) {
  if (type)
    *type = ii->type;
  if (addr) {
    *addrsize = *addrsize < ii->phys.size ? *addrsize : ii->phys.size;
    if (ii->phys.addr)
      memcpy(addr, ii->phys.addr, *addrsize);
  }
  return ii->phys.size;
}

struct iface_addr *iface_getaddr_first(struct iface_if *ii, int family) {
  struct iface_addr	*ia;

  if (! (ia = ii->addrs))
    return NULL;
  if (family && (ia->family != family))
    return iface_getaddr_next(ia, family);
  return ia;
}

struct iface_addr *iface_getaddr_next(struct iface_addr *ia, int family) {
  if (ia)
    do {
      ia = ia->next;
    } while (ia && family && (ia->family != family));
  return ia;
}

int iface_addr_getfamily(struct iface_addr *ia) {
  return ia->family;
}

int iface_addr_ifindex(struct iface_addr *ia) {
  return ia->ifi->index;
}

void *iface_addr_getinfo(struct iface_addr *ia, void *infobuf) {
  switch(ia->family) {
  case AF_INET:
    memcpy(infobuf, &ia->af.inet,  sizeof(struct iface_addr_inet));
    return infobuf;
  case AF_INET6:
    memcpy(infobuf, &ia->af.inet6, sizeof(struct iface_addr_inet6));
    return infobuf;
  default:
    return NULL;
  }
}

/* *************************************************** */

int iface6(int *idx, int size) {
  struct iface_if	*ii;
  struct iface_handler	*ih;
  int			count	= 0;


  ih = iface_new();

  if(ih == NULL)
    return -1;

  for (ii = iface_getif_first(ih) ; ii ; ii = iface_getif_next(ii))
    if ((iface_if_getinfo(ii) & (IFACE_INFO_UP | IFACE_INFO_LOOPBACK)) ==
	IFACE_INFO_UP)
      if (iface_getaddr_first(ii, AF_INET6)) {
	if (idx) {
	  if (count == size)
	    return count;
	  *idx++ = iface_if_getindex(ii);
	}
	count++;
      }

  iface_destroy(ih);
  return count;
}


#if 0
// check for using only SIOCGIF* instead of sysctl, it seems more
// protable


#define ESTIMATED_LOCAL 20


/*@brief expand sockaddr's included in <code>ifam</code>
 *
 *@param ifam message containing information about interface
 *            addresses.
 *@param ai structure where addresses will be expanded.
 */


void iface_unpackaddr(struct ifa_msghdr *ifam, struct rt_addrinfo *ai){
  char *wp;
  int rtax;

  wp = (char *)(ifam + 1);

  ai->rti_addrs = ifam->ifam_addrs;
  for (rtax = 0; rtax < sizeof ai->rti_info / sizeof *ai->rti_info; rtax++)
    if (ifam->ifam_addrs & (1 << rtax)) {
      ai->rti_info[rtax] = (struct sockaddr *)wp;
      wp += ROUNDUP(ai->rti_info[rtax]->sa_len);
    } else
      ai->rti_info[rtax] = NULL;
}


/*@ find all IP interfaces addreses
 *
 *@param type  adresses family (AF_INET / AF_INET6)
 *@param size  number of addresses found
 *@param addr  buffer of list of adresses should be IPv4/IPv6
 */

int iface_getalladdr(int type, int *size, char **addr){
  int mib[6], n, s, alloced;
  size_t needed;
  char *buf, *end, *ptr;
  struct if_msghdr *ifm;
  struct ifa_msghdr *ifam;
  struct rt_addrinfo ai;
  struct ifreq ifr;
  struct sockaddr_dl *dl;
  struct sockaddr_in6 *sin;
  int num_local = -1;
  struct in6_addr *saddr;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[4] = NET_RT_IFLIST;
  mib[2] = mib[3] = mib[5] = 0;

  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    return -1;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    goto failed;
  if ((buf = (char *)malloc(needed)) == NULL)
    goto failed;
  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
    goto failed;
  num_local = 0;
  alloced = 0;
  end = buf + needed;

  for (ptr = buf; ptr < end; ptr += ifm->ifm_msglen) {
    ifm = (struct if_msghdr *)ptr;
    dl = (struct sockaddr_dl *)(ifm + 1);
    if (ifm->ifm_index != dl->sdl_index || dl->sdl_nlen == 0)
      /* Skip over remaining ifa_msghdrs */
      continue;
    n = dl->sdl_nlen > sizeof(ifr.ifr_name) ?
      sizeof(ifr.ifr_name) : dl->sdl_nlen;
    strncpy(ifr.ifr_name, dl->sdl_data, n);
    if (n < sizeof (ifr.ifr_name))
      ifr.ifr_name[n] = '\0';
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
      return -1;
    else if (ifr.ifr_flags & IFF_UP) {
      ifam = (struct ifa_msghdr *)(ptr + ifm->ifm_msglen);
      while ((char *)ifam < end && ifam->ifam_type == RTM_NEWADDR) {
	iface_unpackaddr(ifam, &ai);
	switch (type){
	case AF_INET:
	  if (ai.rti_info[RTAX_IFA] != NULL &&
	      ai.rti_info[RTAX_IFA]->sa_family == AF_INET) {
	    if (alloced < num_local + 1) {
	      alloced += ESTIMATED_LOCAL;
	      saddr = (struct in_addr *)realloc(saddr, alloced * sizeof(struct in_addr));
	      if (saddr == NULL) {
		num_local = 0;
		goto failed;
		break;
	      }
	    }
	    memcpy((struct in_addr *)&saddr[num_local++],
		   &(((struct sockaddr_in *)ai.rti_info[RTAX_IFA])->sin_addr),
		   sizeof(struct in_addr));
	  }
	  break;
	case AF_INET6:
	  if (ai.rti_info[RTAX_IFA] != NULL &&
	      ai.rti_info[RTAX_IFA]->sa_family == AF_INET6) {
	    sin = (struct sockaddr_in6 *)ai.rti_info[RTAX_IFA];
	    if (!IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr) &&
		!IN6_IS_ADDR_LOOPBACK(&sin->sin6_addr)){
	      if (alloced < num_local + 1) {
		alloced += ESTIMATED_LOCAL;
		saddr = (struct in6_addr *)realloc(saddr, alloced * sizeof saddr[0]);
		if (saddr == NULL) {
		  num_local = 0;
		  goto failed;
		  break;
		}
	      }
	    }
	    memcpy(&saddr[num_local++],&sin->sin6_addr, sizeof(struct in6_addr));
	  }
	  break;
	default:
	  goto failed;
	}
	ifam = (struct ifa_msghdr *)((char *)ifam + ifam->ifam_msglen);
      }
    }
  }
  free(buf);
  close(s);
  *size = num_local;
  *addr = (char *)saddr;
  return 1;
 failed:
  free(buf);
  close(s);
  *size = num_local;
  *addr = NULL;
  return -1;
}

#endif

#endif /* INET6 */

#endif /* 0 */

/* ********************************************************************** */

void sanitizeIfName(char *deviceDescr) {
#ifdef WIN32
	int i;

	for(i=0; i<strlen(deviceDescr); i++)
    switch(deviceDescr[i]) {
    case ':':
    case '/':
    case '\\':
	case '.':
	case ' ':
      deviceDescr[i] = '_';
    }
#endif
}

/* ********************************************************************** */

void calculateUniqueInterfaceName(int deviceId) {
  if(myGlobals.device[deviceId].uniqueIfName) 
    free(myGlobals.device[deviceId].uniqueIfName);

  myGlobals.device[deviceId].uniqueIfName = strdup(myGlobals.device[deviceId].humanFriendlyName);
  sanitizeIfName(myGlobals.device[deviceId].uniqueIfName);
}

/* ********************************************************************** */

#ifdef HAVE_SNMP

#undef NETSNMP_USE_INLINE
#define NETSNMP_BROKEN_INLINE

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>



#ifndef min
#define min(a,b) (a<b ? a : b)
#endif

char* getIfName(char *hostname, char *community, int ifIdx,
		char *ifName_buf, u_short ifName_buflen) {
  struct snmp_session session, *ss;
  struct snmp_pdu *pdu;
  struct snmp_pdu *response;
  char buf[64];
  oid anOID[MAX_OID_LEN];
  size_t anOID_len = MAX_OID_LEN;
  struct variable_list *vars;
  int status;

  ifName_buf[0] = '\0';

  /*
   * Initialize the SNMP library
   */
  init_snmp("ntop");

  /*
   * Initialize a "session" that defines who we're going to talk to
   */
  snmp_sess_init( &session );                   /* set up defaults */
  session.peername = strdup(hostname);

  /* set up the authentication parameters for talking to the server */

  /* set the SNMP version number */
  session.version = SNMP_VERSION_1;

  /* set the SNMPv1 community name used for authentication */
  session.community = (u_char*)community;
  session.community_len = strlen(community);

  /*
   * Open the session
   */
  ss = snmp_open(&session); /* establish the session */

  if (!ss)
    return(ifName_buf);  
    
  pdu = snmp_pdu_create(SNMP_MSG_GET);

  snprintf(buf, sizeof(buf), ".1.3.6.1.2.1.31.1.1.1.1.%d", ifIdx);
  read_objid(buf, anOID, &anOID_len); snmp_add_null_var(pdu, anOID, anOID_len);

  traceEvent(CONST_TRACE_NOISY, 
	     "Reading SNMP interface name: [host=%s][community=%s][ifIdx=%d]",
	     hostname, community, ifIdx);
  /*
   * Send the Request out.
   */
  status = snmp_synch_response(ss, pdu, &response);

  /*
   * Process the response.
   */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    /* manipuate the information ourselves */
    for(vars = response->variables; vars; vars = vars->next_variable) {
      if (vars->type == ASN_OCTET_STR) {
	int len = min(vars->val_len, ifName_buflen-1);
	memcpy(ifName_buf, vars->val.string, len);
	ifName_buf[len] = '\0';
      }
    }
  }

  /*
   * Clean up:
   *  1) free the response.
   *  2) close the session.
   */
  if (response) snmp_free_pdu(response);
  snmp_close(ss);

  return (ifName_buf);
}

#endif
