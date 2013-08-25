#include "mrinfo.h"
#include "output.h"

char *target;

int
main (int argc, char *argv[])
{
  if (argc < 2)
      o_error (OUT_HELP);

  /* Get command-line parameters */
  int opt;
  int timeout = 5;
  char *iface;
  while ((opt = getopt (argc, argv, "ht:")) != -1)
    switch (opt)
      {
        case 'h':
          o_error (OUT_HELP);
          break;
        case 't':
          timeout = atoi (optarg);
          if ((timeout < 1) || (timeout > 30))
            o_error (OUT_TIMEOUTVAL);
          break;
        case '?':
        default:
          o_error (OUT_HELP);
          break;
      }
  if (argc != optind + 1)
    o_error (OUT_HELP);
  target = argv[optind];

  /* Determine the target address. */
  struct addrinfo hints, *targetinfo, *p;
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  if ((getaddrinfo (target, "80" , &hints, &targetinfo)) != 0)
    o_error (OUT_GETADDRINFO);
  for (p = targetinfo; p != NULL; p = p->ai_next)
    {
      if (p->ai_family == AF_INET)
        {
          struct sockaddr_in *addrin = (struct sockaddr_in *) p->ai_addr;
          void *ipaddr = &(addrin->sin_addr);
          target = malloc (sizeof (INET_ADDRSTRLEN));
          if (!target)
            o_error (OUT_MALLOC);
          if ((inet_ntop (p->ai_family, ipaddr, target, INET_ADDRSTRLEN))
               == NULL)
            o_error (OUT_INETNTOP);
          break;
        }
    }

  /* Determine device to listen on */
  if (get_interface (target, &iface) == -1)
    o_error (OUT_NOIFACE);

  /* Start listener */
  struct pcap_pkthdr header;
  struct bpf_program program;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;
  if ((pcap_handle = pcap_open_live (iface, 4096, 1, timeout*1000, errbuf))
      == NULL)
    o_error (OUT_PCAPOPEN);

  /* IGMP Packets coming with target host as source */
  char *filter;
  asprintf (&filter, "src host %s and ip proto 2", target);

  if (pcap_compile (pcap_handle, &program, filter, 0, PCAP_NETMASK_UNKNOWN)
      == -1 )
    o_error (OUT_PCAPCOMPILE);

  if (pcap_setfilter (pcap_handle, &program) == -1)
    o_error (OUT_PCAPSETFILTER);
  if (send_probe (target) == -1)
    o_error (OUT_SEND);

  struct dvmrp_rprt *report;
  time_t start_time = time (NULL);
  report = (struct dvmrp_rprt *) malloc (sizeof (struct dvmrp_rprt));
  while (time (NULL) - start_time <= timeout)
    {
      if ( (packet = pcap_next (pcap_handle, &header)) == NULL)
        o_error (OUT_NORESPONSE);

      u_char *dvmrp_start = (u_char *) packet + ETHER_HDR_LEN +
                            sizeof (struct ip_hdr);
      if (parse_report (dvmrp_start, header.len - ETHER_HDR_LEN
          - sizeof (struct ip_hdr), report)
          == 0)
        {
          /* Output report */
          if (o_report (report) == -1)
            o_error (OUT_REPORT);
          exit (EXIT_SUCCESS);
        }
    }
  o_error (OUT_NORESPONSE);
}

int
parse_report (const u_char *data, unsigned int length,
              struct dvmrp_rprt *report)
{
  int i;
  struct dvmrp_neighbor *neighbor;
  struct dvmrp_iface *iface;
  /* Length of the packet should be multiple of 4 and > 8 */
  if ((length <= 8) || (length % 4 != 0))
    o_error (OUT_RLENGTH);

  memcpy ((void *) &report->hdr, data, sizeof (report->hdr));
  /* Check that the IGMP type is DVMRP */
  if (report->hdr.type != 0x13)
    return -1;

  /* Check that the code is Neighbors2 (Report) */
  if (report->hdr.code != 0x06)
    return -1;

  u_char *index = (u_char *) data + sizeof (report->hdr);
  /* Loop that parses the interfaces
   * Minimal length for an interface entry is
   * 4 (Addr) + 1 (Metric) + 1 (Treshold) + 1 (Flags) + 1 (Count)
   * + 4 (1 Neighbor)
   * */

  /* Start with allocating memory for interface */
  report->ifaces = (struct dvmrp_iface *) malloc (sizeof
                                                   (struct dvmrp_iface));
  iface = report->ifaces;

  /* Parse interface entries */
  while (length - (index - data) >= 12)
    {
      /* Local Address */
      memcpy (&iface->addr, index, sizeof (iface->addr));
      index += sizeof (iface->addr);
      /* Metric */
      memcpy (&iface->metric, index, sizeof (iface->metric));
      index += sizeof (iface->metric);
      /* Treshold */
      memcpy (&iface->treshold, index, sizeof (iface->treshold));
      index += sizeof (iface->treshold);
      /* Flags */
      memcpy (&iface->flags, index, sizeof (iface->flags));
      index += sizeof (iface->flags);
      /* Count */
      memcpy (&iface->count, index, sizeof (iface->count));
      index += sizeof (iface->count);

      /* Check that count is not == 0 and that there is still enough space for
       * the number of neighbors
       */
      if ((iface->count == 0x00)
           || ((length - (index - data))
                < iface->count * 4))
        return -1;
      /* Parse the neighbors */
      iface->neighbors = (struct dvmrp_neighbor *)
                          malloc (sizeof (struct dvmrp_neighbor));
      neighbor = iface->neighbors;
      for (i=0; i < iface->count; i++)
        {
          memcpy (&neighbor->addr, index, sizeof (neighbor->addr));
          index += sizeof (neighbor->addr);
          neighbor->next = malloc (sizeof (struct dvmrp_neighbor));
          neighbor = neighbor->next;
        }
      neighbor = NULL;
      /* Move to the next interface */
      iface->next = (struct dvmrp_iface *) malloc (sizeof
                                                    (struct dvmrp_iface));
      iface = iface->next;
    }
  iface = NULL;
  /* Additional check that we didn't get a malformed report */
  if (length != index - data)
    return -1;
  return 0;
}

int
send_probe (const char *target)
{
  int sd;
  struct sockaddr_in dstaddr;
  struct dvmrp_hdr probe;

  /* Open the appropriate socket */
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
    o_error (OUT_SOCKET);

  /* Initiate fields */
  bzero (&dstaddr, sizeof (dstaddr));
  if (inet_pton (AF_INET, target, &dstaddr.sin_addr) <=0)
    o_error (OUT_INETPTON);

  probe.type = 0x13;                /* Type: DVMRP */
  probe.code = 0x05;                /* Code: Ask Neighbors2 (Probe) */
  probe.chksum = htons (0xe8e4);    /* No need to calculate it */
  probe.reserved = 0x00;            /* Reserved field */
  probe.caps = 0x0a;                /* Capabilities field */
  probe.minor = 0x04;               /* Minor version */
  probe.major = 0x0c;               /* Major version */

  /* Send the probe */
  if (sendto (sd, &probe, sizeof (probe), 0, (struct sockaddr *) &dstaddr,
              sizeof (dstaddr))
      < 0)
    o_error (OUT_SENDTO);
  return 0;
}

int
get_interface (const char *target, char **iface)
{
  int sd;
  unsigned int i;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof (addr);
  struct ifconf ifconf;
  struct ifreq ifreq[MAXIFACES];
  struct sockaddr_in *iaddr;

  /* Open the appropriate socket */
  if ((sd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    o_error (OUT_SOCKET);

  bzero (&addr, sizeof (addr));
  if (inet_pton (AF_INET, target, &addr.sin_addr) <=0)
    o_error (OUT_INETPTON);
  addr.sin_port = htons (53);
  addr.sin_family = AF_INET;

  if ((connect (sd, (struct sockaddr *) &addr, addrlen)) == -1)
    o_error (OUT_CONNECT);

  if ((getsockname (sd, (struct sockaddr *) &addr, &addrlen)) == -1)
    o_error (OUT_GETSOCKNAME);

    /* Now, look for device name by searching for an interface that has the same
     * address */
  ifconf.ifc_buf = (char *) ifreq;
  ifconf.ifc_len = sizeof (ifreq);
  if (ioctl (sd, SIOCGIFCONF, &ifconf) == -1)
    o_error (OUT_IOCTL);
  for (i = 0; i < ifconf.ifc_len / sizeof (ifreq[0]); i++)
    {
      iaddr = (struct sockaddr_in *) &ifreq[i].ifr_addr;
      if (iaddr->sin_addr.s_addr == addr.sin_addr.s_addr)
        {
          *iface = strdup ((const char *) &ifreq[i].ifr_ifrn.ifrn_name);
          return 0;
        }
    }
  return -1;
}
