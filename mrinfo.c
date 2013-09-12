#include "mrinfo.h"
#include "output.h"


/**
 * @brief Opens a network interface for packet capturing.
 *
 * @param[in]   iface       Name of the interface (device) to listen on.
 * @param[in]   timeout     Packets read timeout in seconds.
 *
 * @return pcap_handle on success, NULL on error.
 */
pcap_t *
get_pcap_handle (const char *iface, int timeout)
{
  pcap_t *pcap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_handle = pcap_open_live (iface, 4096, 1, timeout*1000, errbuf);
  if (pcap_handle == NULL)
    {
      fprintf (stderr, "%s\n", errbuf);
      return NULL;
    }

  return pcap_handle;
}

/**
 * @brief Gets the filter string to apply when capturing dvmrp report.
 *
 * @param[in]   ipaddr      Target IP address.
 *
 * @return NULL if error, Pointer to dynamically allocated filter string
 * otherwise.
 */
char *
get_filter_str (struct in_addr *ipaddr)
{
  char *filter, target[INET_ADDRSTRLEN];

  if (inet_ntop (AF_INET, ipaddr, target, sizeof (target)) == NULL)
    {
      perror ("inet_ntop()");
      return NULL;
    }

  asprintf (&filter, "src host %s and ip proto 2", target);
  return filter;
}

/**
 * @brief Starts a pcap listener for DVMRP reports.
 *
 * @param[in]   ipaddr      Address of report sender.
 * @param[in]   timeout     Packets read timeout in seconds.
 *
 * @return pcap_handle on success, NULL on error.
 */
pcap_t *
start_dvmrp_listener (struct in_addr *ipaddr, int timeout)
{
  struct bpf_program program;
  pcap_t *pcap_handle;
  char *iface, *filter;

  /* Determine device to listen on */
  if (get_interface_name (ipaddr, &iface) == -1)
    return NULL;

  pcap_handle = get_pcap_handle (iface, timeout);
  free (iface);
  if (pcap_handle == NULL)
    return NULL;

  /* Get filter string. */
  if ((filter = get_filter_str (ipaddr)) == NULL)
    return NULL;

  if (pcap_compile (pcap_handle, &program, filter, 0, PCAP_NETMASK_UNKNOWN)
      == -1)
  {
    free (filter);
    fprintf (stderr, "%s\n", pcap_geterr (pcap_handle));
    return NULL;
  }
  free (filter);

  if (pcap_setfilter (pcap_handle, &program) == -1)
    {
      fprintf (stderr, "%s\n", pcap_geterr (pcap_handle));
      return NULL;
    }

  return pcap_handle;
}

int
main (int argc, char *argv[])
{
  char *hostname;
  struct in_addr ipaddr;
  pcap_t *pcap_handle;
  int timeout = 5;
  time_t start_time;

  if (get_options (argc, argv, &timeout, &hostname) == -1)
    {
      o_help ();
      exit (EXIT_FAILURE);
    }

  if (determine_target (hostname, &ipaddr) == -1)
    return EXIT_FAILURE;

  /* Start listener */
  if ((pcap_handle = start_dvmrp_listener (&ipaddr, timeout)) == NULL)
    return EXIT_FAILURE;

  if (send_dvmrp_probe (&ipaddr) == -1)
    return EXIT_FAILURE;

  start_time = time (NULL);
  while (time (NULL) - start_time <= timeout)
    {
      int ip_length;
      struct pcap_pkthdr header;
      const u_char *packet, *dvmrp_start;
      dvmrp_report_t *report;

      if ((packet = pcap_next (pcap_handle, &header)) == NULL)
        {
          o_noresponse ();
          return EXIT_FAILURE;
        }

      /* Get IP total header length rather than use header.len directly as
       * ethernet frames may be padded up to 64.
       */
      ip_length = ntohs (((struct ip_hdr *) (packet + ETHER_HDR_LEN))->ip_len);
      dvmrp_start = (u_char *) packet + ETHER_HDR_LEN + sizeof (struct ip_hdr);
      report = dvmrp_report_parse (dvmrp_start, ip_length - 20);
      if (report)
        {
          /* Output report */
          if (o_report (&ipaddr, report, stdout) == -1)
            {
              dvmrp_report_free (report);
              return EXIT_FAILURE;
            }
          dvmrp_report_free (report);
          return EXIT_SUCCESS;
        }
    }

  o_noresponse ();
  return EXIT_FAILURE;
}

/**
 * @brief Determines the IPv4 address from a hostname.
 *
 * @param[in]   hostname      Hostname to resolve.
 * @param[out]  ipaddr        Buffer for IP address.
 *
 * @return 0 if success, -1 otherwise.
 */
int
determine_target (char *hostname, struct in_addr *ipaddr)
{
  int err;
  struct addrinfo hints, *targetinfo, *p;

  if (ipaddr == NULL || hostname == NULL)
    return -1;

  /*
   * Directly check if user provided an IPv4 address as the
   * target.
   */
  if (inet_pton (AF_INET, hostname, ipaddr) == 1)
    return 0;

  bzero (&hints, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  err = getaddrinfo (hostname, NULL, &hints, &targetinfo);
  if (err)
    {
      fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (err));
      return -1;
    }

  p = targetinfo;
  while (p)
    {
      if (p->ai_family == AF_INET)
        {
          struct sockaddr_in *addrin = (struct sockaddr_in *) p->ai_addr;

          memcpy (ipaddr, &(addrin->sin_addr), 4);
          freeaddrinfo (targetinfo);
          return 0;
        }
      p = p->ai_next;
    }

  freeaddrinfo (targetinfo);
  return -1;
}

/**
 * @brief Parses a data buffer as a DVMRP Header.
 *
 * @param[in]   data          Data buffer.
 *
 * @return DVMRP Header pointer on success, NULL on failure.
 */
dvmrp_header_t *
dvmrp_header_parse (const u_char *data)
{
  dvmrp_header_t *new_header;

  if (data == NULL)
    return NULL;

  new_header = calloc (sizeof (dvmrp_header_t), 1);
  /* IGMP Type. */
  memcpy (&new_header->type, data, 1);
  /* DVMRP type. */
  memcpy (&new_header->code, data + 1, 1);
  /* Packet checksum. */
  memcpy (&new_header->chksum, data + 2, 2);
  /* Reserved. */
  memcpy (&new_header->reserved, data + 4, 1);
  /* Capabilities. */
  memcpy (&new_header->caps, data + 5, 1);
  /* Minor version. */
  memcpy (&new_header->minor, data + 6, 1);
  /* Major version. */
  memcpy (&new_header->major, data + 7, 1);

  return new_header;
}

/**
 * @brief Parses a data buffer as a DVMRP Report interface.
 *
 * @param[in]   data          Data buffer.
 * @param[in]   length        Data buffer length.
 * @param[out]  iface         Parsed DVMRP Interface.
 *
 * @return Pointer to next interface in buffer, NULL on failure.
 */
const u_char *
dvmrp_iface_parse (const u_char *data, int length, dvmrp_iface_t **iface)
{
  dvmrp_iface_t *new_iface;

  if (data == NULL || iface == NULL)
    return NULL;

  new_iface = calloc (sizeof (dvmrp_iface_t), 1);
  if (new_iface == NULL)
    return NULL;

  /* Local Address */
  memcpy (&new_iface->addr, data, 4);
  /* Metric */
  memcpy (&new_iface->metric, data + 4, 1);
  /* Treshold */
  memcpy (&new_iface->treshold, data + 5, 1);
  /* Flags */
  memcpy (&new_iface->flags, data + 6, 1);
  /* Count */
  memcpy (&new_iface->count, data + 7, 1);
  data += 8;

  /**
   * Check that count is not 0 and that there is still enough space for the
   * number of neighbors.
   */
  if ((new_iface->count == 0x00) || (length < 8 + (new_iface->count * 4)))
    {
      free (new_iface);
      return NULL;
    }
  /* Parse the neighbors */
  new_iface->neighbors = calloc (4, new_iface->count);
  memcpy (new_iface->neighbors, data, 4 * new_iface->count);
  data += 4 * new_iface->count;
  *iface = new_iface;
  return data;
}

/**
 * @brief Parses a data buffer as a list of DVMRP Report interfaces.
 *
 * @param[in]   data          Data buffer.
 * @param[in]   length        Data buffer length.
 *
 * @return DVMRP Report interfaces on success, NULL on failure.
 */
dvmrp_iface_t *
dvmrp_ifaces_parse (const u_char *data, int length)
{
  const u_char *index;
  dvmrp_iface_t *ifaces, *iface;

  if (data == NULL)
    return NULL;

  index = data;
  ifaces = NULL;
  while (data + length - index >= 12)
    {
      dvmrp_iface_t *new_iface;

      index = dvmrp_iface_parse (index, data + length - index, &new_iface);
      if (index == NULL || new_iface == NULL)
        {
          dvmrp_ifaces_free (ifaces);
          return NULL;
        }
      /* If first interface, link in ifaces list. */
      if (ifaces == NULL)
        {
          iface = new_iface;
          ifaces = iface;
        }
      else
        {
          iface->next = new_iface;
          iface = iface->next;
        }
    }

  /* Additional check that we didn't get a malformed ifaces list. */
  if (length != index - data)
    {
      dvmrp_ifaces_free (ifaces);
      return NULL;
    }

  return ifaces;
}

/**
 * @brief Parses a data buffer as a list of DVMRP Report.
 *
 * @param[in]   data          Data buffer.
 * @param[in]   length        Data buffer length.
 *
 * @return DVMRP Report on success, NULL on failure.
 */
dvmrp_report_t *
dvmrp_report_parse (const u_char *data, unsigned int length)
{
  dvmrp_report_t *report;

  /* Length of the packet should be multiple of 4 and at least 8 bytes. */
  if ((length < 8) || (length % 4 != 0))
    return NULL;

  report = calloc (sizeof (*report), 1);
  if (report == NULL)
    {
      perror ("calloc()");
      return NULL;
    }

  /* Parse DVMRP Report header. */
  report->hdr = dvmrp_header_parse (data);
  if (report->hdr == NULL)
    {
      dvmrp_report_free (report);
      return NULL;
    }
  data += 8;

  /* IGMP type is DVMRP and code is Neighbors2 (Report). */
  if (report->hdr->type != 0x13 || report->hdr->code != 0x06)
    {
      dvmrp_report_free (report);
      return NULL;
    }

  /**
   * Parse interface entries.
   * Minimal length for an interface entry is 12:
   * 4 (Addr) + 1 (Metric) + 1 (Treshold) + 1 (Flags) + 1 (Count)
   * + 4 (1 Neighbor)a.
   */
  if (length - 8 >= 12)
    {
      report->ifaces = dvmrp_ifaces_parse (data, length - 8);
      if (report->ifaces == NULL)
        {
          dvmrp_report_free (report);
          return NULL;
        }
    }

  return report;
}

/**
 * @brief Frees a list of DVMRP report interfaces.
 *
 * @param[in]   report        Report to free.
 */
void
dvmrp_ifaces_free (dvmrp_iface_t *ifaces)
{
  while (ifaces)
    {
      dvmrp_iface_t *tmp;
      tmp = ifaces;
      ifaces = ifaces->next;
      if (tmp->neighbors)
        free (tmp->neighbors);
      free (tmp);
    }
}

/**
 * @brief Frees the memory occupied by a DVMRP Report.
 *
 * @param[in]   report        Report to free.
 */
void
dvmrp_report_free (dvmrp_report_t *report)
{
  if (report == NULL)
    return;
  if (report->hdr)
    free (report->hdr);
  dvmrp_ifaces_free (report->ifaces);
  free (report);
}

/**
 * @brief Sends a DVMRP Ask Neighbors 2 probe to a target.
 *
 * @param[in]   ipaddr  Target IP address.
 *
 * @return -1 if error, 0 otherwise.
 */
int
send_dvmrp_probe (struct in_addr *ipaddr)
{
  int sd;
  struct sockaddr_in dstaddr;
  dvmrp_header_t probe;

  if (ipaddr == NULL)
    return -1;

  /* Open the appropriate socket */
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
    {
      perror ("socket()");
      return -1;
    }

  /* Initiate fields */
  bzero (&dstaddr, sizeof (dstaddr));
  dstaddr.sin_addr = *ipaddr;

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
    {
      perror ("sendto()");
      return -1;
    }
  return 0;
}

/**
 * @brief Gets the name of network interface to use for target IP.
 *
 * @param[in]   ipaddr      Target IP address.
 * @param[out]  hostname    Local network interface name.
 *
 * @return -1 if error, 0 otherwise.
 */
int
get_interface_name (struct in_addr *ipaddr, char **iface)
{
#define MAXIFACES 30

  int sd;
  unsigned int i;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof (addr);
  struct ifconf ifconf;
  struct ifreq ifreq[MAXIFACES];
  struct sockaddr_in *iaddr;

  if (ipaddr == NULL)
    return -1;

  /* Open the appropriate socket */
  if ((sd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      perror ("socket()");
      return -1;
    }

  bzero (&addr, sizeof (addr));
  addr.sin_addr = *ipaddr;
  addr.sin_port = htons (53);
  addr.sin_family = AF_INET;

  if ((connect (sd, (struct sockaddr *) &addr, addrlen)) == -1)
    {
      perror ("connect()");
      return -1;
    }

  if ((getsockname (sd, (struct sockaddr *) &addr, &addrlen)) == -1)
    {
      perror ("getsockname()");
      return -1;
    }

    /* Now, look for device name by searching for an interface that has the same
     * address */
  ifconf.ifc_buf = (char *) ifreq;
  ifconf.ifc_len = sizeof (ifreq);
  if (ioctl (sd, SIOCGIFCONF, &ifconf) == -1)
    {
      perror ("ioctl()");
      return -1;
    }
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

/**
 * @brief Gets the options from command-line arguments.
 *
 * @param[in]   argc        Arguments count.
 * @param[in]   argv        Arguments vector.
 * @param[out]  timeout     Timeout value, if provided.
 * @param[out]  hostname    Hostname value, if provided. Statically allocated.
 *
 * @return -1 if error, 0 otherwise.
 */
int
get_options (int argc, char **argv, int *timeout, char **target)
{
  int opt;

  if (argc < 2 || argv == NULL || timeout == NULL || target == NULL)
    return -1;

  while ((opt = getopt (argc, argv, "ht:")) != -1)
    switch (opt)
      {
        case 't':
          *timeout = atoi (optarg);
          if (*timeout < 1)
            {
              fprintf (stderr, "timeout should be at least 1.\n");
              return -1;
            }
          break;
        case 'h':
        case '?':
        default:
          return -1;
      }
  if (argc != optind + 1)
    return -1;

  *target = argv[optind];
  return 0;
}

