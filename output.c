#include "mrinfo.h"
#include "output.h"

 /* Function definitions. */

/**
 * @brief Outputs a DVMRP report interface flags in printable format.
 *
 * @param[in]   flags   Flags value in report interface.
 * @param[out]  str     Buffer of at least 47 bytes size.
 *
 */
static void
set_iface_flags_str (uint8_t flags, char *str)
{
  if (str == NULL)
    return;

  str[0] = '\0';
  if (flags & 0x1)
    strcat (str, "/Tunnel");
  if (flags & 0x2)
    strcat (str, "/Source Route");
  if (flags & 0x10)
    strcat (str, "/Down");
  if (flags & 0x20)
    strcat (str, "/Disabled");
  if (flags & 0x40)
    strcat (str, "/Querier");
  if (flags & 0x80)
    strcat (str, "/Leaf");
}

/**
 * @brief Outputs a DVMRP Report interface in printable format.
 *
 * @param[in]   iface  DVMRP Report interface.
 * @param[in]   fout   File stream to output to.
 *
 */
static void
o_report_iface (const dvmrp_iface_t *iface, FILE *fout)
{
  int i;
  char flags_str[50];
  char iaddr[INET_ADDRSTRLEN], naddr[INET_ADDRSTRLEN];

  if (iface == NULL || fout == NULL)
    return;

  inet_ntop (AF_INET, &iface->addr, iaddr, sizeof (iaddr));
  /* Flags associated with this interface */
  set_iface_flags_str (iface->flags, flags_str);

  for (i=0; i < iface->count; i++)
    {
      inet_ntop (AF_INET, &(iface->neighbors[4 * i]), naddr, sizeof (naddr));
      fprintf (fout, "  %s -> %s [%d/%d%s]\n", iaddr, naddr,
               iface->metric, iface->treshold, flags_str);
    }
}

/**
 * @brief Gives a DVMRP Report's capabilities in printable format.
 *
 * @param[in]   capabilities    Capabilities value in report header.
 * @param[out]  str             Buffer of at least 6 bytes size.
 *
 */
static void
set_report_capabilities_str (uint8_t capabilities, char *str)
{
  if (str == NULL)
    return;

  str[0] = '\0';
  if (capabilities & 0x1)
    strcat (str, "L");
  if (capabilities & 0x2)
    strcat (str, "P");
  if (capabilities & 0x4)
    strcat (str, "G");
  if (capabilities & 0x8)
    strcat (str, "M");
  if (capabilities & 0x10)
    strcat (str, "S");
}

/**
 * @brief Outputs a DVMRP report in printable format.
 *
 * @param[in]   ipaddr  Target IP address.
 * @param[in]   report  DVMRP response.
 * @param[in]   fout    File stream to output to.
 *
 * @return -1 if error, 0 otherwise.
 */
int
o_report (const struct in_addr *ipaddr, const dvmrp_report_t *report,
          FILE *fout)
{
  char caps_str[6];
  char ip_str[INET_ADDRSTRLEN];
  dvmrp_iface_t *iface;

  if (ipaddr == NULL || report == NULL || fout == NULL)
    return -1;

  if (inet_ntop (AF_INET, ipaddr, ip_str, sizeof (ip_str)) == NULL)
    {
      perror ("inet_ntop()");
      return -1;
    }

  /* General information. */
  set_report_capabilities_str (report->hdr->caps, caps_str);
  fprintf (stdout, "%s [Version %d.%d] [Capabilities %s]:\n", ip_str,
           report->hdr->major, report->hdr->minor, caps_str);
  /* Interfaces information */
  iface = report->ifaces;
  while (iface != NULL)
    {
      o_report_iface (iface, fout);
      iface = iface->next;
    }
  return 0;
}

/**
 * @brief Outputs the help message to stderr.
 */
void
o_help (void)
{
  fprintf (stderr, "Usage: mrinfo [-t timeout] target\n");
}

/**
 * @brief Outputs the "no response" error message to stderr.
 */
void
o_noresponse (void)
{
  fprintf (stderr, "No response received.\n");
}
