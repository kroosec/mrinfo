#define _GNU_SOURCE     /* asprintf() */

#ifndef _MRINFO_H
#define _MRINFO_H

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <errno.h>

#define ETHER_HDR_LEN 14

 /* Data structures */

struct ip_hdr
{
  uint8_t ip_ver_hl;       /* IP Version + header length */
  uint8_t ip_tos;          /* Type of service */
  uint16_t ip_len;         /* Total length (header + packet) */
  uint16_t ip_id;          /* ID number */
  uint16_t ip_frag_offset; /* Fragment offset + flags */
  uint8_t ip_ttl;          /* TTL */
  uint8_t ip_type;         /* Protocol Type */
  uint16_t ip_checksum;    /* Checksum */
  uint32_t ip_src_addr;    /* Source IP address */
  uint32_t ip_dest_addr;   /* Destination IP address */
}__attribute__ ((packed));

struct dvmrp_header
{
  uint8_t type;       /* IGMP Type. Should be always 0x13 for DVMRP */
  uint8_t code;       /* DVMRP Packet type */
  uint16_t chksum;    /* Packet checksum */
  uint8_t reserved;   /* Reserved */
  uint8_t caps;       /* Capabilities */
  uint8_t minor;      /* Minor version */
  uint8_t major;      /* Major version */
};

struct dvmrp_iface
{
  uint32_t addr;            /* Local address. */
  uint8_t metric;           /* Metric. */
  uint8_t treshold;         /* Treshold. */
  uint8_t flags;            /* Flags. */
  uint8_t count;            /* Neighbors: count. */
  char *neighbors;          /* Neighbors: Array of IPv4 addresses. */
  struct dvmrp_iface *next; /* Next interface. */
};

struct dvmrp_report
{
  struct dvmrp_header *hdr;     /* DVMRP Header. */
  struct dvmrp_iface *ifaces;   /* DVMRP Report Interfaces list. */
};

 /* Type definitions. */

typedef struct dvmrp_report dvmrp_report_t;
typedef struct dvmrp_header dvmrp_header_t;
typedef struct dvmrp_iface dvmrp_iface_t;

 /* Function declarations. */

dvmrp_report_t *
dvmrp_report_parse (const u_char *, unsigned int);

void
dvmrp_ifaces_free (dvmrp_iface_t *);

void
dvmrp_report_free (dvmrp_report_t *);

int
send_dvmrp_probe (struct in_addr *);

int
get_interface_name (struct in_addr *, char **);

int
determine_target (char *, struct in_addr *);

int
get_options (int, char **, int *, char **);

#endif /* not _MRINFO_H */
