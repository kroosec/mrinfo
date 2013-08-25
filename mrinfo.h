#define _GNU_SOURCE     /* asprintf() */

#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

#define IP_HDR_LEN 20

#define MAXIFACES 30

/********************* Data structures ********************/
struct ip_hdr
{
  uint8_t ip_ver_hl;       /* IP Version + header length              */
  uint8_t ip_tos;          /* Type of service                         */
  uint16_t ip_len;         /* Total length (header + packet)          */
  uint16_t ip_id;          /* ID number                               */
  uint16_t ip_frag_offset; /* Fragment offset + flags                 */
  uint8_t ip_ttl;          /* TTL                                     */
  uint8_t ip_type;         /* Protocol Type                           */
  uint16_t ip_checksum;    /* Checksum                                */
  uint32_t ip_src_addr;    /* Source IP address                       */
  uint32_t ip_dest_addr;   /* Destination IP address                  */
}__attribute__ ((packed));

struct dvmrp_hdr
{
  uint8_t type;       /* IGMP Type. Should be always 0x13 for DVMRP */
  uint8_t code;       /* DVMRP Packet type                          */
  uint16_t chksum;    /* Packet checksum                            */
  uint8_t reserved;   /* Reserved                                   */
  uint8_t caps;       /* Capabilities                               */
  uint8_t minor;      /* Minor version                              */
  uint8_t major;      /* Major version                              */
}__attribute__ ((packed));

struct dvmrp_neighbor
{
  uint32_t addr;
  struct dvmrp_neighbor *next;
}__attribute__ ((packed));

struct dvmrp_iface
{
  uint32_t addr;
  uint8_t metric;
  uint8_t treshold;
  uint8_t flags;
  uint8_t count; /* Neighbors count */
  struct dvmrp_neighbor *neighbors;
  struct dvmrp_iface *next;
}__attribute__ ((packed));

struct dvmrp_rprt
{
  struct dvmrp_hdr hdr;
  struct dvmrp_iface *ifaces;
}__attribute__ ((packed));

/********************* Function prototypes ********************/
char *find_device (const char *address);

int parse_report (const u_char *packet, unsigned int length,
                  struct dvmrp_rprt *report);

int send_probe (const char *target);

int get_interface (const char *target, char **iface);
