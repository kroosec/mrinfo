/* Common output error messages */
#define OUT_TIMEOUTVAL "timeout should be a value between 1 and 30.\n"
#define OUT_HELP "Usage: mrinfo [-t timeout] -i interface target\n\n"
#define OUT_PCAPOPEN "pcap_open_live() error.\n"
#define OUT_PCAPCOMPILE "pcap_compile() error.\n"
#define OUT_PCAPSETFILTER "pcap_setfilter() error.\n"
#define OUT_SEND "Error sending to the target.\n"
#define OUT_REPORT "Error outputing the received response.\n"
#define OUT_RLENGTH "Error in received response length.\n"
#define OUT_INETPTON "Error inet_pton().\n"
#define OUT_SENDTO "Error sendto().\n"
#define OUT_NOIFACE "Couldn't find interface to target host.\n"
#define OUT_SOCKET "Error in socket().\n"
#define OUT_GETADDRINFO "Error in getaddrinfo()\n"
#define OUT_MALLOC "Error in malloc().\n"
#define OUT_INETNTOP "Error in inet_ntop().\n"
#define OUT_CONNECT "Error in connect().\n"
#define OUT_GETSOCKNAME "Error in getsockname().\n"
#define OUT_IOCTL "Error in ioctl().\n"
#define OUT_NORESPONSE "No response received.\n"

#define o_error(msg)                                             \
    do {                                                         \
      printf ("%s", msg);                                        \
      exit (EXIT_FAILURE);                                       \
    } while (0)

int o_report (struct dvmrp_rprt *report);
