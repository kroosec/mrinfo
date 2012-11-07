#include "mrinfo.h"
#include "output.h"

extern char *target;

int 
o_report(struct dvmrp_rprt *report)
{
    /* Output the first row */
    int i;
    char flags[6] = "";
    char iflags[50];
    char iaddr[16];
    char naddr[16];
    struct dvmrp_iface *iface;
    struct dvmrp_neighbor *neighbor;

    /* Check flags */
    if (report->hdr.caps & 0x1)
	strcat(flags, "L");
    if (report->hdr.caps & 0x2)
	strcat(flags, "P");
    if (report->hdr.caps & 0x4)
	strcat(flags, "G");
    if (report->hdr.caps & 0x8)
	strcat(flags, "M");
    if (report->hdr.caps & 0x10)
	strcat(flags, "S");
    printf("%s [Version  %d.%d] [Flags: %s]:\n", target, report->hdr.major, report->hdr.minor, flags);
    iface = report->ifaces;
        /* Output for this interface */
    while(iface != NULL)
    {
	inet_ntop(AF_INET, &iface->addr, iaddr, sizeof(iaddr));
	neighbor = iface->neighbors;
	strncpy(iflags, "", 1);
	/* Flags associated with this interface */
	if (iface->flags & 0x1)
	    strcat(iflags, "/Tunnel");
	if (iface->flags & 0x2)
	    strcat(iflags, "/Source Route");
	if (iface->flags & 0x10)
	    strcat(iflags, "/Down");
	if (iface->flags & 0x20)
	    strcat(iflags, "/Disabled");
	if (iface->flags & 0x40)
	    strcat(iflags, "/Querier");
	if (iface->flags & 0x80)
	    strcat(iflags, "/Leaf");

	for(i=0; i < iface->count; i++)
	{
	    inet_ntop(AF_INET, &neighbor->addr, naddr, sizeof(naddr));
	    printf("  %s -> %s [%d/%d%s]\n", iaddr, naddr, iface->metric, iface->treshold, iflags);
	    neighbor = neighbor->next;
	}
	iface = iface->next;
    }
    return 0;
}
