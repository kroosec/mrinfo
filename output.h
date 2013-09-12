#ifndef _OUTPUT_H
#define _OUTPUT_H

 /* Function headers. */

int
o_report (const struct in_addr *, const dvmrp_report_t *, FILE *);

void
o_help (void);

void
o_noresponse (void);

#endif /* not _OUTPUT_H */
