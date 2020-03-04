#ifndef _XT_RAWCOOKIE_H
#define _XT_RAWCOOKIE_H

#define XT_RAWCOOKIE_OPT_MSS		0x01
#define XT_RAWCOOKIE_OPT_WSCALE		0x02
#define XT_RAWCOOKIE_OPT_SACK_PERM	0x04
#define XT_RAWCOOKIE_OPT_TIMESTAMP	0x08
#define XT_RAWCOOKIE_OPT_ECN		0x10

struct xt_rawcookie_info {
	__u8	options;
	__u8	wscale;
	__u16	mss;
};

#endif /* _XT_RAWCOOKIE_H */
