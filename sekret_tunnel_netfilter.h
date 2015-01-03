#include <linux/types.h>

#define IPPROTO_SEKRET 150

struct sekret_header{
		__u32	signature; 		/* should be SEKRET_SIGNATURE 				*/
		__u32 	msg_id;			/* message id, to detect lost packets 		*/
		__be32	saddr;			/* source address (IP)						*/
		__be16	dport;			/* destination port 						*/
		__be16	__padding;		/* padding to 32 bits 						*/
		__u32	packet_num;		/* packet number from total 				*/
		__u32	packet_total; 	/* total packets							*/
		__u32	size_bytes;		/* payload size in bytes 					*/
};

