#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h> /* for proc_fs */


#include <net/tcp.h>

#include "sekret_tunnel_netfilter.h"

#define SEKRET_DEBUG (0)


/*NOTE: 10.0.2.15(167772687)*/
/* 32bit packet identifer*/
#define SEKRET_SIGNATURE (0xAB007B1F)
#define SEKRET_C_OPEN_PORT (5555)
#define SEKRET_UDP_PACKET_SIZE_MAX (512)

/* packets will be redirected to the followign address */
/* should be __be32 */
static uint target_ip = 0x7F000001; /* 127.0.0.1 */
module_param(target_ip, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(target_ip, "Target Sekret server IP (in hex)");

/* netfilter hooks */
static struct nf_hook_ops rx_nfho;
static struct nf_hook_ops tx_nfho;

#define SEKRET_PORTS_NUM (2)
static int sekret_ports[SEKRET_PORTS_NUM]={80, 123};
#define SEKRET_TUNNEL_IP_NUM (2)
static __be32 sekret_current_machine_ip[SEKRET_TUNNEL_IP_NUM] = {0,0};

/** Forward decleration *******************************************************/
bool __is_tunneled_connection(struct iphdr* ip_header, struct udphdr* udp_header);
unsigned int __port_str_int(char* port_str);
static unsigned int rx_hook_func(const struct nf_hook_ops *ops,
	struct sk_buff* skb,
	const struct net_device* in,
	const struct net_device* out,
	int (*okfn)(struct sk_buff*)
	);
static unsigned int tx_hook_func(
	const struct nf_hook_ops *ops,
	struct sk_buff* skb,
	const struct net_device* in,
	const struct net_device* out,
	int (*okfn)(struct sk_buff*)
	);
static bool __sek_port_in_redirect_list(unsigned int port);
static bool __sek_ip_in_locals_list(__be32 ip);

/******************************************************************************/

unsigned int __port_str_int(char* port_str){
	unsigned int port = 0;
	int i = 0;
	
	if (port_str == NULL)
		return 0;

	while (port_str[i]!='\0'){
		port = port*10 + (port_str[i]-'0');
		++i;
	}
	return port;
}

/* 
 * listen for incoming packets, if a Sekret packet is recognized, 
 * get the data and redirect it to the listening application
 */
static unsigned int rx_hook_func(
	const struct nf_hook_ops *ops,
	struct sk_buff* skb,
	const struct net_device* in,
	const struct net_device* out,
	int (*okfn)(struct sk_buff*)
	){

	//LOCAL_IN hook: encapsulated reply packet (from eth1)
	//FORWARD hook: reply packet (from eth1 -> eth0).

	static struct sk_buff* sock_buff;
	static struct iphdr*	ip_header;
//	static struct udphdr* 	udp_header;
	static struct sekret_header* sek_header;

	sock_buff = skb;
	
	if (!sock_buff)
		return NF_ACCEPT;

	ip_header = (struct iphdr*) skb_network_header(sock_buff);
	if (!ip_header)
		return NF_ACCEPT;

	if (ip_header->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	sek_header = (struct sekret_header*) 
		( skb_transport_header(sock_buff) + sizeof(struct iphdr) );

	/* recognize sekret data structure */
	if (sek_header->signature != SEKRET_SIGNATURE)
		return NF_ACCEPT;
		
	#if SEKRET_DEBUG > 0
	printk(KERN_INFO "[SEK] DEBUG: th: 0p:%p\n", 
		sek_header);
	printk(KERN_INFO "[SEK] DEBUG: nh: 0p:%p\n", 
		skb_network_header(sock_buff));
	printk(KERN_INFO "[SEK] DEBUG: mh: 0p:%p\n",
		skb_mac_header(sock_buff));
	printk(KERN_INFO "[SEK] DEBUG: length: sek_header:%d"
		"| dport:%d | signature:%d\n",
		 sizeof(sek_header),
		 sizeof(sek_header->dport),
		 sizeof(sek_header->signature));
	printk(KERN_INFO "[SEK] DEBUG: From IP address: %d.%d.%d.%dn",
		ip_header-saddr & 0x000000FF,
		(ip_header->saddr & 0x0000FF00) >> 8,
		(ip_header->saddr & 0x00FF0000) >> 16,
		(ip_header->saddr & 0xFF000000) >> 24);
	#endif

	printk(KERN_INFO "[SEK] Got a Sekret packet for port=%d.\n",
		ntohs(sek_header->dport));

	/* Strip header */

	/* Get data */

	/* construct a new ip packet */

	/* Send data to target */
	/* change target port to localhost */

	
	/* Done */
	return NF_DROP;
	return NF_QUEUE; /* queue packet to user space*/
}


/* 
 * test if the port is in the redirected ports list
 */
static bool __sek_port_in_redirect_list(unsigned int port){
 	unsigned int port_idx = 0;
    for (;port_idx < SEKRET_PORTS_NUM; port_idx++) {
    	if (port == sekret_ports[port_idx]) {
    		return true;
    	}
    }
    return false;
}

/* 
 * test if the ip is local ip
 */
static bool __sek_ip_in_locals_list(__be32 ip){
 	unsigned int ip_idx =0;
    for (;ip_idx < SEKRET_TUNNEL_IP_NUM; ip_idx++) {
    	if (ip == sekret_current_machine_ip[ip_idx]) {
    		return true;
    	}
    }
    return false;
}

bool __is_tunneled_connection(struct iphdr* ip_header, struct udphdr* udp_header){
   	unsigned int dest_ip  = 0;
   	//static char *drop_if = "lo";

    /* filter by port */
    unsigned int dest_port = (unsigned int)ntohs(udp_header->dest); 
    printk(KERN_ALERT "[SEK] received packet from port: %d\n",dest_port);
    if (false == __sek_port_in_redirect_list(dest_port) )
    	return false;

    printk(KERN_ALERT "[SEK] packet to port 80 or 123\n");
    /* filter by ip - verify target ip is the current machine*/
    dest_ip = (unsigned int)ip_header->daddr;

    /* accept messages to local interface */

    if (false == __sek_ip_in_locals_list(dest_ip) )
    	return false;

    printk(KERN_ALERT "[SEK] packet to local machine\n");

#ifdef FILTER_DEMO
     unsigned char *deny_ip = "\x7f\x00\x00\x01";  /* 127.0.0.1 */
	  
	  ...

          static int check_ip_packet(struct sk_buff *skb)
          {
              /* We don't want any NULL pointers in the chain to
	       * the IP header. */
              if (!skb )return NF_ACCEPT;
              if (!(skb->nh.iph)) return NF_ACCEPT;
          
              if (skb->nh.iph->saddr == *(unsigned int *)deny_ip) { 
	          return NF_DROP;
              }

              return NF_ACCEPT;
          }
#endif

    return true;
}

/* 
* Modifies the header and adds a sekret packet information
*/
int __create_sek_packet(
		struct sk_buff* sock_buff_in,
	 	struct sk_buff** sock_buff_out){
	
	/* http://stackoverflow.com/questions/13071054/how-to-echo-a-packet-in-kernel-space-using-netfilter-hooks*/
	static struct iphdr*   ip_header;
	static struct udphdr*  udp_header;

	unsigned char* 	payload;   /* packet payload */
	unsigned char*	payload_copy; /* */
	unsigned int 	payload_len_bytes; /* packet payload length in bytes */
   
    struct sekret_header sek_header;
    struct sekret_header* p_sek_header;

    int total_header_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    int sekret_header_len = sizeof(struct sekret_header);
    int header_delta = 0;
    int udp_len = 0;

    /* pointers to existing data */
    ip_header  = (struct iphdr*) skb_network_header(sock_buff_in);
    udp_header = (struct udphdr *) (ip_header + ip_hdrlen(sock_buff_in) );
    payload    = (unsigned char *) (skb_header_pointer(sock_buff_in,
    	sizeof(struct iphdr) + sizeof(struct udphdr),0, NULL));
    payload_len_bytes = sock_buff_in->len - total_header_len;

    /* sekret header */
    sek_header.signature 	= SEKRET_SIGNATURE;
    sek_header.dport   		= udp_header->dest;
    sek_header.packet_num	= 1; /* for now */
    sek_header.packet_total = 1; /* for now */
    sek_header.size_bytes	= payload_len_bytes;


    udp_len = sekret_header_len + payload_len_bytes + sizeof(struct udphdr);
	/* forge the source and target address and port */ 
    ip_header->saddr 	= sekret_current_machine_ip[1]; /* local machine ip */
	ip_header->daddr 	= target_ip;  /* target machine ip */
	ip_header->tot_len  = htons(udp_len + sizeof(struct iphdr));

	udp_header->dest    = htons(SEKRET_OPEN_PORT);  /* port 5555 */
	udp_header->len     = htons(udp_len); 

	
	/* NOTE: make payload copy - move to static buffer*/
	payload_copy = kmalloc(payload_len_bytes, GFP_ATOMIC);
	memcpy(payload_copy, payload, payload_len_bytes);

	/* allocate extra space is needed */
	header_delta = sekret_header_len - skb_headroom(sock_buff_in);
	if (header_delta > 0){
		/* allocate a new skb */
		if (0 != pskb_expand_head(sock_buff_in, header_delta, 0,GFP_ATOMIC)) {
			printk(KERN_ALERT 
			"[SEK] __create_sek_packet:: failed to allocate memory.\n");
			kfree(payload_copy);
			return -1;
		}
	}
	p_sek_header = (struct sekret_header*)skb_push(
		sock_buff_in, sekret_header_len);

	/* add sekret header */
	memcpy(p_sek_header, &sek_header, sekret_header_len);
	
	/* add the payload */
	memcpy(p_sek_header + sekret_header_len, payload_copy, payload_len_bytes);


	/* free allocated memory*/
	kfree(payload_copy);

	/* calculate ip checksum */
	ip_header->check = 0;
	ip_send_check(ip_header);

	/* calculate udp checksum */
	udp_header->check = 0;
	int offset = skb_transport_offset(sock_buff_in);
	int len = sock_buff_in->len - offset;
	udp_header->check = ~csum_tcpudp_magic(ip_header->saddr,ip_header->daddr,
		len, IPPROTO_UDP, 0);

	*sock_buff_out = sock_buff_in;

	return 0;

}

/*
* recognize packets going to localhost on ports 80 and 123
* wrap with sekret packet, and send to target server
*/
static unsigned int tx_hook_func(
	const struct nf_hook_ops *ops,
	struct sk_buff* skb,
	const struct net_device* in,
	const struct net_device* out,
	int (*okfn)(struct sk_buff*)
	){

	static struct sk_buff* sock_buff;
	static struct sk_buff* sock_buff_sek; /* sekret packet */
	static struct iphdr*   ip_header;
	static struct udphdr*  udp_header;
	//static struct sekret_header* sek_header;
	//unsigned int src_port;
	//unsigned int dest_port;
	//unsigned int src_ip;
	//unsigned int dest_ip;
	//unsigned int sekret_port;

	sock_buff = skb;
	
	if (!sock_buff)
		return NF_ACCEPT;

	ip_header = (struct iphdr*) skb_network_header(sock_buff);
	if (!ip_header)
		return NF_ACCEPT;

	if (ip_header->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	/* Recognize that the packet is for port 80 or 123 */
	/* and the target is the local machine only for UDP */
	udp_header = (struct udphdr *) (ip_header + ip_hdrlen(sock_buff) );

	if (false == __is_tunneled_connection(ip_header, udp_header) )
		return NF_ACCEPT;
   
    printk(KERN_ALERT "[SEK] tunneled packet found \n");


    
    //return 0; /* DEBUG */


    /* Add sekret packet after the */
    if ( 0 != __create_sek_packet(sock_buff, &sock_buff_sek))
    	return NF_ACCEPT;
    
    printk(KERN_ALERT "[SEK] sekretg header added to packet\n");
   
	/* add the packet back after the firewall 					*/
	/* NOTE: also so the packet won't get caught by the rx hook :) */
	

	/* remove tracking information - the packet has changed */
    #ifdef CONFIG_NETFILTER
            nf_conntrack_put(skb->nfct);
            skb->nfct = NULL;
    #ifdef CONFIG_NETFILTER_DEBUG
             skb->nf_debug = 0;
    #endif
    #endif

    /* Send "new" packet from local host */
    /* reinject the skb back to the queue */
    //nf_reinject();
    //NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, sock_buff_sek, NULL, rt->u.dst.dev, ip_send);
    okfn(sock_buff_sek);
	return NF_STOLEN; /* NF_DROP */
}

static __be32 __get_dev_addr_by_name(const char* dev_name){

	/* initialize local ip table */
	/* net/ipv4/devinet.c :: int devinet_ioctl */
	
	struct in_device* in_dev;
	struct in_ifaddr** ifap = NULL;
	struct in_ifaddr* ifa = NULL;
	struct net_device* dev;
  
  	__be32 dev_ip = 0;

  	rtnl_lock();
  	dev = dev_get_by_name(&init_net, dev_name);
  	if (!dev)
  		goto done;

  	/* __in_dev_get_rtnl */
  	in_dev = rtnl_dereference(dev->ip_ptr);
  	if (!in_dev)
  		goto done;
  	
  	ifap = &in_dev->ifa_list;

  	for (ifap = &in_dev->ifa_list; (ifa = *ifap)!=NULL; ifap=&ifa->ifa_next) {
  		if(!(strcmp(ifa->ifa_label, dev_name))) {
  			printk("[SEK] ifa->ifa_address=0x%x\n",ifa->ifa_address);	
  			dev_ip = ifa->ifa_address;
			break;
  		}
  	}

  	done:
  	rtnl_unlock();
  	return dev_ip;	
}

/* initialize */
void __init_current_machine_ip(void){
	
	/* get localhost address */
	sekret_current_machine_ip[0] = __get_dev_addr_by_name("lo");
	sekret_current_machine_ip[1] = __get_dev_addr_by_name("eth0");

	printk(KERN_INFO "[SEK] local ip's: [0]: 0x%x [1]:0x%x\n",
		sekret_current_machine_ip[0], sekret_current_machine_ip[1]);

}

static int __init sek_main(void){
	__init_current_machine_ip();

	printk(KERN_ALERT "Target Sekret IP is :0x%x\n", target_ip);

#ifdef NO_TEST_O
	/* register incoming traffic hook */
	printk (KERN_ALERT "[SEK] Starting Sekret Tunnel Rx hook \n");
	rx_nfho.hook 		= rx_hook_func;
	rx_nfho.hooknum		= NF_INET_LOCAL_IN; /* NF_INET_PRE_ROUTING */
	rx_nfho.pf 			= PF_INET;
	rx_nfho.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&rx_nfho);
#endif

 	/* register outgoing traffic hook */
	printk (KERN_ALERT "[SEK] Starting Sekret Tunnel Tx hook \n");
	tx_nfho.hook 		= tx_hook_func;
	tx_nfho.hooknum		= NF_INET_LOCAL_OUT; 
	tx_nfho.pf 			= PF_INET;
	tx_nfho.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&tx_nfho);

	return 0;
}

static void __exit sek_exit(void){
	printk (KERN_ALERT "[SEK] Stopping Sekret Tunnel RX/TX \n");
	//nf_unregister_hook(&rx_nfho);
	nf_unregister_hook(&tx_nfho);

}

module_init(sek_main);
module_exit(sek_exit);

MODULE_LICENSE("LGPL v2.1");
