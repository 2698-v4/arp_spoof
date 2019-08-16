#include <stdint.h>
#include <sys/types.h>

#ifndef ARP_SPOOF
#define ARP_SPOOF

#define ETH_ALEN 6
#define ETH_TYPE_IPv4 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_HLEN 14

#define ARP_HLEN 28
#define ARP_HTYPE_ETH 0x1	// HW type for Ethernet is 1. 
#define ARP_PTYPE_IPV4 ETH_TYPE_IPv4	// 'Protocol Type' field shares EtherType values. 
#define ARP_HALEN ETH_ALEN
#define ARP_PALEN 4	// IPv4 Address is 4-bytes.
#define ARP_OPCODE_REQ 1	// 1 for request
#define ARP_OPCODE_REP 2	// 2 for reply

#define RTRSNMT 5           // how many times ARP reply will be re-transmitted
#define TTS 10000           // time to sleep in us

#define ANSI_COLOR_RED      "\x1b[31m"
#define ANSI_COLOR_GREEN    "\x1b[32m"
#define ANSI_COLOR_BLUE     "\x1b[34m"
#define ANSI_COLOR_RESET    "\x1b[0m"

struct eth_header {
    uint8_t mac_dest[6];
    uint8_t mac_src[6];
    uint16_t etherType; 
}__attribute__((packed));

struct arp_header {
	uint16_t hw_type;
	uint16_t pro_type;
	uint8_t halen;
	uint8_t palen;
	uint16_t opcode;	// reply or request
	uint8_t sender_hw[6];
	uint8_t sender_pr[4];
	uint8_t target_hw[6];
	uint8_t target_pr[4];
}__attribute__((packed));

void convert_ip(u_char*, uint8_t*);

void make_arp_req(unsigned char*, uint8_t*, uint8_t*);
void make_arp_rep(unsigned char*, uint8_t*, uint8_t*, uint8_t*, uint8_t*);

int is_arp_request(const u_char*, uint8_t*, uint8_t*);
int is_arp_reply(const u_char*, uint8_t*, uint8_t*);
int is_routing_needed(const u_char*, uint8_t*, uint8_t*);

void change_eth_hdr(unsigned char*, uint8_t*, uint8_t*);

void send_packet_mul(pcap_t*, const u_char*, uint32_t);

#endif // arp_spoof.h