#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"

uint16_t cksum(const void *_data, int len)
{
    const uint8_t *data = _data;
    uint32_t sum;

    for (sum = 0; len >= 2; data += 2, len -= 2)
        sum += data[0] << 8 | data[1];
    if (len > 0)
        sum += data[0] << 8;
    while (sum > 0xffff)
        sum = (sum >> 16) + (sum & 0xffff);
    sum = htons(~sum);
    return sum ? sum : 0xffff;
}

/* Custom: compute checksum for TCP header with psuedo-header (assumes tcp_sum was previously 0'ed) */
uint16_t tcp_cksum(void *packet, unsigned int len)
{
    int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    int pseudo_len = sizeof(sr_tcp_pseudo_hdr_t) + tcp_len;

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Create pseudo-header (pseudo-header + original TCP headers) */
    sr_tcp_pseudo_hdr_t *pseudo = (sr_tcp_pseudo_hdr_t *)malloc(sizeof(sr_tcp_pseudo_hdr_t) + tcp_len);
    pseudo->ip_src = ip_hdr->ip_src;
    pseudo->ip_dst = ip_hdr->ip_dst;
    pseudo->reserved = 0;
    pseudo->ip_p = ip_protocol_tcp;
    pseudo->tcp_len = htons(tcp_len);
    memcpy((uint8_t *)pseudo + sizeof(sr_tcp_pseudo_hdr_t), (uint8_t *)tcp_hdr, tcp_len);

    /* Compute checksum */
    uint16_t new_cksum = cksum(pseudo, pseudo_len);

    free(pseudo);
    return new_cksum;
}

/* Custom method: verify IP packet headers */
int verify_ip(sr_ip_hdr_t *ip_hdr)
{
    /* Verify checksum of header */
    uint16_t old_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t new_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    ip_hdr->ip_sum = old_cksum;
    if (old_cksum != new_cksum)
    {
        Debug("IP: checksum didn't match\n");
        return -1;
    }

    /* Verify packet meets minimum length */
    if (ip_hdr->ip_len < 20)
    {
        Debug("IP: header length too short\n");
        return -1;
    }

    return 0;
}

/* Custom method: verify ICMP headers */
int verify_icmp(uint8_t *packet, unsigned int len)
{
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)payload;

    /* Verify that header length is valid */
    if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t))
    {
        Debug("ICMP: insufficient header length\n");
        return -1;
    }

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Verify that the ICMP checksum matches */
    uint16_t old_cksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t new_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
    icmp_hdr->icmp_sum = old_cksum;
    if (old_cksum != new_cksum)
    {
        Debug("ICMP: checksum didn't match\n");
        return -1;
    }

    return 0;
}

/* Custom method: verify TCP headers */
int verify_tcp(uint8_t *packet, unsigned int len)
{
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)payload;

    /* Verify that the TCP checksum matches */
    uint16_t old_cksum = tcp_hdr->tcp_sum;
    tcp_hdr->tcp_sum = 0;
    uint16_t new_cksum = tcp_cksum(packet, len);
    tcp_hdr->tcp_sum = old_cksum;
    if (old_cksum != new_cksum)
    {
        Debug("TCP: checksum didn't match\n");
        return -1;
    }

    /* Minimum size */
    if (tcp_hdr->offset < 5)
    {
        Debug("TCP: insufficient header length\n");
        return -1;
    }

    return 0;
}

uint16_t ethertype(uint8_t *buf)
{
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf);
    return ip_hdr->ip_p;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr)
{
    int pos = 0;
    uint8_t cur;
    for (; pos < ETHER_ADDR_LEN; pos++)
    {
        cur = addr[pos];
        if (pos > 0)
            fprintf(stderr, ":");
        fprintf(stderr, "%02X", cur);
    }
    fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address)
{
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
        fprintf(stderr, "inet_ntop error on address conversion\n");
    else
        fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip)
{
    uint32_t curOctet = ip >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 8) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 16) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 24) >> 24;
    fprintf(stderr, "%d\n", curOctet);
}

void addr_ip_int(char *buf, uint32_t ip)
{
    sprintf(
        buf,
        "%d.%d.%d.%d",
        ip >> 24,
        (ip << 8) >> 24,
        (ip << 16) >> 24,
        (ip << 24) >> 24);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf)
{
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    fprintf(stderr, "ETHERNET header:\n");
    fprintf(stderr, "\tdestination: ");
    print_addr_eth(ehdr->ether_dhost);
    fprintf(stderr, "\tsource: ");
    print_addr_eth(ehdr->ether_shost);
    fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in TCP header */
void print_hdr_tcp(uint8_t *buf)
{
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)buf;
    fprintf(stderr, "TCP header\n");
    fprintf(stderr, "\tsource port: %d\n", ntohs(tcp_hdr->src_port));
    fprintf(stderr, "\tdestination port: %d\n", ntohs(tcp_hdr->dst_port));
    fprintf(stderr, "\tsequence number: %d\n", ntohl(tcp_hdr->seq_num));
    fprintf(stderr, "\tacknowledgement number: %d\n", ntohl(tcp_hdr->ack_num));
    fprintf(stderr, "\toffset: %d\n", ntohl(tcp_hdr->offset));

    fprintf(stderr, "\tCWR: %d\n", tcp_hdr->cwr);
    fprintf(stderr, "\tECE: %d\n", tcp_hdr->ece);
    fprintf(stderr, "\tURG: %d\n", tcp_hdr->urg);
    fprintf(stderr, "\tACK: %d\n", tcp_hdr->ack);
    fprintf(stderr, "\tPSH: %d\n", tcp_hdr->psh);
    fprintf(stderr, "\tRST: %d\n", tcp_hdr->rst);
    fprintf(stderr, "\tSYN: %d\n", tcp_hdr->syn);
    fprintf(stderr, "\tFIN: %d\n", tcp_hdr->fin);

    fprintf(stderr, "\twindow size: %d\n", tcp_hdr->window_size);
    fprintf(stderr, "\tchecksum: %d\n", tcp_hdr->tcp_sum);
    fprintf(stderr, "\turgent pointer: %d\n", tcp_hdr->urgent_ptr);
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf);
    fprintf(stderr, "IP header:\n");
    fprintf(stderr, "\tversion: %d\n", ip_hdr->ip_v);
    fprintf(stderr, "\theader length: %d\n", ip_hdr->ip_hl);
    fprintf(stderr, "\ttype of service: %d\n", ip_hdr->ip_tos);
    fprintf(stderr, "\tlength: %d\n", ntohs(ip_hdr->ip_len));
    fprintf(stderr, "\tid: %d\n", ntohs(ip_hdr->ip_id));

    if (ntohs(ip_hdr->ip_off) & IP_DF)
        fprintf(stderr, "\tfragment flag: DF\n");
    else if (ntohs(ip_hdr->ip_off) & IP_MF)
        fprintf(stderr, "\tfragment flag: MF\n");
    else if (ntohs(ip_hdr->ip_off) & IP_RF)
        fprintf(stderr, "\tfragment flag: R\n");

    fprintf(stderr, "\tfragment offset: %d\n", ntohs(ip_hdr->ip_off) & IP_OFFMASK);
    fprintf(stderr, "\tTTL: %d\n", ip_hdr->ip_ttl);
    fprintf(stderr, "\tprotocol: %d\n", ip_hdr->ip_p);

    /*Keep checksum in NBO*/
    fprintf(stderr, "\tchecksum: %d\n", ip_hdr->ip_sum);

    fprintf(stderr, "\tsource: ");
    print_addr_ip_int(ntohl(ip_hdr->ip_src));

    fprintf(stderr, "\tdestination: ");
    print_addr_ip_int(ntohl(ip_hdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf)
{
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
    fprintf(stderr, "ICMP header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
    /* Keep checksum in NBO */
    fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
    fprintf(stderr, "\tid: %d\n", icmp_hdr->icmp_id);
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf)
{
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
    fprintf(stderr, "ARP header\n");
    fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
    fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
    fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
    fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
    fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

    fprintf(stderr, "\tsender hardware address: ");
    print_addr_eth(arp_hdr->ar_sha);
    fprintf(stderr, "\tsender ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_sip));

    fprintf(stderr, "\ttarget hardware address: ");
    print_addr_eth(arp_hdr->ar_tha);
    fprintf(stderr, "\ttarget ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length)
{
    /* Ethernet */
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (length < minlength)
    {
        fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
        return;
    }

    uint16_t ethtype = ethertype(buf);
    print_hdr_eth(buf);

    if (ethtype == ethertype_ip)
    { /* IP */
        minlength += sizeof(sr_ip_hdr_t);
        if (length < minlength)
        {
            fprintf(stderr, "Failed to print IP header, insufficient length\n");
            return;
        }

        print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
        switch(ip_protocol(buf + sizeof(sr_ethernet_hdr_t)))
        {
        /* ICMP */
        case ip_protocol_icmp:
        {
            minlength += sizeof(sr_icmp_hdr_t);
            if (length < minlength)
                fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
            else
                print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            break;
        }

        /* TCP */
        case ip_protocol_tcp:
        {
            minlength += sizeof(sr_tcp_hdr_t);
            if (length < minlength)
                fprintf(stderr, "Failed to print TCP header, insufficient length\n");
            else
                print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            break;
        }
        }
    }
    else if (ethtype == ethertype_arp)
    { /* ARP */
        minlength += sizeof(sr_arp_hdr_t);
        if (length < minlength)
            fprintf(stderr, "Failed to print ARP header, insufficient length\n");
        else
            print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
    }
    else
    {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
}
