/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    if (sr->enable_nat)
    {
        sr_nat_init(&(sr->nat));
    }
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    assert(sr);
    assert(packet);
    assert(interface);

    Debug("*** -> Received packet of length %d\n", len);

    /* Verify minimum size of ethernet packet */
    if (len < sizeof(sr_ethernet_hdr_t))
    {
        return;
    }

    switch (ethertype(packet))
    {
        /* ARP packet */
        case ethertype_arp:
        {
            handle_arp(sr, packet, len, interface);
            break;
        }

        /* IP packet */
        case ethertype_ip:
        {
            handle_ip(sr, packet, len, interface);
            break;
        }
    }
}

/* Custom: handles ARP packet */
void handle_arp(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    Debug("ARP: received packet\n");

    /* The actual contents of the packet */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Ensure we have an ethernet packet */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet)
    {
        Debug("ARP: not an ethernet frame\n");
        return;
    }

    /* Ensure we have an IP packet */
    if (ntohs(arp_hdr->ar_pro) != ethertype_ip)
    {
        Debug("ARP: not an IP packet\n");
        return;
    }

    /* Check if destined for one of the router's interfaces */
    struct sr_if *dest = sr_get_interface_ip(sr, arp_hdr->ar_tip);
    if (!dest)
    {
        Debug("ARP: not destined for router\n");
        return;
    }

    switch (ntohs(arp_hdr->ar_op))
    {
        case arp_op_request:
        {
            /* ARP request: reply back */
            Debug("ARP: received request\n");

            /* Interface that we received the packet from */
            struct sr_if *intf = sr_get_interface(sr, interface);

            /* Create copy of the request */
            uint8_t *arpres = malloc(len);
            memcpy(arpres, packet, len);

            /* Update ethernet header */
            sr_ethernet_hdr_t *arpres_eth_hdr = (sr_ethernet_hdr_t *)arpres;
            /* Reply dest MAC address is request source MAC address */
            memcpy(arpres_eth_hdr->ether_dhost, arpres_eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(arpres_eth_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN);

            /* Update ARP header */
            sr_arp_hdr_t *arpres_arp_hdr = (sr_arp_hdr_t *)(arpres + sizeof(sr_ethernet_hdr_t));
            arpres_arp_hdr->ar_op = htons(arp_op_reply);                     /* Reply operation */
            memcpy(arpres_arp_hdr->ar_sha, intf->addr, ETHER_ADDR_LEN);      /* Source MAC address */
            arpres_arp_hdr->ar_sip = intf->ip;                               /* Source IP address */
            memcpy(arpres_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); /* Target MAC address */
            arpres_arp_hdr->ar_tip = arp_hdr->ar_sip;                        /* Target IP address */

            send_packet(sr, arpres, len, intf, arp_hdr->ar_sip);
            free(arpres);

            break;
        }

        case arp_op_reply:
        {
            /* ARP reply: cache it */
            Debug("ARP: received reply\n");

            struct sr_arpreq *cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Send outstanding ARP packets */
            if (cached)
            {
                struct sr_packet *packet = cached->packets;

                struct sr_if *packet_intf = NULL;
                sr_ethernet_hdr_t *eth_hdr = NULL;

                while (packet)
                {
                    packet_intf = sr_get_interface(sr, packet->iface);

                    if (packet_intf)
                    {
                        /* Set src/dest MAC addresses */
                        eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, packet_intf->addr, ETHER_ADDR_LEN);

                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    }

                    packet = packet->next;
                }

                sr_arpreq_destroy(&sr->cache, cached);
            }

            break;
        }
    }
}

/* Custom: handles IP packet (ICMP, TCP, UDP) */
void handle_ip(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    Debug("IP: received packet\n");

    /* The actual contents of the packet */
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)payload;

    /* Drop packet if it's invalid */
    if (verify_ip(ip_hdr) == -1)
    {
        return;
    }

    /* Handle NAT */
    if (sr->enable_nat)
    {
        handle_ip_nat(sr, packet, len, interface);
        return;
    }

    /* Check if destined for one of the router's interfaces */
    struct sr_if *dest = sr_get_interface_ip(sr, ip_hdr->ip_dst);
    if (dest)
    {
        Debug("IP: destined for router\n");

        /* Destined for router: handle contained packet */
        switch (ip_hdr->ip_p)
        {
            /* ICMP messages */
            case ip_protocol_icmp:
            {
                Debug("IP: ICMP message\n");

                /* Verify ICMP header */
                if (verify_icmp(packet, len) == -1)
                {
                    return;
                }

                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Handle "echo request" */
                if (icmp_hdr->icmp_type == icmp_type_echo_request)
                {
                    send_icmp_msg(sr, packet, len, icmp_type_echo_reply, (uint8_t)0);
                }

                break;
            }

            /* TCP/UDP: drop packet and send "destination unreachable" ICMP */
            case ip_protocol_tcp:
            case ip_protocol_udp:
            {
                Debug("IP: TCP/UDP message\n");
                send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                break;
            }
        }
    }
    else
    {
        /* Forward the packet to its actual destination */
        Debug("IP: destined elsewhere\n");

        forward_ip(sr, packet, len);
    }
}

/* Custom: handles IP packet with NAT functionality */
void handle_ip_nat(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    Debug("IP NAT: enabled\n");

    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)payload;

    /* Check if destined for one of the router's interfaces */
    struct sr_if *dest = sr_get_interface_ip(sr, ip_hdr->ip_dst);

    struct sr_nat_mapping *mapping = NULL;

    if (strncmp(interface, NAT_INT_INTF, sr_IFACE_NAMELEN) == 0)
    {
        /* Internal -> external */
        Debug("IP NAT: internal interface\n");

        if (dest)
        {
            send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
        }
        else
        {
            /* Outbound message */
            Debug("IP NAT internal: outbound message\n");

            struct sr_if *ext_intf = sr_get_interface(sr, "eth2");

            switch (ip_hdr->ip_p)
            {
                case ip_protocol_icmp:
                {
                    Debug("IP NAT internal: ICMP message\n");

                    /* Verify ICMP header */
                    if (verify_icmp(packet, len) == -1)
                    {
                        return;
                    }

                    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Find NAT mapping based on ICMP id */
                    mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                    if (!mapping)
                    {
                        mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                        mapping->ip_ext = ext_intf->ip;
                        mapping->last_updated = time(NULL);
                    }

                    /* Update ICMP header with mapping's ID */
                    icmp_hdr->icmp_id = mapping->aux_ext;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                    break;
                }

                case ip_protocol_tcp:
                {
                    Debug("IP NAT internal: TCP message\n");

                    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Verify TCP header */
                    if (verify_tcp(packet, len) == -1)
                    {
                        return;
                    }

                    /* Find NAT mapping based on TCP source port */
                    mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
                    if (!mapping)
                    {
                        mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->src_port), nat_mapping_tcp);
                        mapping->ip_ext = ext_intf->ip;
                        mapping->last_updated = time(NULL);
                    }

                    pthread_mutex_lock(&(sr->nat.lock));

                    struct sr_nat_connection *conn = sr_nat_get_conn(mapping, ip_hdr->ip_dst);
                    if (!conn)
                    {
                        conn = sr_nat_add_conn(mapping, ip_hdr->ip_dst);
                    }

                    switch (conn->state)
                    {
                        case tcp_state_established:
                        {
                            /* ESTAB -> CLOSED (ACK of FIN) */
                            if (tcp_hdr->fin && tcp_hdr->ack)
                            {
                                conn->client_seq_num = ntohl(tcp_hdr->seq_num);
                                conn->state = tcp_state_closed;
                            }
                            break;
                        }

                        case tcp_state_closed:
                        {
                            /* CLOSED -> SYN_SENT */
                            if (!tcp_hdr->ack && tcp_hdr->syn && ntohl(tcp_hdr->ack_num) == 0)
                            {
                                conn->client_seq_num = ntohl(tcp_hdr->seq_num);
                                conn->state = tcp_state_syn_sent;
                            }
                            break;
                        }

                        case tcp_state_syn_received:
                        {
                            /* SYN_RCVD -> ESTAB (ACK of SYN) */
                            if (!tcp_hdr->syn && ntohl(tcp_hdr->seq_num) == conn->client_seq_num + 1 && ntohl(tcp_hdr->ack_num) == conn->server_seq_num + 1)
                            {
                                conn->client_seq_num = ntohl(tcp_hdr->seq_num);
                                conn->state = tcp_state_established;
                            }

                            add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);
                            break;
                        }

                        default:
                        {
                            break;
                        }
                    }

                    pthread_mutex_unlock(&(sr->nat.lock));

                    /* Update TCP header with mapping's external port */
                    tcp_hdr->src_port = htons(mapping->aux_ext);

                    tcp_hdr->tcp_sum = 0;
                    tcp_hdr->tcp_sum = tcp_cksum(packet, len);

                    break;
                }
            }

            /* Update IP header's source with NAT's external IP */
            ip_hdr->ip_src = ext_intf->ip;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        }
    }
    else if (strncmp(interface, NAT_EXT_INTF, sr_IFACE_NAMELEN) == 0)
    {
        /* External -> internal */
        Debug("IP NAT external: external interface\n");

        if (dest)
        {
            /* Inbound message */
            Debug("IP NAT external: inbound message\n");

            switch (ip_hdr->ip_p)
            {
                case ip_protocol_icmp:
                {
                    Debug("IP NAT external: ICMP message\n");

                    /* Verify ICMP header */
                    if (verify_icmp(packet, len) == -1)
                    {
                        return;
                    }

                    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Find NAT mapping based on ICMP id */
                    mapping = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);
                    if (!mapping)
                    {
                        Debug("IP NAT external: can't find ICMP mapping, dropping\n");
                        return;
                    }

                    /* Update ICMP header with mapping's internal ID */
                    icmp_hdr->icmp_id = mapping->aux_int;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                    break;
                }

                case ip_protocol_tcp:
                {
                    Debug("IP NAT external: TCP message\n");

                    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                    /* Verify TCP header */
                    if (verify_tcp(packet, len) == -1)
                    {
                        return;
                    }

                    /* Restricted ports */
                    if (ntohs(tcp_hdr->dst_port) < MIN_NAT_PORT)
                    {
                        Debug("IP NAT external: restricted TCP port, dropping\n");
                        send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                        return;
                    }

                    /* Find NAT mapping based on TCP destination port */
                    mapping = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->dst_port), nat_mapping_tcp);
                    if (!mapping)
                    {
                        /* Add new SYN if it's a valid route */
                        if (tcp_hdr->syn)
                        {
                            struct sr_rt *rt = (struct sr_rt *)longest_matching_prefix(sr, ip_hdr->ip_dst);
                            if (rt)
                            {
                                add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->dst_port, packet, len);
                            }
                        }

                        Debug("IP NAT external: can't find TCP mapping, dropping\n");
                        return;
                    }

                    pthread_mutex_lock(&(sr->nat.lock));

                    struct sr_nat_connection *conn = sr_nat_get_conn(mapping, ip_hdr->ip_src);
                    if (!conn)
                    {
                        conn = sr_nat_add_conn(mapping, ip_hdr->ip_src);
                    }

                    switch (conn->state)
                    {
                        case tcp_state_syn_sent:
                        {
                            /* SYN_SENT -> SYN_RECV */
                            if (tcp_hdr->syn)
                            {
                                if (tcp_hdr->ack && ntohl(tcp_hdr->ack_num) == conn->client_seq_num + 1)
                                {
                                    /* Simultaneous open */
                                    conn->server_seq_num = ntohl(tcp_hdr->seq_num);
                                    conn->state = tcp_state_syn_received;
                                }
                                else if (!tcp_hdr->ack && ntohl(tcp_hdr->ack_num) == 0)
                                {
                                    /* SYN + initial seq num of 0 */
                                    conn->server_seq_num = ntohl(tcp_hdr->seq_num);
                                    conn->state = tcp_state_syn_received;
                                }

                                add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);
                            }
                            break;
                        }

                        case tcp_state_syn_received:
                        {
                            add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);
                            break;
                        }

                        default:
                        {
                            break;
                        }
                    }

                    pthread_mutex_unlock(&(sr->nat.lock));

                    /* Update TCP header's destination port with mapping's internal port */
                    tcp_hdr->dst_port = htons(mapping->aux_int);

                    tcp_hdr->tcp_sum = 0;
                    tcp_hdr->tcp_sum = tcp_cksum(packet, len);

                    break;
                }
            }
        }
        else
        {
            Debug("IP NAT external: not destined for router, dropping\n");
            return;
        }

        /* Update IP header destination with mapping's internal IP */
        ip_hdr->ip_dst = mapping->ip_int;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    }

    /* Send packet if we did stuff before */
    if (mapping)
    {
        forward_ip(sr, packet, len);

        free(mapping);
        return;
    }
}

/* Custom method: sends out a packet (or queues the ARP request) */
void send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, uint32_t dest_ip)
{
    /* Check if in ARP cache (using IP address) */
    struct sr_arpentry *cached = sr_arpcache_lookup(&sr->cache, dest_ip);

    if (cached)
    {
        /* Send out packet using cached ARP info */
        Debug("send_packet: Using cached ARP\n");

        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); /* Source: MAC address from the interface that sent it */
        memcpy(eth_hdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);     /* Dest: MAC address from ARP cache entry */

        sr_send_packet(sr, packet, len, interface->name);
        free(cached);
    }
    else
    {
        /* Queue ARP request */
        Debug("send_packet: Queue ARP request\n");

        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
        handle_arpreq(sr, req);
    }
}

/* Custom: decrements IP header TTL and attempts to send it */
void forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Decrement TTL */
    ip_hdr->ip_ttl--;

    /* Send "Time exceeded" ICMP message if the TTL causes the packet to be dropped */
    if (ip_hdr->ip_ttl == 0)
    {
        Debug("IP: TTL decremented to 0 (sending ICMP time exceeded)\n");
        send_icmp_msg(sr, packet, len, icmp_type_time_exceeded, (uint8_t)0);
        return;
    }

    /* Recompute IP header checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

    /* Look up in routing table with longest matching prefix */
    struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_dst);
    if (!route)
    {
        Debug("No route found (sending ICMP net unreachable)\n");
        send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
        return;
    }

    struct sr_if *route_intf = sr_get_interface(sr, route->interface);
    if (!route_intf)
    {
        Debug("No interface found with name \"%s\"", route->interface);
        return;
    }

    send_packet(sr, packet, len, route_intf, route->gw.s_addr);
}

/* Custom: sends an ICMP message */
void send_icmp_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get longest matching prefix for source */
    struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_src);
    if (!route)
    {
        Debug("send_icmp_msg_addr: Routing table entry not found\n");
        return;
    }

    /* Get the sending interface */
    struct sr_if *sending_intf = sr_get_interface(sr, route->interface);

    switch (type)
    {
        /* Regular ICMP */
        case icmp_type_echo_reply:
        {
            /* Update Ethernet Header source host/destination host */
            memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

            /* Swap IP header source/destination */
            uint32_t old_ip_src = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = old_ip_src;

            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            /* Create ICMP header */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;

            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

            send_packet(sr, packet, len, sending_intf, route->gw.s_addr);
            break;
        }

        /* Type 3 or Type 11 ICMP */
        case icmp_type_time_exceeded:
        case icmp_type_dest_unreachable:
        {
            /* Calculate new packet length */
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *new_packet = malloc(new_len);

            /* Sanity Check */
            assert(new_packet);

            /* Need to construct new headers for type 3 */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
            sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

            /* Init ethernet header */
            memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
            new_eth_hdr->ether_type = htons(ethertype_ip);

            /* Init IP header */
            new_ip_hdr->ip_v = 4;
            new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; /* ip_hl is in words */
            new_ip_hdr->ip_tos = 0;
            new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id = htons(0);
            new_ip_hdr->ip_off = htons(IP_DF);
            new_ip_hdr->ip_ttl = 255;
            new_ip_hdr->ip_p = ip_protocol_icmp;

            struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_src);
            if (!route)
            {
                Debug("send_icmp_msg: Routing table entry not found\n");
                return;
            }

            new_ip_hdr->ip_src = code == icmp_dest_unreachable_port ? ip_hdr->ip_dst : sending_intf->ip;
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            /* Init ICMP header */
            new_icmp_hdr->icmp_type = type;
            new_icmp_hdr->icmp_code = code;
            new_icmp_hdr->unused = 0;
            new_icmp_hdr->next_mtu = 0; /* May need additional code here to handle code 4 */
            memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            new_icmp_hdr->icmp_sum = 0;
            new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, sending_intf, route->gw.s_addr);
            free(new_packet);
            break;
        }
    }
}
