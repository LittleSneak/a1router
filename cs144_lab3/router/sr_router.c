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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
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
    
    /* Add initialization code here! */

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
  /*Perform minimum packet length checks*/
  /*and identify packet type*/
  /*Structures for handling ICMP replies*/
  uint8_t *reply = NULL;
  sr_ethernet_hdr_t *retEhdr = NULL;
  sr_ip_hdr_t *retIPhdr = NULL;
  sr_icmp_hdr_t *retICMPhdr = NULL;
  sr_arp_hdr_t *retARPhdr = NULL;
  
  int type = 0;
  int located = 0;
  struct sr_rt* rt_walker = NULL;
  struct sr_if* if_walker = NULL;
  
  /*Structures for holding headers in the packet*/
  sr_ethernet_hdr_t *ehdr = NULL;
  sr_ip_hdr_t *iphdr = NULL;
  sr_icmp_hdr_t *icmp_hdr = NULL;
  sr_arp_hdr_t *arp_hdr = NULL;
  struct sr_arpentry* arpentry = NULL;
  
  int minlength = sizeof(sr_ethernet_hdr_t);
  if(len < minlength){
	  return;
  }
  /*Obtain ethernet header*/
  else{
	  ehdr = (sr_ethernet_hdr_t *)packet;
  }
  uint16_t ethtype = ethertype(packet);
  /*Found an IP header after the ethernet header*/
  if (ethtype == ethertype_ip) {
	  minlength = minlength + sizeof(sr_ip_hdr_t);
	  if(len < minlength){
		  return;
	  }
	  else{
		  /*Check if it is an ICMP packet*/
		  uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
		  if (ip_proto == ip_protocol_icmp) {
		      minlength = minlength + sizeof(sr_icmp_hdr_t);
			  if(len < minlength){
				  return;
			  }
			  type = 1;
		  }
		  else{
			  type = 0;
		  }
	  }
  }
  /*ARP packet*/
  else if(ethtype == ethertype_arp){
	  minlength = minlength + sizeof(sr_arp_hdr_t);
	  if(len < minlength){
		  return;
	  }
	  type = 2;
  }
  
  /*Handle IP packet or an ICMP packet*/
  if(type == 0 || type == 1){
	  /*Obtain ip header*/
	  iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	  /*Check the checksum*/
	  if(cksum(iphdr, sizeof(sr_ip_hdr_t)) != 0){
		  return;
	  }
	  /*Check if packet is meant for the router*/
	  int found = 0;
	  while (if_walker){
		  if(if_walker->ip == iphdr->ip_dst){
			  found = 1;
	      }
	  }
	  /*Check if the message is an echo request*/
	  if(type == 1 && found == 1){
		  icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		  if(cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)) != 0){
			  return;
		  }
		  /*Handle echo requests*/
		  if(icmp_hdr->icmp_type == 8 && found == 1){
			  printf("here\n");
	          print_hdrs(packet, len);
			  uint8_t *reply = malloc(len);
			  memcpy(reply, packet, len);
			  retEhdr = (sr_ethernet_hdr_t *)reply;
			  retIPhdr = (sr_ip_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t));
			  retICMPhdr = (sr_icmp_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			  /*Change the appropriate variables in the ethernet header*/
			  memcpy(retEhdr->ether_dhost, ehdr->ether_shost, sizeof(retEhdr->ether_shost));
			  memcpy(retEhdr->ether_shost, ehdr->ether_dhost, sizeof(retEhdr->ether_shost));
			  
			  /*Change values in IP header*/
			  retIPhdr->ip_sum = 0;
			  retIPhdr->ip_ttl = 64;
			  retIPhdr->ip_src = iphdr->ip_dst;
			  retIPhdr->ip_dst = iphdr->ip_src;
			  retIPhdr->ip_sum = cksum(retIPhdr, sizeof(sr_ip_hdr_t));
			  
			  /*Change values in ICMP*/
			  retICMPhdr->icmp_type = 0;
			  retICMPhdr->icmp_sum = 0;
			  retICMPhdr->icmp_sum = cksum(retICMPhdr, sizeof(sr_icmp_hdr_t));
			  
			  /*Find interface*/
			  rt_walker = sr->routing_table;
			  while(rt_walker){
				  if(rt_walker->dest.s_addr == retIPhdr->ip_dst){
					  break;
				  }
				  rt_walker = rt_walker->next;
			  }
			  
			  /*Send the echo reply*/
			  sr_send_packet(sr /* borrowed */,
                         reply /* borrowed */ ,
                         len,
                         rt_walker->interface);
			  free(reply);
			  return;
		  }
	  }
	  /*Packet is meant for router and is not an ICMP*/
	  else if (found == 1){
		  /*Return ICMP destination not reachable*/
	  }
	  
	  iphdr->ip_ttl = iphdr->ip_ttl - 1;
	  if(iphdr->ip_ttl == 0){
		  /*Return ICMP time out*/
		  return;
	  }
	  
	  /*obtain new checksum*/
	  iphdr->ip_sum = 0;
	  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
	  
	  /*Check if the destination is one of the interfaces*/
	  if_walker = sr->if_list;
	  while(if_walker){
		  if(if_walker->ip == iphdr->ip_dst){
			  /*Return ICMP unreachable*/
			  return;
		  }
		  if_walker = if_walker->next;
	  }
	  /*Find the longest prefix match*/
	  rt_walker = sr->routing_table;
	  while(rt_walker){
		  if(rt_walker->dest.s_addr == iphdr->ip_dst){
			  break;
		  }
	  }
	  /*Found a destination*/
	  if(!rt_walker){
		  /*Check arp cache*/
		  arpentry = sr_arpcache_lookup(&(sr->cache), rt_walker->dest.s_addr);
		  if(arpentry != NULL){
			  ehdr->ether_dhost[0] = arpentry->mac[0];
			  ehdr->ether_dhost[1] = arpentry->mac[1];
			  ehdr->ether_dhost[2] = arpentry->mac[2];
			  ehdr->ether_dhost[3] = arpentry->mac[3];
			  ehdr->ether_dhost[4] = arpentry->mac[4];
			  ehdr->ether_dhost[5] = arpentry->mac[5];
			  sr_send_packet(sr, packet, len, rt_walker->interface);
			  free(arpentry);
			  return;
		  }
		  /*Not in cache, send ARP requests*/
		  else{
			  sr_arpcache_queuereq(&(sr->cache),
                                       rt_walker->dest.s_addr,
                                       packet,
                                       len,
                                       rt_walker->interface);
		  }
		  return;
	  }
	  else{
		  /*return icmp unreachable*/
	  }
  }
  
  
  /*Handle ARP packet*/
  if(type == 2){
	  print_hdrs(packet, len);
	  /*Obtain ARP header*/
	  arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	  /*Handle arp request*/
	  if(ntohs(arp_hdr->ar_op) == 1){
		  /*check if the request is for this router*/
		  if_walker = sr->if_list;
		  located = 0;
		  while(if_walker){
			  if(if_walker->ip == arp_hdr->ar_tip){
				  located = 1;
				  break;
			  }
			  if_walker = if_walker->next;
		  }
		  /*Request is for this router, send a reply*/
		  if(located == 1){
			  reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
			  retEhdr = (sr_ethernet_hdr_t *) reply;
			  retARPhdr = (sr_arp_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t));
			  /*Setup ethernet header*/
			  memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
			  memcpy(retEhdr->ether_dhost, ehdr->ether_shost, sizeof(uint8_t) * 6);
			  retEhdr->ether_type = htons(ethertype_arp);
			  /*Setup ARP header*/
			  memcpy(retARPhdr, arp_hdr, sizeof(sr_arp_hdr_t));
			  memcpy(retARPhdr->ar_sha, if_walker->addr, sizeof(uint8_t) * 6);
			  memcpy(retARPhdr->ar_tha, ehdr->ether_shost, sizeof(uint8_t) * 6);
			  retARPhdr->ar_sip = if_walker->ip;
			  retARPhdr->ar_tip = arp_hdr->ar_sip;
			  retARPhdr->ar_op = htons(arp_op_reply);
			  
			  /*Find interface*/
			  rt_walker = sr->routing_table;
			  while(rt_walker){
				  if(rt_walker->dest.s_addr == retARPhdr->ar_tip){
					  break;
				  }
				  rt_walker = rt_walker->next;
			  }
			  /*Send the packet*/
			  sr_send_packet(sr /* borrowed */,
                         reply /* borrowed */ ,
                         sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
                         rt_walker->interface);
			  return;
		  }
		  
		  /*destination is not for this router, forward the packet*/
		  else{
			  rt_walker = sr->routing_table;
			  while(rt_walker){
				  if(rt_walker->dest.s_addr == retARPhdr->ar_tip){
					  break;
				  }
				  rt_walker = rt_walker->next;
			  }
			  if(!rt_walker){
		          /*Check arp cache*/
		          arpentry = sr_arpcache_lookup(&(sr->cache), rt_walker->dest.s_addr);
				  /*In cache, send the packet*/
		          if(arpentry != NULL){
			          ehdr->ether_dhost[0] = arpentry->mac[0];
			          ehdr->ether_dhost[1] = arpentry->mac[1];
			          ehdr->ether_dhost[2] = arpentry->mac[2];
		    	      ehdr->ether_dhost[3] = arpentry->mac[3];
			          ehdr->ether_dhost[4] = arpentry->mac[4];
			          ehdr->ether_dhost[5] = arpentry->mac[5];
			          sr_send_packet(sr, packet, len, rt_walker->interface);
			          free(arpentry);
			          return;
		          }
		          /*Not in cache, send ARP requests*/
		          else{
			          sr_arpcache_queuereq(&(sr->cache),
                                           rt_walker->dest.s_addr,
                                           packet,
                                           len,
                                           rt_walker->interface);
		          }
		          return;
	          }
	          else{
		          /*return icmp unreachable*/
	          }
		  }
	  }
	  
	  
	  
	  /*arp packet is a reply*/
	  else{
		  /*check if the reply is for this router*/
		  if_walker = sr->if_list;
		  located = 0;
		  while(if_walker){
			  if(if_walker->ip == arp_hdr->ar_tip){
				  located = 1;
				  break;
			  }
			  if_walker = if_walker->next;
		  }
		  /*Find the interface for this IP address*/
		  rt_walker = sr->routing_table;
	      while(rt_walker){
		      if(rt_walker->dest.s_addr == arp_hdr->ar_tip){
			      break;
		      }
		      rt_walker = rt_walker->next;
	      }
		  /*Reply is for this router, cache the reply*/
		  if(located == 1){
			  struct sr_arpreq *requests =  sr_arpcache_insert(&(sr->cache),
                                         arp_hdr->ar_sha,
                                         arp_hdr->ar_sip);
			  struct sr_packet *req_walker = requests->packets;
			  /*Go through all the queued packets and send them*/
			  while(req_walker){
				  ehdr = (sr_ethernet_hdr_t *) req_walker->buf;
				  memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, sizeof(ehdr->ether_dhost));
				  sr_send_packet(sr /* borrowed */,
                         req_walker->buf /* borrowed */ ,
                         req_walker->len,
                         rt_walker->interface /* borrowed */);
				  req_walker = req_walker->next;
			  }
			  /*Free all requests related to this reply*/
			  sr_arpreq_destroy(&(sr->cache), requests);
		  }
	  }
  }

}/* end sr_ForwardPacket */

