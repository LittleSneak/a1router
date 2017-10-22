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
	  uint16_t sum = iphdr->ip_sum;
	  iphdr->ip_sum = 0;
	  if(cksum(iphdr, sizeof(sr_ip_hdr_t)) != sum){
		  printf("Checksum failed\n");
		  return;
	  }
	  else{
		  iphdr->ip_sum = sum;
	  }
	  /*Check if packet is meant for the router*/
	  int found = 0;
	  if_walker = sr->if_list;
	  print_hdrs(packet, len);
	  while (if_walker){
		  if(if_walker->ip == iphdr->ip_dst){
			  found = 1;
			  break;
	      }
		  if_walker = if_walker->next;
	  }
	  /*Check if the message is an echo request*/
	  if(type == 1 && found == 1){
		  icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		  
		  /* Checksum is not working...
		  sum = icmp_hdr->icmp_sum;
		  if(cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)) != sum){
			  printf("Checksum failed\n");
			  return;
		  }
		  else{
			  icmp_hdr->icmp_sum = sum;
		  }*/
		  /*Handle echo requests*/
		  if(icmp_hdr->icmp_type == 8 && found == 1){
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
		      retICMPhdr->icmp_code = 0;
			  retICMPhdr->icmp_sum = 0;
			  retICMPhdr->icmp_sum = cksum(retICMPhdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			  
			  /*Find interface*/
			  rt_walker = sr->routing_table;
			  while(rt_walker){
				  if(rt_walker->dest.s_addr == retIPhdr->ip_dst){
					  break;
				  }
				  rt_walker = rt_walker->next;
			  }
			  if(rt_walker == NULL){
				  return;
			  }
			  /* Check if address is in cache */
			  arpentry = sr_arpcache_lookup(&(sr->cache), retIPhdr->ip_dst);
		      /*Not cache queue the packet */
		      if(arpentry == NULL){
			      sr_arpcache_queuereq(&(sr->cache),
                                       iphdr->ip_src,
                                       reply,           /* borrowed */
                                       len,
                                       rt_walker->interface);
		      }
			  else{
				  /*Send the echo reply*/
			      sr_send_packet(sr /* borrowed */,
                         reply /* borrowed */ ,
                         len,
                         rt_walker->interface);
			  }
			  return;
		  }
	  }
	  /*Packet is meant for router and is not an ICMP*/
	  else if (iphdr->ip_p == 6 || iphdr->ip_p == 17){
		  printf("Not for this router\n");
		  send_icmp_type_3(3, len, packet, sr);
		  return;
	  }
	  
	  iphdr->ip_ttl = iphdr->ip_ttl - 1;
	  /* Send an ICMP time out back */
	  if(iphdr->ip_ttl == 0){
		  /*Return ICMP time out*/
		  reply = malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
		  retEhdr = (sr_ethernet_hdr_t *) reply;
		  retIPhdr = (sr_ip_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t));
		  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		  
		  /* Set up the ethernet header */
		  memcpy(retEhdr->ether_dhost, ehdr->ether_shost, sizeof(uint8_t) * 6);
		  memcpy(retEhdr->ether_shost, ehdr->ether_dhost, sizeof(uint8_t) * 6);
		  retEhdr->ether_type = ehdr->ether_type;
		  
		  /* Set up the IP header */
		  memcpy(retIPhdr, iphdr, sizeof(sr_ip_hdr_t));
		  retIPhdr->ip_ttl = 64;
		  retIPhdr->ip_sum = 0;
		  retIPhdr->ip_dst = iphdr->ip_src;
		  retIPhdr->ip_p = ip_protocol_icmp;
		  retIPhdr->ip_id = retIPhdr->ip_id + 1;
		  
		  /* Find the interface to send to */
		  if_walker = sr->if_list;
		  while(if_walker){
			  if(memcmp(if_walker->addr, ehdr->ether_dhost, sizeof(unsigned char) * 6) == 0){
				  break;
			  }
			  if_walker = if_walker->next;
		  }
		  if(if_walker == NULL){
			  return;
		  }
		  retIPhdr->ip_src = if_walker->ip;
		  retIPhdr->ip_sum = cksum(retIPhdr, sizeof(sr_ip_hdr_t));
		  
		  /* Set up ICMP header */
		  icmp_header->icmp_type = 11;
		  icmp_header->icmp_code = 0;
		  icmp_header->icmp_sum = 0;
		  icmp_header->unused = 0;
		  icmp_header->next_mtu = 0;
		  /* Determine how many bytes from the datagram's data should be read */
		  int bytes_to_read = 0;
		  if(len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) < ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t)){
			  bytes_to_read = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
		  }
		  else{
			  bytes_to_read = ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t);
		  }
		  /* Copy IP header and datagram's data into ICMP header */
		  memcpy(icmp_header->data, iphdr, sizeof(sr_ip_hdr_t) + bytes_to_read);
		  icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
		  
          sr_send_packet(sr /* borrowed */,
                         reply /* borrowed */ ,
                         sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t),
                         if_walker->name /* borrowed */);
		  free(reply);
		  return;
	  }
	  
	  /*obtain new checksum*/
	  iphdr->ip_sum = 0;
	  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
	  
	  /*Find the longest prefix match*/
	  rt_walker = sr->routing_table;
	  while(rt_walker){
		  if(rt_walker->dest.s_addr == iphdr->ip_dst){
			  break;
		  }
		  rt_walker = rt_walker->next;
	  }
	  /*Found a destination*/
	  if(rt_walker != NULL){
		  /*Check arp cache*/
		  arpentry = sr_arpcache_lookup(&(sr->cache), rt_walker->dest.s_addr);
		  if(arpentry != NULL){
			  memcpy(ehdr->ether_dhost, arpentry->mac, sizeof(uint8_t) * 6);
			  /* Find interface */
			  if_walker = sr->if_list;
			  while(if_walker){
				  if(strcmp(if_walker->name, rt_walker->interface) == 0){
					  break;
				  }
				  if_walker = if_walker->next;
			  }
			  if(if_walker == NULL){
				  return;
			  }
			  memcpy(ehdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
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
		  send_icmp_type_3(0, len, packet, sr);
	  }
  }
  
  
  /*Handle ARP packet*/
  if(type == 2){
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
			  free(reply);
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
					  memcpy(ehdr->ether_dhost, arpentry->mac, sizeof(uint8_t) * 6);
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
		          send_icmp_type_3(0, len, packet, sr);
	          }
		  }
	  }
	  
	  
	  
	  /*arp packet is a reply*/
	  else{
		  /*check if the reply is for this router*/
		  if_walker = sr->if_list;
		  while(if_walker){
			  if(if_walker->ip == arp_hdr->ar_tip){
				  break;
			  }
			  if_walker = if_walker->next;
		  }
		  /*Reply is for this router, cache the reply*/
		  if(if_walker != NULL){
			  struct sr_arpreq *requests =  sr_arpcache_insert(&(sr->cache),
                                         arp_hdr->ar_sha,
                                         arp_hdr->ar_sip);
			  struct sr_packet *req_walker = requests->packets;
			  /*Go through all the queued packets and send them*/
			  while(req_walker != NULL){
				  ehdr = (sr_ethernet_hdr_t *) req_walker->buf;
				  memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, sizeof(ehdr->ether_dhost));
				  memcpy(ehdr->ether_shost, if_walker->addr, sizeof(ehdr->ether_dhost));
				  
				  sr_send_packet(sr /* borrowed */,
                         req_walker->buf /* borrowed */ ,
                         req_walker->len,
                         req_walker->iface /* borrowed */);
				  req_walker = req_walker->next;
			  }
			  /*Free all requests related to this reply*/
			  sr_arpreq_destroy(&(sr->cache), requests);
		  }
	  }
  }

}/* end sr_ForwardPacket */

/* Sends a type 3 ICMP error  with a given code*/
void send_icmp_type_3 (uint8_t code, unsigned int len, uint8_t *packet, struct sr_instance *sr){
	
	int arp = 1;
	struct sr_rt* rt_walker = NULL;
	struct sr_if* if_walker = NULL;
	uint8_t *reply = malloc(sizeof(sr_ethernet_hdr_t) 
	    + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
		
	/* Headers for the ICMP packet */
    sr_ethernet_hdr_t *retEhdr = (sr_ethernet_hdr_t *) reply;
    sr_ip_hdr_t *retIPhdr = (sr_ip_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *retICMPhdr = (sr_icmp_t3_hdr_t *) 
	    (reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		
	/* Headers for the packet that was being processed */
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
	
	/* Set ethernet header */
	memcpy(retEhdr->ether_dhost, ehdr->ether_shost, sizeof(uint8_t) * 6);
	memcpy(retEhdr->ether_shost, ehdr->ether_dhost, sizeof(uint8_t) * 6);
	retEhdr->ether_type = htons(ethertype_ip);
	
	/* Check if it is an arp packet */
	if(ethertype(packet) == ethertype_ip){
		arp = 0;
	}
	
	/* The packet was not an ARP packet */
	if(arp == 0){
		sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (packet + 
	        sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		/* Set up IP header */
		memcpy(retIPhdr, iphdr, sizeof(sr_ip_hdr_t));
		retIPhdr->ip_p = ip_protocol_icmp;
		retIPhdr->ip_dst = iphdr->ip_src;
		retIPhdr->ip_sum = 0;
		retIPhdr->ip_ttl = 64;
		retIPhdr->ip_id = 0;
		/* Set up the ICMP header */
		retICMPhdr->icmp_type = 3;
		retICMPhdr->icmp_code = code;
		retICMPhdr->icmp_sum = 0;
		retICMPhdr->unused = 0;
		retICMPhdr->next_mtu = 0;
		/* Decide how many bytes to read into the data array */
		int size_of_data = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
		int bytes_to_read = 0;
		if(size_of_data < ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t)){
			bytes_to_read = size_of_data;
		}
		else{
			bytes_to_read = ICMP_DATA_SIZE - sizeof(sr_ip_hdr_t);
		}
		memcpy(retICMPhdr->data, iphdr, sizeof(sr_ip_hdr_t) + bytes_to_read);
		
		retICMPhdr->icmp_sum = cksum(retICMPhdr, sizeof(sr_icmp_t3_hdr_t));
		/* Find interface */
		rt_walker = sr->routing_table;
		while(rt_walker){
			if(rt_walker->dest.s_addr == retIPhdr->ip_dst){
				break;
			}
			rt_walker = rt_walker->next;
		}
		if(rt_walker == NULL){
			return;
		}
		/* Find the source ip */
		if_walker = sr->if_list;
		while(if_walker){
			if(strcmp(if_walker->name, rt_walker->interface) == 0){
				break;
			}
			if_walker = if_walker->next;
		}
		if(if_walker == NULL){
			return;
		}
		retIPhdr->ip_src = if_walker->ip;
		retIPhdr->ip_sum = cksum(retIPhdr, sizeof(sr_ip_hdr_t));
		memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
		sr_send_packet(sr,
                       reply,
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                       rt_walker->interface);
		free(reply);
		return;
	}
	
	/* The original packet was an ARP packet */
	else{
		sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			
		/* Set up IP header */
		retIPhdr->ip_tos = 0;
		retIPhdr->ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
		retIPhdr->ip_id = 0;
		retIPhdr->ip_off = 0;
		retIPhdr->ip_ttl = 64;
		retIPhdr->ip_p = ip_protocol_icmp;
		retIPhdr->ip_dst = arphdr->ar_sip;
		retIPhdr->ip_sum = 0;
		retIPhdr->ip_ttl = 64;
		
		
		/* Set up the ICMP header */
		retICMPhdr->icmp_type = 3;
		retICMPhdr->icmp_code = code;
		retICMPhdr->icmp_sum = 0;
		retICMPhdr->unused = 0;
		retICMPhdr->next_mtu = 0;
		/* Read bytes into data array */
		int size_of_data = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_arp_hdr_t);
		int bytes_to_read = 0;
		if(size_of_data < ICMP_DATA_SIZE - sizeof(sr_arp_hdr_t)){
			bytes_to_read = size_of_data;
		}
		else{
			bytes_to_read = ICMP_DATA_SIZE - sizeof(sr_arp_hdr_t);
		}
		memcpy(retICMPhdr->data, arphdr, sizeof(sr_arp_hdr_t) + bytes_to_read);
		
		retICMPhdr->icmp_sum = cksum(retICMPhdr, sizeof(sr_icmp_t3_hdr_t));
		
		/* Find interface */
		rt_walker = sr->routing_table;
		while(rt_walker){
			if(rt_walker->dest.s_addr == retIPhdr->ip_dst){
				break;
			}
			rt_walker = rt_walker->next;
		}
		if(rt_walker == NULL){
			return;
		}
		
		/* Find the IP address of the interface */
		if_walker = sr->if_list;
		while(if_walker){
			if(strcmp(rt_walker->interface, if_walker->name) == 0){
				break;
			}
			if_walker = if_walker->next;
		}
		if(if_walker == NULL){
			return;
		}
		retIPhdr->ip_src = if_walker->ip;
		retIPhdr->ip_sum = cksum(retIPhdr, sizeof(sr_ip_hdr_t));
		memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
		
		sr_send_packet(sr,
                       reply,
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                       rt_walker->interface);
		free(reply);
		return;
	}
	
}
