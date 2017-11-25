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
#include "sr_nat.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	
	/* Handle nat initialization if needed */
    if(sr->is_nat == 1){
		struct sr_nat *nat = (struct sr_nat *) malloc(sizeof(struct sr_nat));
	    sr_nat_init(nat);
	    nat->icmp_timeout = sr->icmp_timeout;
	    nat->tcp_timeout_est = sr->tcp_timeout_est;
	    nat->tcp_timeout_trans = sr->tcp_timeout_trans;
		sr->nat = nat;
		nat->sr = sr;
    }
    
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
  print_hdrs(packet, len);
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
	  /* If nat is enabled, handle this in the sr_handle_nat function */
	  if(sr->is_nat == 1){
		  sr_handle_nat(sr, packet, len, interface);
		  return;
	  }
	  
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
		  printf("%u %u\n", sum, cksum(icmp_hdr, sizeof(sr_icmp_hdr_t) + 8));
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
                  memcpy(retEhdr->ether_dhost, arpentry->mac, sizeof(retEhdr->ether_shost));
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
	  else if (found == 1){
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
		  printf("ARP REPLY\n");
		  fflush(stdout);
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
				  printf("HANDLING\n");
		  fflush(stdout);
				  ehdr = (sr_ethernet_hdr_t *) req_walker->buf;
				  memcpy(ehdr->ether_dhost, arp_hdr->ar_tha, sizeof(ehdr->ether_dhost));
				  memcpy(ehdr->ether_shost, if_walker->addr, sizeof(ehdr->ether_dhost));
				  if_walker = sr->if_list;
                  while(if_walker){
                      if(memcmp(if_walker->addr, arp_hdr->ar_tha, sizeof(unsigned char) * 6) == 0){
                      break;
                      }
                      if_walker = if_walker->next;
                  }
				  sr_send_packet(sr /* borrowed */,
                                      req_walker->buf /* borrowed */ ,
                                      req_walker->len,
                                      if_walker->name /* borrowed */);
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
        if(code == 3){
            retIPhdr->ip_src = iphdr->ip_dst;
        }
        else{
            retIPhdr->ip_src = if_walker->ip;
        }
		retIPhdr->ip_sum = cksum(retIPhdr, sizeof(sr_ip_hdr_t));
		memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
		sr_send_packet(sr,
                       reply,
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                       if_walker->name);
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
		
		/* Find the IP address of the interface */
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
		memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
		
		sr_send_packet(sr,
                       reply,
                       sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t),
                       if_walker->name);
		free(reply);
		return;
	}
	
}

/* Function for handling IP packets when nat is enabled
 */
void sr_handle_nat(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface){
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t *icmphdr = NULL;
	uint16_t *icmp_id = 0;   /* The port/id for icmp */
	sr_tcp_hdr_t *tcphdr = NULL;
	struct sr_nat_mapping *mapping = NULL;
	struct sr_nat_connection *connection = NULL;
	
	/* Check if it is going to one of our interfaces */
	struct sr_if* if_walker = sr->if_list;
	while(if_walker != NULL){
		if(if_walker->ip == iphdr->ip_dst){
			break;
		}
		if_walker = if_walker->next;
	}
	
	/* Get the external interface */
	struct sr_if* ext_if = sr_get_interface(sr, "eth2");
	struct sr_if* int_if = sr_get_interface(sr, "eth1");
	
	/* Check if IP or ICMP packet */
	uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
	/* Drop UDP packet */
	if(ip_proto == 0x0011){
		return;
	}
	
	/* Packet coming from internal */
	if(strncmp(interface, "eth3", 4)){
		/* IP packet sent to our interface, port unreachable */
		if(if_walker != NULL){
			send_icmp_type_3 (3, len, packet, sr);
			return;
		}
		/* Otherwise, handle packet */
		
		/* Handle ICMP packet */
		if (ip_proto == ip_protocol_icmp) {
			/* TODO: handle checksum */
			icmphdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_id = (uint16_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
			mapping = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, *icmp_id, nat_mapping_icmp);
			/* Mapping not found add it */
			if(mapping == NULL){
				mapping = sr_nat_insert_mapping(sr->nat, iphdr->ip_src, *icmp_id, nat_mapping_icmp);
			}
			
			/* Update ICMP header */
			*icmp_id = mapping->aux_ext;
			icmphdr->icmp_sum = 0;
			icmphdr->icmp_sum = cksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		}
		
		/* Handle TCP packet */
		else{
			/* TODO: handle checksum */
			tcphdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			mapping = sr_nat_lookup_internal(sr->nat, iphdr->ip_src, ntohs(tcphdr->src_port), nat_mapping_tcp);
			/* No mapping yet, add it */
			if(mapping == NULL){
				mapping = sr_nat_insert_mapping(sr->nat, iphdr->ip_src, tcphdr->src_port, nat_mapping_tcp);
			}
			
			/* Find connection, insert if it does not exist */
			connection = sr_nat_lookup_connection(sr->nat, mapping, iphdr->ip_dst);
			if(connection == NULL){
				connection = sr_nat_insert_connection(sr->nat, mapping, iphdr->ip_dst);
			}
			
			pthread_mutex_lock(&(sr->nat->lock));
			/* Update connection state to keep track of 3-way handshake */
			switch(connection->state){
				/* Connection goes from listen to syn_sent when sending SYN */
				case tcp_listen:{
					if(tcphdr->syn == 1){
						connection->state = tcp_syn_sent;
					}
				}
				/* Recieved goes to established */
				case tcp_rcvd:{
					if(tcphdr->ack == 1){
						connection->state = tcp_established;
					}
				}
				/* Acknowledging a fin means that the connection is closed */
				case tcp_established:{
					if(tcphdr->fin == 1 && tcphdr->ack == 1){
						connection->state = tcp_closed;
					}
				}
				default:{
					break;
				}
			}
			pthread_mutex_unlock(&(sr->nat->lock));
			/* Update tcp headers */
			tcphdr->src_port = htons(mapping->aux_ext);
			tcphdr->checksum = 0;
			tcphdr->checksum = cksum(tcphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		}
		memcpy(ehdr->ether_shost, ext_if->addr, sizeof(uint8_t) * 6);
		iphdr->ip_src = ext_if->ip;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
		/*Check arp cache*/
		struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), iphdr->ip_dst);
		if(arpentry != NULL){
			memcpy(ehdr->ether_dhost, arpentry->mac, sizeof(uint8_t) * 6);
			sr_send_packet(sr, packet, len, "eth2");
			free(arpentry);
			return;
		}
		/*Not in cache, send ARP requests*/
		else{
			sr_arpcache_queuereq(&(sr->cache),
                                    iphdr->ip_dst,
                                    packet,
                                    len,
                                    "eth2");
		}
	}
	
	/* Packet coming from external */
	else{
		/* Handle incoming ICMP packet */
		
		/* TODO: handle pings to external if */
		if (ip_proto == ip_protocol_icmp) {
			/* TODO: handle checksum */
			icmp_id = (uint16_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
			mapping = sr_nat_lookup_external(sr->nat, *icmp_id, nat_mapping_icmp);
			/* Mapping not found drop packet */
			if(mapping == NULL){
				return;
			}
			
			/* Update ICMP header */
			*icmp_id = mapping->aux_int;
			icmphdr->icmp_sum = 0;
			icmphdr->icmp_sum = cksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		}
		
		/* Handle incoming TCP packet */
		else{
			/* TODO: handle checksum */
			tcphdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			mapping = sr_nat_lookup_external(sr->nat, tcphdr->dst_port, nat_mapping_tcp);
			/* Mapping not found add to incoming list if it is SYN */
			if(mapping == NULL){
				if(tcphdr->syn == 1){
					sr_nat_insert_incoming(sr->nat, packet, len, iphdr->ip_src);
				}
				return;
			}
			
			/* Get connection */
			connection = sr_nat_lookup_connection(sr->nat, mapping, iphdr->ip_src);
			pthread_mutex_lock(&(sr->nat->lock));
			/* Update connection state to keep track of 3-way handshake */
			switch(connection->state){
				/* Connection goes from sent to recieved */
				case tcp_syn_sent:{
					if(tcphdr->ack == 1){
						connection->state = tcp_established;
					}
				}
				/* Check if fin was requested */
				case tcp_established:{
					if(tcphdr->fin == 1){
						connection->state = tcp_transitory;
					}
				}
				default:{
					break;
				}
			}
			pthread_mutex_unlock(&(sr->nat->lock));
			/* Update tcp headers */
			tcphdr->dst_port = htons(mapping->aux_int);
			tcphdr->checksum = 0;
			tcphdr->checksum = cksum(tcphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		}
		memcpy(ehdr->ether_dhost, int_if->addr, sizeof(uint8_t) * 6);
		iphdr->ip_dst = mapping->ip_int;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
		printf("REPLY SENT TO:\n");
		print_hdrs(packet, len);
		sr_send_packet(sr, packet, len, "eth1");
	}
}

