#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
	struct sr_arpreq *req_walker = sr->cache.requests;
	struct sr_arpreq *req_walker_next = NULL;
	while(req_walker){
		req_walker_next = req_walker->next;
		handle_arpreq(sr, req_walker);
		req_walker = req_walker_next;
	}
}

/* Function for sending an ARP request for a given request
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request){
	time_t now;
	time(&now);
	/*Packet that will be sent*/
	uint8_t *reply = NULL;
	sr_ethernet_hdr_t *retEhdr = NULL;
	/*
	sr_ip_hdr_t *retIPhdr = NULL;
    sr_icmp_hdr_t *retICMPhdr = NULL;
	*/
    sr_arp_hdr_t *retARPhdr = NULL;
	struct sr_if* if_walker = NULL;
	struct sr_packet *packet_walker = NULL;
	
	
	/* Check if it's been at least 1 second since last request */
	if(difftime(now, request->sent) > 1){
		/* Request sent 5 times, send back an ICMP error */
		if(request->times_sent >= 5){
			packet_walker = request->packets;
			while(packet_walker){
				send_icmp_type_3(1, packet_walker->len, packet_walker->buf, sr);
				packet_walker = packet_walker->next;
			}
			sr_arpreq_destroy(&(sr->cache), request);
			return;
		}
		/* Send a request */
		else{
			/*Initialize the packet and headers*/
			reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
			retEhdr = (sr_ethernet_hdr_t *) reply;
			retARPhdr = (sr_arp_hdr_t *) (reply + sizeof(sr_ethernet_hdr_t));
			
			/* Find the interface for source mac and ip */
			if_walker = sr->if_list;
			while(if_walker){
				if(strcmp(if_walker->name, request->packets->iface) == 0){
					break;
				}
				if_walker = if_walker->next;
			}
			if(if_walker == NULL){
				printf("interface not found\n");
				return;
			}
			
			/* Set up ethernet header */
			retEhdr->ether_type = htons(ethertype_arp);
			memcpy(retEhdr->ether_shost, if_walker->addr, sizeof(uint8_t) * 6);
			/*Set destination to FF-FF-FF-FF-FF-FF*/
			retEhdr->ether_dhost[0] = 255;
			retEhdr->ether_dhost[1] = 255;
			retEhdr->ether_dhost[2] = 255;
			retEhdr->ether_dhost[3] = 255;
			retEhdr->ether_dhost[4] = 255;
			retEhdr->ether_dhost[5] = 255;

			/*Set up ARP header*/
			retARPhdr->ar_hrd = htons(arp_hrd_ethernet);
			retARPhdr->ar_pro = htons(0x0800);
			retARPhdr->ar_hln = ETHER_ADDR_LEN;
			retARPhdr->ar_pln = 4;
			retARPhdr->ar_op = htons(arp_op_request);
			memcpy(retARPhdr->ar_sha, if_walker->addr, sizeof(unsigned char) * 6);
			retARPhdr->ar_sip = if_walker->ip;
			retARPhdr->ar_tha[0] = 0;
			retARPhdr->ar_tha[1] = 0;
			retARPhdr->ar_tha[2] = 0;
			retARPhdr->ar_tha[3] = 0;
			retARPhdr->ar_tha[4] = 0;
			retARPhdr->ar_tha[5] = 0;
			retARPhdr->ar_tip = request->ip;
			
			/* Send the packet */
			sr_send_packet(sr, reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), if_walker->name);
			/* Update information in request */
			time(&now);
			request->sent = now;
			request->times_sent = request->times_sent + 1;
			free(reply);
		}
	}
	return;
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

