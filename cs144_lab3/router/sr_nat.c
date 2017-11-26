
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_router.h"
#include "sr_if.h"

int next_port = 1024;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->incoming = NULL;
  nat->sr = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *currMapping = nat->mappings;
  struct sr_nat_mapping *prevMapping;
  struct sr_nat_connection *currConnection;
  struct sr_nat_connection *prevConnection;
  struct sr_nat_incoming *currIncoming = nat->incoming;
  struct sr_nat_incoming *prevIncoming;
  
  /* Free mappings */
  while(currMapping != NULL){
	  /* Free connections */
	  currConnection = currMapping->conns;
	  while(currConnection != NULL){
		  prevConnection = currConnection;
		  currConnection = currConnection->next;
		  free(prevConnection);
	  }
	  prevMapping = currMapping;
	  currMapping = currMapping->next;
	  free(prevMapping);
  }
  
  /* Free incoming SYN */
  while(currIncoming != NULL){
	  prevIncoming = currIncoming;
	  currIncoming = currIncoming->next;
	  free(prevIncoming);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  
  /* Structures for iterating through stuff */
  struct sr_nat_mapping *currMapping = nat->mappings;
  struct sr_nat_mapping *prevMapping = NULL;
  struct sr_nat_connection *currConnection = NULL;
  struct sr_nat_connection *prevConnection = NULL;
  struct sr_nat_incoming *currIncoming = nat->incoming;
  struct sr_nat_incoming *prevIncoming = NULL;
  
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* Iterate through mappings */
    while(currMapping != NULL){
		/* mapping is for ICMPs */
		if(currMapping->type == nat_mapping_icmp){
			/* Remove mapping if it timed out */
			/* Pointer will increment here */
			if(difftime(currMapping->last_updated, curtime) > nat->icmp_timeout){
				/* This was the head of the list */
				if(prevMapping == NULL){
					nat->mappings = currMapping->next;
					free(currMapping);
					currMapping = nat->mappings;
				}
				/* This was not the head */
				else{
					prevMapping->next = currMapping->next;
					free(currMapping);
					currMapping = prevMapping->next;
				}
			}
			/* Increment pointer for mappings */
			else{
				prevMapping = currMapping;
				currMapping = currMapping->next;
			}
		}
		/* Mapping is for TCP, check the connections */
		else{
			/* Iterate through connections connections */
			currConnection = currMapping->conns;
			while(currConnection != NULL){
				/* Check if connection is established and if it timed out */
				/* Or if transitory state and timed out */
				/* Pointer auto increments here */
				if((difftime(currConnection->last_updated, curtime) > nat->tcp_timeout_est && 
				    currConnection->state == tcp_established) || 
					difftime(currConnection->last_updated, curtime) > nat->tcp_timeout_trans){
						
				    /* Remove connection */
					
					/* This was the head */
					if(prevConnection == NULL){
						currMapping->conns = currConnection->next;
						free(currConnection);
						currConnection = currMapping->conns;
					}
					/* Not the head, unlink it */
					else{
						prevConnection->next = currConnection->next;
						free(currConnection);
						currConnection = prevConnection->next;
					}
				}
				/* Otherwise just increment pointer */
				else{
					prevConnection = currConnection;
				    currConnection = currConnection->next;
				}
			}
			/* Increment pointer for mappings */
			prevMapping = currMapping;
		    currMapping = currMapping->next;
		}
		prevConnection = NULL;
    }
	
	
	/* Look for timed out incoming SYN */
	while(currIncoming != NULL){
		/* Timed out, remove it and send ICMP back */
		if(difftime(currIncoming->last_updated, curtime) > 6){
			/* Is the head of the list */
			if(prevIncoming == NULL){
				/* Send icmp */
				send_icmp_type_3(3, currIncoming->len, currIncoming->packet, nat->sr);
				nat->incoming = currIncoming->next;
				/*free(currIncoming);*/
				currIncoming = nat->incoming;
			}
			/* Not the head, unlink */
			else{
				send_icmp_type_3(3, currIncoming->len, currIncoming->packet, nat->sr);
				prevIncoming->next = currIncoming->next;
				/*free(currIncoming);*/
			    currIncoming = prevIncoming->next;
			}
		}
		/* Incrememnt pointer */
		else{
			prevIncoming = currIncoming;
			currIncoming = currIncoming->next;
		}
	}
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = nat->mappings;
  /* Look for mapping */
  while(mapping != NULL){
	  if(mapping->type == type && mapping->aux_ext == aux_ext){
		  break;
	  }
  }
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  
  /* No mapping found */
  if(mapping == NULL){
	  return copy;
  }
  /* Mapping found, make a copy */
  else{
	  /* Update last use time */
      mapping->last_updated = time(NULL);
	  copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = nat->mappings;
  /* Look for mapping */
  while(mapping != NULL){
	  if(mapping->type == type && mapping->aux_int == aux_int && mapping->ip_int == ip_int){
		  break;
	  }
  }
  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  
  /* No mapping found */
  if(mapping == NULL){
	  return copy;
  }
  
  /* Mapping found, make a copy */
  else{
	  /* Update last use time */
      mapping->last_updated = time(NULL);
	  copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* Get the external interface */
  struct sr_if* ext_if = sr_get_interface(nat->sr, "eth2");
  struct sr_nat_mapping *newMapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  newMapping->type = type; 
  newMapping->ip_int = ip_int; /* internal ip addr */
  newMapping->ip_ext = ext_if->ip; /* external ip addr */
  newMapping->aux_int = aux_int; /* internal port or icmp id */
  newMapping->aux_ext = htons(next_port); /* external port or icmp id */
  next_port++;
  newMapping->last_updated = time(NULL); /* use to timeout mappings */
  newMapping->conns = NULL; /* list of connections. null for ICMP */
  newMapping->next = nat->mappings;
  nat->mappings = newMapping;
	
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(mapping, newMapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/* Insert a connection to a mapping */
struct sr_nat_connection * sr_nat_insert_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip){
	pthread_mutex_lock(&(nat->lock));
	struct sr_nat_connection *newConn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
	newConn->ip = ip;
	newConn->last_updated = time(NULL);
	newConn->state = tcp_listen;
	newConn->next = mapping->conns;
	mapping->conns = newConn;
	pthread_mutex_unlock(&(nat->lock));
	return newConn;
}

/* Find a connection with a given mapping and IP */
struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat *nat, 
  struct sr_nat_mapping *mapping, uint32_t ip){
	  
	pthread_mutex_lock(&(nat->lock));
	struct sr_nat_connection *retConn = NULL;
	struct sr_nat_connection *currConn = mapping->conns;
	while(currConn != NULL){
		if(currConn->ip == ip){
			break;
		}
	}
	if(currConn == NULL){
		return retConn;
	}
	currConn->last_updated = time(NULL);
	retConn = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
	memcpy(retConn, currConn, sizeof(struct sr_nat_connection));
	pthread_mutex_unlock(&(nat->lock));
	return retConn;
}

/* Insert an incoming unsolicited SYN packet to the list */
void sr_nat_insert_incoming(struct sr_nat *nat, uint8_t *packet, 
  unsigned int len, uint32_t ip){
	  
	pthread_mutex_lock(&(nat->lock));
	struct sr_nat_incoming *newInc = (struct sr_nat_incoming *) malloc(sizeof(struct sr_nat_incoming));
	newInc->packet = packet;
	newInc->len = len;
	newInc->ip = ip;
	newInc->last_updated = time(NULL);
	newInc->next = nat->incoming;
	nat->incoming = newInc;
	pthread_mutex_unlock(&(nat->lock));
}