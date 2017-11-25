#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_nat.h"
#include "sr_router.h"

int next_tcp_port = 0;
int next_icmp_port = 0;

/* Initializes the nat */
int sr_nat_init(struct sr_nat *nat)
{
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

    /* Initialize any variables here */
    nat->mappings = NULL;
    nat->incoming = NULL;
    next_tcp_port = MIN_NAT_PORT;
    next_icmp_port = MIN_NAT_PORT;

    return success;
}

/* Destroys the nat (free memory) */
int sr_nat_destroy(struct sr_nat *nat)
{
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *mapping = nat->mappings;
    while (mapping)
    {
        struct sr_nat_mapping *prev_mapping = mapping;
        mapping = mapping->next;
        free(prev_mapping);
    }

    struct sr_nat_tcp_syn *incoming = nat->incoming;
    while (incoming)
    {
        struct sr_nat_tcp_syn *prev_incoming = incoming;
        incoming = incoming->next;
        free(prev_incoming);
    }

    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
           pthread_mutexattr_destroy(&(nat->attr));
}

/* Periodic Timeout handling */
void *sr_nat_timeout(void *nat_ptr)
{
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    while (1)
    {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t curtime = time(NULL);

        /* Handle incoming SYNs */
        struct sr_nat_tcp_syn *prev_incoming = NULL;
        struct sr_nat_tcp_syn *incoming = nat->incoming;
        while (incoming)
        {
            /* Shouldn't respond to unsolicited inbound SYN packet for at least 6 seconds */
            if (difftime(curtime, incoming->last_received) > 6)
            {
                struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, incoming->port, nat_mapping_tcp);
                if (!mapping)
                {
                    send_icmp_msg(nat->sr, incoming->packet, incoming->len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                }

                /* Remove from list */
                if (prev_incoming)
                {
                    prev_incoming->next = incoming->next;
                }
                else
                {
                    nat->incoming = incoming->next;
                }

                free(incoming->packet);
                free(incoming);
            }
            else
            {
                prev_incoming = incoming;
                incoming = incoming->next;
            }
        }

        /* Remove timed out mappings */
        struct sr_nat_mapping *prev_mapping = NULL;
        struct sr_nat_mapping *mapping = nat->mappings;
        while (mapping)
        {
            switch (mapping->type)
            {
                case nat_mapping_icmp:
                {
                    /* ICMP query timeout */
                    if (difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout)
                    {
                        sr_nat_remove_mapping(nat, mapping, prev_mapping);
                    }
                    break;
                }

                case nat_mapping_tcp:
                {
                    int remove_mapping = 1;
                    struct sr_nat_connection *prev_conn = NULL;
                    struct sr_nat_connection *conn = mapping->conns;
                    if (conn)
                    {
                        while (conn) {
                            switch (conn->state) {
                                /* TCP Established Idle Timeout */
                                case tcp_state_established:
                                case tcp_state_fin_wait_1:
                                case tcp_state_fin_wait_2:
                                case tcp_state_close_wait:
                                {
                                    if (difftime(curtime, conn->last_updated) > nat->tcp_established_timeout)
                                    {
                                        sr_nat_remove_conn(nat, mapping, conn, prev_conn);
                                    }
                                    else
                                    {
                                        remove_mapping = 0;
                                    }

                                    break;
                                }

                                /* TCP Transitory Idle Timeout */
                                case tcp_state_syn_sent:
                                case tcp_state_syn_received:
                                case tcp_state_last_ack:
                                case tcp_state_closing:
                                {
                                    if (difftime(curtime, conn->last_updated) > nat->tcp_transitory_timeout)
                                    {
                                        sr_nat_remove_conn(nat, mapping, conn, prev_conn);
                                    }
                                    else
                                    {
                                        remove_mapping = 0;
                                    }

                                    break;
                                }

                                default:
                                {
                                    break;
                                }
                            }

                            prev_conn = conn;
                            conn = conn->next;
                        }
                    }

                    if (remove_mapping)
                    {
                        sr_nat_remove_mapping(nat, mapping, prev_mapping);
                    }

                    break;
                }
            }

            prev_mapping = mapping;
            mapping = mapping->next;
        }

        pthread_mutex_unlock(&(nat->lock));
    }

    return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping)
    {
        if (mapping->type == type && mapping->aux_ext == aux_ext)
        {
            copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            /* mapping->last_updated = time(NULL); */
            break;
        }
        mapping = mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping)
    {
        if (mapping->type == type && mapping->aux_int == aux_int && mapping->ip_int == ip_int)
        {
            copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

            /* mapping->last_updated = time(NULL); */
            break;
        }
        mapping = mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_mapping *mapping = NULL;

    /* See if it already exists */
    mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
    if (mapping)
    {
        return mapping;
    }

    mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

    mapping->type = type;
    mapping->ip_int = ip_int;
    mapping->ip_ext = 0;
    mapping->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;

    /* TODO: double check this */
    switch (type)
    {
        case nat_mapping_icmp:
        {
            mapping->aux_ext = next_icmp_port++;
            if (next_icmp_port >= MAX_NAT_PORT)
            {
                next_icmp_port = MIN_NAT_PORT;
            }
            break;
        }

        case nat_mapping_tcp:
        {
            mapping->aux_ext = next_tcp_port++;
            if (next_tcp_port >= MAX_NAT_PORT)
            {
                next_tcp_port = MIN_NAT_PORT;
            }
            break;
        }
    }

    mapping->next = nat->mappings;
    nat->mappings = mapping;

    /* Make a copy for thread safety */
    struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/* Custom: Removes a mapping from the linked list */
void sr_nat_remove_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *prev_mapping)
{
    pthread_mutex_lock(&(nat->lock));

    if (!prev_mapping)
    {
        /* mapping was the head */
        nat->mappings = mapping->next;
    }
    else
    {
        prev_mapping->next = mapping->next;
    }

    struct sr_nat_connection *conn = mapping->conns;
    while (conn)
    {
        free(conn);
        conn = conn->next;
    }

    free(mapping);

    pthread_mutex_unlock(&(nat->lock));
}

/* Custom: finds a connection from a mapping's list */
struct sr_nat_connection *sr_nat_get_conn(struct sr_nat_mapping *mapping, uint32_t ip)
{
    struct sr_nat_connection *conn = mapping->conns;

    while (conn)
    {
        if (conn->ip == ip)
        {
            return conn;
        }

        conn = conn->next;
    }

    return NULL;
}

/* Custom: inserts a connection to a mapping's list */
struct sr_nat_connection *sr_nat_add_conn(struct sr_nat_mapping *mapping, uint32_t ip)
{
    struct sr_nat_connection *conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
    memset(conn, 0, sizeof(struct sr_nat_connection));

    conn->ip = ip;
    conn->state = tcp_state_closed;
    conn->last_updated = time(NULL);

    /* Add as head of linked list */
    conn->next = mapping->conns;
    mapping->conns = conn;

    return conn;
}

/* Custom: Removes a connection from the linked list */
void sr_nat_remove_conn(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *conn, struct sr_nat_connection *prev_conn)
{
    pthread_mutex_lock(&(nat->lock));

    if (!prev_conn)
    {
        /* conn was the head */
        mapping->conns = conn->next;
    }
    else
    {
        prev_conn->next = conn->next;
    }

    free(conn);

    pthread_mutex_unlock(&(nat->lock));
}

/* Custom: checks if an incoming TCP SYN connection exists and adds it if not */
void add_incoming_syn(struct sr_nat *nat, uint32_t src_ip, uint16_t src_port, uint8_t *packet, unsigned int len)
{
    struct sr_nat_tcp_syn *incoming = nat->incoming;
    while (incoming)
    {
        if ((incoming->ip == src_ip) && (incoming->port == src_port))
        {
            return;
        }

        incoming = incoming->next;
    }

    /* Add new SYN to linked list */
    incoming = (struct sr_nat_tcp_syn *)malloc(sizeof(struct sr_nat_tcp_syn));

    incoming->ip = src_ip;
    incoming->port = src_port;
    incoming->packet = (uint8_t *)malloc(len);
    memcpy(incoming->packet, packet, len);
    incoming->len = len;
    incoming->last_received = time(NULL);

    incoming->next = nat->incoming;
    nat->incoming = incoming;
}
