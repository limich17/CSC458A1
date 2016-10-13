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
#include <stdlib.h>
#include <assert.h>
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
  
    /* 
  1. determine if IP packet or ARP packet (ethertype: IPv4 - 0x0800, ARP - 0x0806)
  2a. if IP packet, determine if destination interface is in routing table
  	3a. if in routing table (for me), determine if ICMP or TCP/UDP request
  		 4a. if ICMP echo request, send echo reply
  		 4b. if TCP/UDP, send ICMP port unreachable message
  	3b. if not in routing table (not for me), do LPM on routing table and find match
  		 4a. if no match, send ICMP net unreachable message 
 		 4b. if match, check ARP cache for next-hop MAC address which corresponds to the matched IP
  				5a. if found MAC, send packet
  				5b. if no MAC, send ARP request to IP (if not sent within last second) and add packet to ARP request queue
   2b. if ARP packet, determine if reply/request
   	3a. if reply, cache and go through request queue, send outstanding packets
   	3b. if request, construct ARP reply and send back?
  */

 
  struct sr_ethernet_hdr *eth_header;

  eth_header = malloc(sizeof(struct sr_ethernet_hdr *));

  memcpy(eth_header->ether_dhost, packet, 6);
  memcpy(eth_header->ether_shost, packet + 6, 6);
  memcpy(&(eth_header->ether_type), packet + 12, 2);

  uint16_t eth_type = htons(eth_header->ether_type);

  /* ---------- PRINT ETHERNET HEADER ------------- */
  /*
  printf("eth_header.ether_type: %#06X\n", eth_type);
  
  int i, j;

  printf("eth_header->ether_dhost: ");
  for (i = 0; i < 6; i++) {
    printf("%0X", eth_header->ether_dhost[i]);
  }
  printf("\n");

  printf("eth_header->ether_shost: ");
  for (j = 0; j < 6; j++) { 
    printf("%0X", eth_header->ether_shost[j]);
  }
  printf("\n");

  printf("equal? %d\n", eth_type == ethertype_arp);
  */

  /* is ARP packet */
  if (eth_type == ethertype_arp) {
    /*struct sr_arp_hdr *arp_header;


    printf("THIS IS ARP \n");
    arp_header = malloc(sizeof(struct sr_arp_hdr *));

    memcpy(&(arp_header->ar_hrd), packet + 14, 2);
    memcpy(&(arp_header->ar_pro), packet + 16, 2);
    memcpy(&(arp_header->ar_hln), packet + 18, 1);
    memcpy(&(arp_header->ar_pln), packet + 19, 1);
    memcpy(&(arp_header->ar_op), packet + 20, 2);
    memcpy(arp_header->ar_sha, packet + 22, 6);
    memcpy(&(arp_header->ar_sip), packet + 28, 4);
    memcpy(arp_header->ar_tha, packet + 32, 6);
    memcpy(&(arp_header->ar_tip), packet + 38, 4); */
  } 
  /* is IP packet */
  else {

  }

}
