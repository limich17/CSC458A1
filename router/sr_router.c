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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
/*Added by student:*/
#include "string.h"
#include "stdlib.h"

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
  printf("Interface is: %d \n", *interface);
  /*int i;
  for (i = 0; i < len; i = i + 1 ){
	  
	  printf("Packet %d: %02X \n", i, *(packet + i));
  }*/
  
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
  

  

  struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
  */
  print_hdr_eth(packet);

  uint16_t eth_type = ethertype(packet);

  /* is ARP packet */
  if (eth_type == ethertype_arp) {
	sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *)(packet + 14);
	  
	  print_hdr_arp(packet + 14);

	  printf("opcode: %02X \n", ntohs(arpHdr->ar_op));
	
	  if (ntohs(arpHdr->ar_op) == arp_op_request){ 
	
	  	printf("It is a request ARP packet \n");
		/* Go through each interface, look for a match*/
		
		struct sr_if* in_router = sr_get_interface_by_ip(sr, arpHdr->ar_tip);
		
		if (in_router){
			printf("Ok, the target is in our routing table, send this back: \n");
			
		uint8_t * packetReply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
		
		printf("size of packet: %lu \n", sizeof(packetReply));
		printf("size of given buffer: %lu \n", sizeof(packet));	 
		/*
		sr_ethernet_hdr_t *ethReply;
		sr_arp_hdr_t *arpReply;
		
		memcpy(ethReply->ether_dhost, packet + 6, 6);
  		memcpy(ethReply->ether_shost, in_router->addr, 6);
		memcpy(&(ethReply->ether_type), packet + 12, 2);
		
		 	
		memcpy(&(arpReply->ar_hrd), &(arpHdr->ar_hrd), 2);
		memcpy(&(arpReply->ar_pro), &(arpHdr->ar_pro), 2);
		memcpy(&(arpReply->ar_hln), &(arpHdr->ar_hln), 1);
		memcpy(&(arpReply->ar_pln), &(arpHdr->ar_pln), 1);
		arpReply->ar_op = htons(arp_op_reply);
		
		memcpy(arpReply->ar_sha, in_router->addr, ETHER_ADDR_LEN);
		memcpy(arpReply->ar_tha, packet + 6, ETHER_ADDR_LEN);
		
		memcpy(&(arpReply->ar_sip), &(in_router->ip), 4);
		memcpy(&(arpReply->ar_tip), &(arpHdr->ar_sip), 4);
		
		print_hdr_eth((uint8_t *)ethReply);
		print_hdr_arp((uint8_t *)arpReply);
		
		*/
		enum sr_arp_opcode reply;
		reply = htons(arp_op_reply);
  		
		memcpy(packetReply + 0, packet + 6, 6);
		memcpy(packetReply + 6, in_router->addr, 6);
		memcpy(packetReply + 12, packet + 12, 2);
		 	
		memcpy(packetReply + 14, &(arpHdr->ar_hrd), 2);
		memcpy(packetReply + 16, &(arpHdr->ar_pro), 2);
		memcpy(packetReply + 18, &(arpHdr->ar_hln), 1);
		memcpy(packetReply + 19, &(arpHdr->ar_pln), 1);
		
		memcpy(packetReply + 20, &reply, 2);
		
		
		memcpy(packetReply + 22, in_router->addr, ETHER_ADDR_LEN);
		memcpy(packetReply + 22 + ETHER_ADDR_LEN, &(in_router->ip), 4);
		memcpy(packetReply + 26 + ETHER_ADDR_LEN, packet + 6, ETHER_ADDR_LEN);
		memcpy(packetReply + 26 + (2 * ETHER_ADDR_LEN), &(arpHdr->ar_sip), 4);
		
		
		
		
		printf("Now custom packet buffer: \n\n");
		print_hdr_eth(packetReply);
		print_hdr_arp(packetReply + 14);
		printf("\n\n Now sending the packet! \n");
		
		
		sr_send_packet(sr, packetReply, len,
                (const char *)in_router);
		free(packetReply);
		
	
		}else{
			printf("Target not in our table. Drop it safely (like its hot)  \n");
		}
	
		

	  }

	  else if (ntohs(arpHdr->ar_op) == arp_op_reply){ 
	
		struct sr_arpreq *replyReq;
		printf("It is a reply ARP packet. Add to cache. Here is cache before add: \n");
		
		sr_arpcache_dump(&(sr->cache));
		replyReq = sr_arpcache_insert(&(sr->cache),arpHdr->ar_sha, arpHdr->ar_sip);
		printf("And after add\n");
		sr_arpcache_dump(&(sr->cache));
		
		
		/*Now go through request queue for this reply, send them all out */
		if (replyReq){
        		struct sr_packet *sendPacket, *nextPacket;
        
        		for (sendPacket = replyReq->packets; sendPacket; sendPacket = nextPacket) {
            			nextPacket = sendPacket->next;
            			if (sendPacket->buf){
					sr_nexthop(sr, sendPacket->buf, sendPacket->len, arpHdr->ar_sha, sendPacket->iface);
				}
        		}
		
		
		
			sr_arpreq_destroy(&(sr->cache), replyReq);
		} else{
			printf("I got a reply for the below IP, but I have no packets for that IP in my queue: \n");
			print_addr_ip_int(arpHdr->ar_sip);
		}
		
		
	  }

  }
  /* is IP packet */
  else {
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_ip_hdr* ip_header = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

    /* sanity check packet (length, checksum) */
    /* validatePacket(ip_header, len); */

    /* find the interface */
    /* destination is not one of our interfaces */
    if (sr_get_interface_by_ip(sr, ip_header->ip_dst) == 0) {
	printf("not for me \n");
      /* decrement TTL by 1  */
      ip_header->ip_ttl = ip_header->ip_ttl - 1;
      if (ip_header->ip_ttl < 1) {
        /* TTL is 0 */
        /* send ICMP error */
        sr_send_icmp_error(11, 0, sr, packet, ip_header->ip_src);
      } else {
        /* recompute checksum over modified header */
        ip_header->ip_sum = calc_ip_cksum(ip_header);
	
	printf("\n now print it again after recalculating checksum and decrementing TTL:");
	print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
	
        /* do LPM with dest IP address */
        struct sr_rt *matchResult = sr_find_lpm(sr->routing_table, ip_header->ip_dst);
        if (!matchResult) {
	  printf("no lpm match found \n");
          /* no match found, send ICMP net unreachable */
          sr_send_icmp_error(3, 0, sr, packet, ip_header->ip_src);
        } else {
          /* match found, check ARP cache */
	  printf("lpm match found \n");
	  
   	struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst);

   	if (entry){
	printf("I found the ICMP target ip in my cache! Sending it forward to next hop \n");
	/* Send the ICMP now */
	
		sr_nexthop(sr, packet, len, entry->mac, matchResult->interface);
	
	
	
	
       		}
   	else{
   		/* Must create an ARP request below. Calling quereq makes a new request. COPY PACKET WITH MEMCPY */
		struct sr_arpreq *req;
       		req = sr_arpcache_queuereq(&(sr->cache), ip_header->ip_dst, packet, len, matchResult->interface);
		/* now send the req through a function. Keep sending it every second for 5 seconds: */
       
       		handle_arpreq(req, sr); /* doesn't work yet */
  	 }
	  
	  
	  
        }
      }

    } else {
      /* destination is one of our interfaces */
	  printf("for me");
	  
		  if (ip_protocol((packet + sizeof(sr_ethernet_hdr_t))) == ip_protocol_icmp) {
			  printf("is ICMP packet \n");
			  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			  
			  uint8_t type = icmp_header->icmp_type;
			  
			  if (type == 8) {
				  printf("is ICMP echo request \n");
				  /* check checksum */
				  sr_send_echo_reply(sr, packet, len, interface);
			  } else if (type == 6 || type == 17) {
				  printf("is TCP or UDP \n");
				  sr_send_icmp_error(3, 3, sr, packet, ip_header->ip_src);
			  }
		  }
	}
	  
  }

}/* end sr_ForwardPacket */

void sr_send_icmp_error(uint8_t icmp_type, uint8_t icmp_code, struct sr_instance *sr, uint8_t *packet, uint32_t dest) {
  /* get packet length */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  
  uint8_t *icmp_packet = malloc(len);

  struct sr_icmp_t3_hdr *icmp3_header = (sr_icmp_t3_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  struct sr_ip_hdr *ip_header = (sr_ip_hdr_t *) (icmp_packet + sizeof(sr_ethernet_hdr_t));
  struct sr_ethernet_hdr *eth_header = (sr_ethernet_hdr_t *) icmp_packet;

  struct sr_ip_hdr *orig_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  icmp3_header->icmp_type = icmp_type;
  icmp3_header->icmp_code = icmp_code;
  memcpy(icmp3_header->data, orig_ip_header, 28);
  icmp3_header->icmp_sum = calc_icmp3_cksum(icmp3_header);

  /* get interface */
  struct sr_if *iface = sr_get_interface_by_ip(sr, ip_header->ip_dst);
  ip_header->ip_v = 4;
  ip_header->ip_hl = sizeof(sr_ip_hdr_t)/4;
  ip_header->ip_id = 0;
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 64;
  ip_header->ip_dst = dest;
  ip_header->ip_src = iface->ip;
  ip_header->ip_sum = calc_ip_cksum(ip_header);

  uint8_t *eth_src = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_src, eth_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

  memcpy(eth_header->ether_shost, eth_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_header->ether_dhost, eth_src, sizeof(uint8_t) * ETHER_ADDR_LEN);

  free(eth_src);

  sr_send_packet(sr, icmp_packet, len, iface->name);

}

void sr_send_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	/*uint8_t *echo_reply = malloc(len);
	echo_reply = packet;*/
	
  struct sr_icmp_hdr *icmp_header = (struct sr_icmp_hdr *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmp_header->icmp_type = 0;
	icmp_header->icmp_code = 0;
	icmp_header->icmp_sum = calc_icmp_cksum(icmp_header);
	
	struct sr_if *iface = sr_get_interface(sr, interface);
	
  struct sr_ip_hdr *ip_header = (struct sr_ip_hdr *) (packet + sizeof(sr_ethernet_hdr_t));

  uint32_t dest = ip_header->ip_dst;
  
  ip_header->ip_id = 0;
  ip_header->ip_off = 0;
	ip_header->ip_ttl = 64;
	ip_header->ip_dst = ip_header->ip_src;
	ip_header->ip_src = dest;
  ip_header->ip_sum = calc_ip_cksum(ip_header);
	
	printf("given interface: %s \n", interface);

	printf("ip_src interface: %s \n", iface->name);
	print_addr_ip_int(iface->ip);
	
  struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	uint8_t *eth_src = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(eth_src, eth_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

	memcpy(eth_header->ether_shost, eth_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, eth_src, sizeof(uint8_t) * ETHER_ADDR_LEN);

	free(eth_src);
	
	print_hdrs(packet, len);

	sr_send_packet(sr, packet, len, interface);

  /* free(echo_reply); */
	
	printf("sent echo reply \n");
}

/* Send the packet to the given hardware address. Assume the packet already had its TTl decremented, and its checksum updated. Do not free the packet here  */
void sr_nexthop(
	struct sr_instance* sr, 
	uint8_t * packet, 
	unsigned int len, 
	unsigned char mac_addr[ETHER_ADDR_LEN],
	const char *iface)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(len);
  assert(mac_addr);
  
  memcpy(packet, mac_addr, 6);
  sr_send_packet(sr, packet, len, iface); 
  


  }

