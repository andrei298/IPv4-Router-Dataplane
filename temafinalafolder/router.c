#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "list.h"
#include "string.h"
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

struct route_table_entry * rtable;
int rtable_len;
struct rtable_tree * rtable_tree_start_point;
list arp_cache_start_point;

void add_arp_cache (uint32_t ip, uint8_t * mac) {

	struct arp_table_entry * new_entry = (struct arp_table_entry *) malloc (sizeof(struct arp_table_entry));
	new_entry -> ip = ip;
	memcpy(new_entry -> mac, mac, 6);

	list cell = (list) malloc (sizeof(struct cell));
	cell -> next = NULL;
	cell -> element = (void *) new_entry;

	if (arp_cache_start_point == NULL) {

		arp_cache_start_point = cell;

	} else {

		list current_cell = arp_cache_start_point;
		while (current_cell -> next != NULL) current_cell = current_cell -> next;
		current_cell -> next = cell;
	}
}

struct arp_table_entry * search_arp_cache (uint32_t ip) {

	list current_cell = arp_cache_start_point;
	while (current_cell != NULL) {

		if ((((struct arp_table_entry *)(current_cell -> element)) -> ip) == ip) 
		return ((struct arp_table_entry *)(current_cell -> element));
		current_cell = current_cell -> next;
	}

	return NULL;
}

void free_arp_cache (list current_cell) {

	if (current_cell -> next != NULL) free_arp_cache (current_cell -> next);
	free((struct arp_table_entry *) current_cell -> element);
	free(current_cell);
}

void populate_rtable_tree () {

	for (int i = 0; i < rtable_len; i ++) {

		struct rtable_tree * current_node = rtable_tree_start_point;
		uint32_t current_mask = ntohl(rtable[i].mask);
		uint32_t current_prefix = ntohl(rtable[i].prefix);

		int count = 31;
		while ((((current_mask >> count) & 1) == 1) && (count >= 0)) {

			if (((current_prefix >> count) & 1) == 0) {

				if (current_node -> left == NULL) {

					struct rtable_tree * node = (struct rtable_tree *) malloc (sizeof(struct rtable_tree));
					node -> left = NULL;
					node -> right = NULL;
					node -> entry = NULL;

					current_node -> left = node;
					current_node = node;
				
				} else {

					current_node = current_node -> left;
				}
			
			} else {

				if (current_node -> right == NULL) {

					struct rtable_tree * node = (struct rtable_tree *) malloc (sizeof(struct rtable_tree));
					node -> left = NULL;
					node -> right = NULL;
					node -> entry = NULL;

					current_node -> right = node;
					current_node = node;
				
				} else {

					current_node = current_node -> right;
				}
			}

			count --;
		}

		current_node -> entry = &rtable[i];
	}
}
 
struct route_table_entry * get_best_route (uint32_t ip_dest) {

	struct route_table_entry * best_route = NULL;
	struct rtable_tree * current_node = rtable_tree_start_point;
	uint32_t ip_dest_host = ntohl(ip_dest);
	int count = 31;
	if (current_node -> entry != NULL) best_route = current_node -> entry;

	while ((current_node != NULL) && (count >= 0)) {

		if (((ip_dest_host >> count) & 1) == 0) current_node = current_node -> left;
		else current_node = current_node -> right;

		if ((current_node != NULL) && (current_node -> entry != NULL)) best_route = current_node -> entry;
		count --;
	}

	return best_route;

}

void deallocate_rtable_tree (struct rtable_tree * current_node) {

	if (current_node == NULL) return;
	deallocate_rtable_tree (current_node -> left);
	deallocate_rtable_tree (current_node -> right);
	free(current_node);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = (struct route_table_entry *) malloc (80000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);

	rtable_tree_start_point = (struct rtable_tree *) malloc (sizeof(struct rtable_tree));
	rtable_tree_start_point -> left = NULL;
	rtable_tree_start_point -> right = NULL;
	rtable_tree_start_point -> entry = NULL;

	populate_rtable_tree();

	queue packet_queue = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr * e_hdr = (struct ether_hdr *) buf;

		if (e_hdr -> ethr_type == htons(ETHERTYPE_ARP)) {

			struct arp_hdr * arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));
			if ((arp_hdr -> tprotoa) != (inet_addr(get_interface_ip(interface)))) continue;

			if (ntohs(arp_hdr -> opcode) == 1) {

				memcpy(e_hdr ->ethr_dhost, e_hdr -> ethr_shost, 6);
				get_interface_mac(interface, e_hdr -> ethr_shost);
				arp_hdr -> opcode = htons(2);

				arp_hdr -> tprotoa = arp_hdr -> sprotoa;
				memcpy(arp_hdr -> thwa, arp_hdr -> shwa, 6);

				get_interface_mac(interface, arp_hdr -> shwa);
				arp_hdr -> sprotoa = inet_addr(get_interface_ip(interface));

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);

			} else if (ntohs(arp_hdr -> opcode) == 2) {

				add_arp_cache(arp_hdr -> sprotoa, arp_hdr -> shwa);
				uint32_t target_ip = arp_hdr -> sprotoa;
				uint8_t target_mac[6];
				memcpy(target_mac, arp_hdr -> shwa, 6);

				if (queue_empty(packet_queue)) continue;
				else {

					queue new_packet_queue = create_queue();
					while (!queue_empty(packet_queue)) {

						struct packet_in_queue * p = (struct packet_in_queue *) queue_deq(packet_queue);
						struct ether_hdr * e_hdr = (struct ether_hdr *) p -> packet;
						struct ip_hdr * ip_hdr = (struct ip_hdr *) (p -> packet + sizeof(struct ether_hdr));
						struct route_table_entry * best_route = get_best_route(ip_hdr -> dest_addr);

						if (best_route -> next_hop == target_ip) {

							uint8_t source_mac[6];
							get_interface_mac(best_route -> interface, source_mac);
							memcpy(e_hdr -> ethr_shost, source_mac, 6);
							memcpy(e_hdr -> ethr_dhost, target_mac, 6);
							send_to_link(p -> len, p -> packet, best_route -> interface);
							free(p);
						}

						else queue_enq(new_packet_queue, (void *) p);
					}

					packet_queue = new_packet_queue;
				}
			}

			continue;

		}

		struct ip_hdr * ip_hdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));
		struct icmp_hdr * icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
		uint32_t this_router_ip = inet_addr(get_interface_ip (interface));
 
		uint16_t received_checksum = ntohs(ip_hdr -> checksum);
		ip_hdr -> checksum = 0;
		uint16_t verify_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr));

		if (received_checksum != verify_checksum) continue;

		if ((this_router_ip) == (ip_hdr -> dest_addr)) {

			if ((icmp_hdr -> mtype == 8) && (icmp_hdr -> mcode == 0)) {

				char original_header_and_data[MAX_PACKET_LEN];
            	memcpy(original_header_and_data, ip_hdr, sizeof(struct ip_hdr) + 8);
            	size_t old_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
            	size_t new_len = sizeof(struct ip_hdr) + 8;

           		memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), original_header_and_data, sizeof(struct ip_hdr) + 8);

				uint32_t aux = ip_hdr -> source_addr;
				ip_hdr -> source_addr = ip_hdr -> dest_addr;
				ip_hdr -> dest_addr = aux;
				ip_hdr -> ttl = 64;
            	ip_hdr -> tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + new_len);
            	ip_hdr -> proto = 1;
            	ip_hdr -> checksum = 0;
            	ip_hdr -> checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

            	uint8_t eth_aux[6];
           		memcpy(eth_aux, e_hdr -> ethr_shost, 6);
            	memcpy(e_hdr -> ethr_shost, e_hdr -> ethr_dhost, 6);
            	memcpy(e_hdr -> ethr_dhost, eth_aux, 6);

				icmp_hdr -> mtype = 0;
				icmp_hdr -> check = 0;
				icmp_hdr -> check = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmp_hdr) + new_len));

				send_to_link(old_len + new_len, buf, interface);
				continue;
			}
		}

		ip_hdr -> ttl--;

		if (ip_hdr -> ttl == 0) {

			char original_header_and_data[MAX_PACKET_LEN];
            memcpy(original_header_and_data, ip_hdr, sizeof(struct ip_hdr) + 8);
            size_t old_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
            size_t new_len = sizeof(struct ip_hdr) + 8;

            memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), original_header_and_data, sizeof(struct ip_hdr) + 8);

            ip_hdr -> dest_addr = ip_hdr -> source_addr;
            ip_hdr -> source_addr = this_router_ip;
            ip_hdr -> ttl = 64;
            ip_hdr -> tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + new_len);
            ip_hdr -> proto = 1;
            ip_hdr -> checksum = 0;
            ip_hdr -> checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

            uint8_t eth_aux[6];
            memcpy(eth_aux, e_hdr -> ethr_shost, 6);
            memcpy(e_hdr -> ethr_shost, e_hdr -> ethr_dhost, 6);
            memcpy(e_hdr -> ethr_dhost, eth_aux, 6);

            icmp_hdr -> mtype = 11;
			icmp_hdr -> mcode = 0;
            icmp_hdr -> check = 0;
            icmp_hdr -> check = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmp_hdr) + new_len));

			send_to_link(old_len + new_len, buf, interface);
            continue;
		}

		struct route_table_entry * best_route = get_best_route(ip_hdr -> dest_addr);
		if (best_route == NULL) {

            char original_header_and_data[MAX_PACKET_LEN];
            memcpy(original_header_and_data, ip_hdr, sizeof(struct ip_hdr) + 8);
            size_t old_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
            size_t new_len = sizeof(struct ip_hdr) + 8;

            memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), original_header_and_data, sizeof(struct ip_hdr) + 8);

            ip_hdr -> dest_addr = ip_hdr -> source_addr;
            ip_hdr -> source_addr = this_router_ip;
            ip_hdr -> ttl = 64;
            ip_hdr -> tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + new_len);
            ip_hdr -> proto = 1;
            ip_hdr -> checksum = 0;
            ip_hdr -> checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

            uint8_t eth_aux[6];
            memcpy(eth_aux, e_hdr -> ethr_shost, 6);
            memcpy(e_hdr -> ethr_shost, e_hdr -> ethr_dhost, 6);
            memcpy(e_hdr -> ethr_dhost, eth_aux, 6);

            icmp_hdr -> mtype = 3;
			icmp_hdr -> mcode = 0;
            icmp_hdr -> check = 0;
            icmp_hdr -> check = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmp_hdr) + new_len));

            send_to_link(old_len + new_len, buf, interface);
            continue;
		}

		ip_hdr -> checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

		struct arp_table_entry * entry = search_arp_cache(best_route -> next_hop);

		if (entry == NULL) {

			struct packet_in_queue * p = (struct packet_in_queue *) malloc (sizeof(struct packet_in_queue));
			p -> len = len;
			memcpy(p -> packet, buf, len);

			queue_enq(packet_queue, (void *) p);
			e_hdr -> ethr_type = htons(ETHERTYPE_ARP);
			get_interface_mac (best_route -> interface, e_hdr -> ethr_shost);
			memset(e_hdr -> ethr_dhost, 0xFF, 6);

			struct arp_hdr * arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));
			arp_hdr -> hw_type = htons(1);
			arp_hdr -> proto_type = htons(ETHERTYPE_IP);
			arp_hdr -> hw_len = 6;
			arp_hdr -> proto_len = 4;
			arp_hdr -> opcode = htons(1);
			get_interface_mac (best_route -> interface, arp_hdr -> shwa);
			arp_hdr -> sprotoa = inet_addr(get_interface_ip(best_route -> interface));
			arp_hdr -> tprotoa = best_route -> next_hop;
			memset(arp_hdr -> thwa, 0, 6);

			send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, best_route -> interface);
			continue;

		}

		get_interface_mac(best_route -> interface, e_hdr -> ethr_shost);
		memcpy(e_hdr -> ethr_dhost, entry -> mac, 6);
		send_to_link(len, buf,
			best_route -> interface);
	}

	free_arp_cache(arp_cache_start_point);
	deallocate_rtable_tree(rtable_tree_start_point);
	return 0;
}

