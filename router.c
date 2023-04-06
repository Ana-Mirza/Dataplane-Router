#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_capacity;
int arp_table_size;

/* Queue for waiting packets */
queue q;

/* Compare function for routing table sort */
int cmp_function(const void *a, const void *b) {
	struct route_table_entry *ob1 = (struct route_table_entry *)a;
	struct route_table_entry *ob2 = (struct route_table_entry *)b;
	uint32_t tmp1 = ob1->prefix & ob1->mask;
	uint32_t tmp2 = ob2->prefix & ob2->mask;

	if (tmp1 != tmp2)
		return tmp1 - tmp2;
	else 
		return ob1->mask - ob2->mask;
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	/* Implement the LPM algorithm using binary search */
	struct route_table_entry *entry = NULL;
	
	int l = 0, r = rtable_len, mid;
	while(l <= r) {
		mid = l + (r - l) / 2;
		uint32_t pref = rtable[mid].prefix & rtable[mid].mask;
		uint32_t dest = ip_dest & rtable[mid].mask;

		if (dest == pref && 
			(entry == NULL || entry->mask < rtable[mid].mask)) {
			entry = &rtable[mid];
			l = mid + 1;
		} else if (dest < pref) {
			r = mid - 1;
		} else {
			l = mid + 1;
		}
	}

	return entry;
}

struct arp_entry *get_arp_entry(uint32_t given_ip)
{
	/*Iterate through the ARP table and search for an entry
	 * that matches given_ip. */
	for (int i = 0; i < arp_table_size; ++i)
	{
		if (arp_table[i].ip == given_ip)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

void arp_request(void *old_packet, int interface)
{
	/* generate ARP request packet */
	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
	char new_arp_packet[MAX_PACKET_LEN];

	/* ether header */
	struct ether_header *eth_hdr = (struct ether_header *)new_arp_packet;
	eth_hdr->ether_type = htons(0x0806);
	get_interface_mac(interface, eth_hdr->ether_shost);
	for (int i = 0; i < 6; i++)
		eth_hdr->ether_dhost[i] = 0xFF;

	/* ARP header */
	struct arp_header *arp_hdr = (struct arp_header *)(eth_hdr + 1);
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr->tha, 0, sizeof(uint8_t) * 6);
	struct iphdr *ip_hdr = (struct iphdr *)(old_packet + sizeof(struct ether_header));
	struct route_table_entry *entry_rtable = get_best_route(ip_hdr->daddr);
	arp_hdr->tpa = entry_rtable->next_hop;

	/* send packet */
	send_to_link(entry_rtable->interface, new_arp_packet, len);
}

void arp(void *old_packet, int len, int interface)
{
	struct arp_header *old_arp_hdr = (struct arp_header *)(old_packet + sizeof(struct ether_header));
	len = sizeof(struct ether_header) + sizeof(struct arp_header);

	/* reply packet */
	if (old_arp_hdr->op == htons(2))
	{
		/* update local ARP cache */
		struct arp_header *arp_hdr = (struct arp_header *)(old_packet + sizeof(struct ether_header));
		arp_table[arp_table_size].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_size].mac, arp_hdr->sha, sizeof(uint8_t) * 6);

		/* check capacity of ARP table */
		arp_table_size++;
		if (arp_table_size == arp_table_capacity)
		{
			void *aux = realloc(arp_table, arp_table_capacity * 2);
			DIE(aux == NULL, "memory");
			arp_table_capacity *= 2;
			arp_table = (struct arp_entry *)aux;
		}

		/* iterate through packets in queue and send ready packets */
		while (!queue_empty(q))
		{
			char *packet = (char *)queue_deq(q);

			struct ether_header *eth_hdr = (struct ether_header *)packet;
			struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
			struct route_table_entry *entry_rtable = get_best_route(ip_hdr->daddr);

			/* update checksum */
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			/* write new address */
			struct arp_entry *entry_arp = get_arp_entry(entry_rtable->next_hop);
			if (entry_arp)
			{
				memcpy(eth_hdr->ether_dhost, entry_arp->mac, sizeof(uint8_t) * 6);

				/* send packet to next hop */
				int packet_len = sizeof(struct ether_header) + sizeof(struct iphdr);
				send_to_link(entry_rtable->interface, packet, packet_len);
				free(packet);
				return;
			}
		}
	}

	/* request packet */
	if (old_arp_hdr->op == htons(1) && old_arp_hdr->tpa == inet_addr(get_interface_ip(interface)))
	{
		/* generate ARP reply packet */
		int len = sizeof(struct ether_header) + sizeof(struct arp_header);
		char new_arp_packet[MAX_PACKET_LEN];

		/* ether header */
		struct ether_header *eth_hdr = (struct ether_header *)new_arp_packet;
		struct ether_header *old_eth_hdr = (struct ether_header *)old_packet;
		eth_hdr->ether_type = htons(0x0806);
		get_interface_mac(interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, sizeof(uint8_t) * 6);

		/* ARP header */
		struct arp_header *arp_hdr = (struct arp_header *)(eth_hdr + 1);
		arp_hdr->htype = htons(1);
		arp_hdr->ptype = htons(0x0800);
		arp_hdr->hlen = 6;
		arp_hdr->plen = 4;
		arp_hdr->op = htons(2);
		memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
		arp_hdr->spa = inet_addr(get_interface_ip(interface));
		memcpy(arp_hdr->tha, old_arp_hdr->sha, sizeof(uint8_t) * 6);
		arp_hdr->tpa = old_arp_hdr->spa;

		/* send packet */
		send_to_link(interface, new_arp_packet, len);
		return;
	}
}

void icmp(uint8_t type, void *old_packet, int error, int interface)
{
	/* build icmp packet */
	int len = 0;
	char new_icmp_packet[MAX_PACKET_LEN];

	/* ethernet header */
	struct ether_header *eth_hdr = (struct ether_header *)new_icmp_packet;
	struct ether_header *old_eth_hdr = (struct ether_header *)old_packet;
	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, sizeof(u_int8_t) * 6);
	memcpy(eth_hdr->ether_shost, old_eth_hdr->ether_dhost, sizeof(u_int8_t) * 6);
	eth_hdr->ether_type = htons(0x0800);

	/* ipv4 header */
	struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);
	memset(ip_hdr, 0, sizeof(struct iphdr));
	struct iphdr *old_ip_hdr = (struct iphdr *)(old_eth_hdr + 1);
	memcpy(&ip_hdr->daddr, &old_ip_hdr->saddr, sizeof(uint32_t));
	memcpy(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(uint32_t));
	ip_hdr->ihl = 5;
	ip_hdr->id = htons(1);
	ip_hdr->version = 4;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->ttl = 64;
	ip_hdr->protocol = 1;

	/* icmp header */
	struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + 1);
	memset(icmp_hdr, 0, sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	/* error message body */
	if (error)
	{
		len = 8;
		memcpy((icmp_hdr + 1), old_ip_hdr, sizeof(struct iphdr));
		memcpy(((icmp_hdr + 1) + sizeof(struct iphdr)), (struct icmphdr *)(old_ip_hdr + 1) + 1, 8);
		ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	}

	/* echo message body */
	if (!error)
	{
		struct icmphdr *old_icmp = (struct icmphdr *)(old_ip_hdr + 1);
		icmp_hdr->un.echo.id = old_icmp->un.echo.id;
		icmp_hdr->un.echo.sequence = old_icmp->un.echo.sequence;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	}
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* send icmp packet */
	len += sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	send_to_link(interface, new_icmp_packet, len);
}

void ipv4(void *old_packet, int packet_len, int interface)
{
	/* check destination and send icmp */
	char *packet = malloc(packet_len);
	memcpy(packet, old_packet, packet_len);
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	/* check chekcsum */
	uint16_t my_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	uint16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	if (new_checksum != my_checksum)
	{
		/* drop packet */
		return;
	}

	/* update ttl */
	if (ip_hdr->ttl <= 1)
	{
		icmp(11, packet, 1, interface);
		return;
	}
	ip_hdr->ttl--;

	/* echo icmp request */
	if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
	{
		icmp(0, packet, 0, interface);
		return;
	}

	/* search in route table */
	struct route_table_entry *entry_rtable = get_best_route(ip_hdr->daddr);
	if (!entry_rtable)
	{
		icmp(3, packet, 1, interface);
		return;
	}

	/* update checksum */
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* write new address */
	struct arp_entry *entry_arp = get_arp_entry(entry_rtable->next_hop);
	get_interface_mac(entry_rtable->interface, eth_hdr->ether_shost);

	/* sent arp request packet if mac not found in ARP table */
	if (!entry_arp)
	{
		queue_enq(q, packet);
		arp_request(packet, entry_rtable->interface);
		return;
	}
	memcpy(eth_hdr->ether_dhost, entry_arp->mac, sizeof(uint8_t) * 6);

	/* send packet to next hop */
	send_to_link(entry_rtable->interface, packet, packet_len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	/* Do not modify this line */
	init(argc - 2, argv + 2);

	/* Code to allocate the ARP and route tables */
	rtable = malloc(sizeof(rtable) * 800000);
	DIE(rtable == NULL, "memory");

	arp_table_capacity = 100;
	arp_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	// arp_entry_len = parse_arp_table("arp_table.txt", arp_entr);

	/* code to allocate the queue */
	q = queue_create();

	/* sort the route table */
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmp_function);

	while (1)
	{

		int interface;
		size_t len;

		/* receive packet */
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		/* bad protocol */
		uint16_t ether_type = ntohs(eth_hdr->ether_type);
		if (ether_type != 0x0800 && ether_type != 0x0806)
			continue;

		/* bad destination address */
		int cont = 0;
		uint8_t mac[6];
		get_interface_mac(interface, mac);
		for (int i = 0; i < 6; i++)
		{
			if (eth_hdr->ether_dhost[i] != mac[i] &&
				eth_hdr->ether_dhost[i] != 0xFF)
				cont = 1;
		}

		if (cont)
			continue;

		/* ipv4 packet */
		if (ether_type == 0x0800)
		{
			ipv4(buf, len, interface);
			continue;
		}

		/* arp packet */
		if (ether_type == 0x0806)
		{
			arp(buf, len, interface);
			continue;
		}
	}

	free(rtable);
	free(arp_table);
}
