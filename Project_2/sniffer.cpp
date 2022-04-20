//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $sniffer $sniffer.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-04-15
//============================================================================//
/**
 * @file        sniffer.cpp
 * @author      Lucia Makaiová
 *
 * @brief
 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <time.h>

#include <getopt.h>
#include <csignal>
#include <pcap.h>
#include <cstring>

//packet structure libraries
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include<iostream>
using namespace std;
#define BUFFER_SIZE 1024
#define FAILURE 1
#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86DD
#define ICMP 1
#define TCP 6
#define UDP 17


void list_interfaces();
void print_data(const u_char *packet, int length, char *packet_data);

bool filter_tcp = false;
bool filter_icmp = false;
bool filter_arp = false;
bool filter_udp = false;
bool port_spec = false; //was port specified? if not listen on all ports
char *port;//stores port number

int main(int argc, char **argv) {
    char err_buf[PCAP_ERRBUF_SIZE];
    char *end;
    char *interface;
    char filter_exp[BUFFER_SIZE];
    string filter;
    int input;
    long int packet_count = 1;      //implicit value of number of packets 1
    bool interface_spec = false;    //was interface specified? if not list interfaces
    struct ether_header *ether_packet;
    int protocol;

    //process command line arguments
    while ((input = getopt(argc, argv, ":i:p:n:-:tu")) != -1) {
        switch (input) {
            case 'i':
                printf("Interface: -%s\n", optarg);
                interface = optarg;
                interface_spec = true;
                printf("Interface: -%s\n", interface);
                break;
            case 'p':
                printf("Port: -%s\n", optarg);
                port_spec = true;
                port = optarg; //strtol(optarg, &end, 10); //TODO check if successful
                break;
            case 'n':
                printf("Number of packets: -%s\n", optarg);
                packet_count = strtol(optarg, &end, 10);//TODO check if successful
                break;
            case 't':
                printf("Filter show tcp packets.\n");
                filter_tcp = true;
                break;
            case 'u':
                printf("Filter show udp packets.\n");
                filter_udp = true;
                break;
            case '-':
                filter = optarg;
                if(filter == "tcp"){
                    printf("Filter show tcp packets.\n");
                    filter_tcp = true;
                }else if(filter == "udp"){
                    printf("Filter show udp packets.\n");
                    filter_udp = true;
                }else if(filter == "icmp"){
                    printf("Filter show icmp packets.\n");
                    filter_icmp = true;
                }else if(filter == "arp"){
                    printf("Filter show arp packets.\n");
                    filter_arp = true;
                }else{
                    fprintf(stderr, "invalid long option: --%s\n", optarg);
                    exit(FAILURE);
                }
                break;
            case '?':
                fprintf(stderr, "invalid option: -%c\n", optopt);
                exit(FAILURE);
            case ':':
                if(optopt=='i') {
                    printf("option -%c -list interfaces\n", optopt);
                }else{
                    fprintf(stderr, "option -%c is missing a required argument\n", optopt);
                    exit(FAILURE);
                }
            default:
                break;
        }
    }

    //Initialize sniffing
    if(interface_spec){
        //connect to device
        pcap_t *session = pcap_open_live(interface, BUFSIZ, 1, 1000, err_buf);
        if (session == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface, err_buf);
            exit(FAILURE);
        }else{
            printf("Sniffing started successfully on interface %s.",interface);
        }

        //find out ichosen interface supports ethernet packets
        if (pcap_datalink(session) != DLT_EN10MB) {
            fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
            return(2);
        }

        //Create filter rules, compile and apply

        //create filter expression
        memset(filter_exp, 0, strlen(filter_exp));
        if(!(filter_tcp && filter_udp && filter_icmp && filter_arp)){
            if(!(!filter_tcp && !filter_udp && !filter_icmp && !filter_arp)){
                if(filter_tcp){
                    strcat(filter_exp, "tcp or ");
                }if(filter_udp){
                    strcat(filter_exp, "udp or ");
                }if(filter_arp){
                    strcat(filter_exp, "arp or ");
                }if(filter_icmp){
                    strcat(filter_exp, "icmp or ");
                }
                filter_exp[strlen(filter_exp)-1] = '\0';
                filter_exp[strlen(filter_exp)-1] = '\0';
                filter_exp[strlen(filter_exp)-1] = '\0';
            }
        }
        if(port_spec){
            strcat(filter_exp, "port ");
            strcat(filter_exp, port);
        }
        printf("Filter expression:%s.",filter_exp);

        //Find out netmask
        bpf_u_int32 mask;		/* The netmask of our sniffing device */
        bpf_u_int32 net;		/* The IP of our sniffing device */

        if (pcap_lookupnet(interface, &net, &mask, err_buf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", interface);
            net = 0;
            mask = 0;
        }

        //compile filter expression
        struct bpf_program compiled_filter;
        if(pcap_compile(session, &compiled_filter, filter_exp, 0, net) == -1){
            fprintf(stderr, "Can't compile filter expression\n");
            exit(FAILURE);
        }

        //set filter to compiled expression
        if(pcap_setfilter(session, &compiled_filter) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(session));
            exit(FAILURE);
        }else{
            printf("Filter expression:%s applied successfully.",filter_exp);
        }

        //TODO: Primary function loop
        const u_char *packet;
        char *packet_data;
        struct pcap_pkthdr packet_header; //TODO: contains packet timestamp and caplen -length of frame in bytes
        packet = pcap_next(session, &packet_header);
        printf("timestamp: %ld.%.6ld\n",packet_header.ts.tv_sec,packet_header.ts.tv_usec);

        //resolve MAC address and frame length
        ether_packet = (struct ether_header *) packet;
        printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ether_packet->ether_shost[0],ether_packet->ether_shost[1],ether_packet->ether_shost[2],ether_packet->ether_shost[3],ether_packet->ether_shost[4],ether_packet->ether_shost[5]);
        printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ether_packet->ether_dhost[0],ether_packet->ether_dhost[1],ether_packet->ether_dhost[2],ether_packet->ether_dhost[3],ether_packet->ether_dhost[4],ether_packet->ether_dhost[5]);
        printf("frame length: %d bytes\n",packet_header.len);

        print_data(packet, (int)packet_header.len, packet_data);

        //resolve src and dst IP addresses
        struct ip *ipv4_packet;
        struct ip6_hdr *ipv6_packet;
        char *src_ip6;
        char *dst_ip6;
        struct ether_arp *arp_packet;
        packet = packet + 14; //cut the ethernet (datalink) header (14 bytes length)

        if(ntohs(ether_packet->ether_type)==ARP){
            arp_packet = (struct ether_arp *) packet;
            printf("src IP: %d.%d.%d.%d\n",arp_packet->arp_spa[0],arp_packet->arp_spa[1],arp_packet->arp_spa[2],arp_packet->arp_spa[3]);
            printf("dst IP: %d.%d.%d.%d\n",arp_packet->arp_tpa[0],arp_packet->arp_tpa[1],arp_packet->arp_tpa[2],arp_packet->arp_tpa[3]);

        }else if(ntohs(ether_packet->ether_type)==IPV4){
            ipv4_packet = (struct ip *) packet;
            printf("src IP: %s\n",inet_ntoa(ipv4_packet->ip_src));
            printf("dst IP: %s\n",inet_ntoa(ipv4_packet->ip_dst));
            printf("version: %d\n",ipv4_packet->ip_p);
            protocol = ipv4_packet->ip_p;
            packet = packet + 4 * ipv4_packet->ip_hl;
        }else if(ntohs(ether_packet->ether_type)==IPV6){
            ipv6_packet = (struct ip6_hdr *) packet;
            printf("src IP: %s\n",inet_ntop(AF_INET6,&(ipv6_packet->ip6_src),src_ip6,INET6_ADDRSTRLEN));
            printf("dst IP: %s\n",inet_ntop(AF_INET6,&(ipv6_packet->ip6_dst),dst_ip6,INET6_ADDRSTRLEN));
        }

        //resolve port numbers
        if(protocol != ICMP){
            if(protocol == UDP){


            }else if(protocol == TCP){
                struct tcphdr *tcp_packet;
                tcp_packet = (struct tcphdr *) packet;
                printf("src port: %hu\n",htons(tcp_packet->th_sport));
                printf("dst port: %hu\n",htons(tcp_packet->th_dport));
            }
        }

        //print_data(packet_data);

        //Close the session.
        pcap_close(session);
    }else{
        //List interfaces function
        list_interfaces();
    }
    return(0);


}
//List interfaces function
void list_interfaces(){
    char err_buf[PCAP_ERRBUF_SIZE];
    printf("List of all interfaces:\n");
    pcap_if_t *device;
    for(pcap_findalldevs(&device,err_buf);device!=NULL;device = device->next){
        printf("%s\n", device->name);
    }
}

void print_data(const u_char *packet, int length, char *packet_data){
    //printf("0x0000:  ");
    char char_format[17] = "";
    //memset(char_format, 0, strlen(char_format));
    int line_number = 0;
    int i;
    for(i = 1; i <= length;i++) {
        if((i-1)%16==0){
            printf("%s",char_format);
            memset(char_format, 0, strlen(char_format));
            //TODO:print shit characters
            printf("\n0x%04d:  ",line_number);
            line_number += 10;
        }
        if (!isprint((char)*packet)){
            char_format[(i-1) % 16] = '.';
        }else{
            char_format[(i-1) % 16] = *packet;
        }
        printf("%02x ", *packet);
        if(i%8==0){
            printf(" ");
        }
        packet +=1;
    }
    if((i-1)%16 != 0){
        printf(" ");
        while((i-1)%16 != 0){
            printf("   ");
            i++;
        }
        printf("%s\n",char_format);
    }
}

