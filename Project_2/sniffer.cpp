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

void list_interfaces();

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
    char filter_exp[1024];
    string filter;
    int input;
    long int packet_count = 1;      //implicit value of number of packets 1
    bool interface_spec = false;    //was interface specified? if not list interfaces


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
                    exit(1);
                }
                break;
            case '?':
                fprintf(stderr, "invalid option: -%c\n", optopt);
                exit(1);
            case ':':
                if(optopt=='i') {
                    printf("option -%c -list interfaces\n", optopt);
                }else{
                    fprintf(stderr, "option -%c is missing a required argument\n", optopt);
                    exit(1);
                }
            default:
                break;
        }
    }

    //Initialize sniffing
    if(interface_spec){
        //connect to device
        pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err_buf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface, err_buf);
            exit(1);
        }else{
            printf("Sniffing started successfully on interface %s.",interface);
        }

        memset(filter_exp, 0, strlen(filter_exp));
        if(!(filter_tcp && filter_udp && filter_icmp && filter_arp)){
            if(!(!filter_tcp && !filter_udp && !filter_icmp && !filter_arp)){
                if(filter_tcp){
                    strcat(filter_exp, "tcp ");
                }if(filter_udp){
                    strcat(filter_exp, "udp ");
                }if(filter_arp){
                    strcat(filter_exp, "arp ");
                }if(filter_icmp){
                    strcat(filter_exp, "icmp ");
                }
            }
        }
        if(port_spec){
            strcat(filter_exp, "port ");
            strcat(filter_exp, port);
        }
        printf("Filter expression:%s.",filter_exp);


        //Close the session.
        pcap_close(handle);
    }else{
        //List interfaces function
        list_interfaces();
    }
    return(0);
    //TODO: Create filter rules, compile and apply
    //TODO: Primary function loop
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

