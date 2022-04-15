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
#include <bitset>
#include <csignal>
#include <pcap.h>
#include <string>

//packet structure libraries
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <iostream>
using namespace std;

int main(int argc, char **argv) {
    string interface;
    string filter = "tcp";
    char input;
    int port;                       //stores port number
    bool port_spec = false;         //was port specified? if not listen on all ports
    bool interface_spec = false;    //was interface specified? if not list interfaces
    bool filter_tcp = false;
    bool filter_icmp = false;
    bool filter_arp = false;
    bool filter_udp = false;
    int packet_count = 1;           //implicit value of number of packets 1
    while ((input = getopt(argc, argv, ":i:p:n:-:tu")) != -1) {
        switch (input) {
            case 'i':
                printf("Interface: -%s\n", optarg);
                break;
            case 'p':
                printf("Port: -%s\n", optarg);
                break;
            case 'n':
                printf("Number of packets: -%s\n", optarg);
                break;
            case 't':
                printf("Filter show tcp packets.\n");
                break;
            case 'u':
                printf("Filter show udp packets.\n");
                break;
            case '-':
                if(filter.compare(optarg) == 0){
                    printf("Filter show tcp packets.\n");
                }
                break;
            case '?':
                fprintf(stderr, "invalid option: -%c\n", optopt);
                exit(1);
            case ':':
                switch (optopt) {
                    case 'i':
                        printf("option -%c -list interfaces\n", optopt);
                        break;
                    default:
                        fprintf(stderr, "option -%c is missing a required argument\n", optopt);
                        exit(1);
                }
        }
    }
}