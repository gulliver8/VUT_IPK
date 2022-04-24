# IPK Project 2 -packet sniffer
Ipk-sniffer is a C++ application, serving as a network analyser. The application captures packets on a set interface and further processess them. It is also possible to list all the available interfaces or filter captured packets based on protocols they use.

### Running the program

$ Use make to build the program. 
$ Run the program 
  ```
  ./ipk-sniffer [-i interface | --interface interface] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
  ```

  For example.

  ```
  ./ipk-sniffer --interface eth0
  ```

$ Possible arguments to specify program behaviour:
+ -i / interface: where interface specifies name of the interface for packet analyser
+ --interface i : where i specifies name of the interface for packet analyser	
		  without specified interface name, program lists all available interfaces
+ -p port	: used to set port on which sniffer looks for packets
+ -n num	: where num sets number of packets for program to print (implicitly set to 1)
Filtering packets:
+ -u / --udp	: program is going to process packets using UDP protocol
+ -t / --tcp	: program is going to process packets using TCP protocol
+ --icmp	: program is going to process packets using ICMP protocol
+ --arp		: program is going to process packets using ARP protocol
Note: If all filtering arguments are chosen, program behaves as if there wouldn't be any chosen.

## Usage

Usage examples:

  ```
Target:	List active interfaces:
Call:	./ipk-sniffer -i
Output:	List of all interfaces:
	ens33
	lo
	any
	bluetooth-monitor
	nflog
	nfqueue

  ```
  ```
Target:	Print first 3 captured packets which use ICMP protocol:
Call:	./ipk-sniffer -n 3 --icmp
Output:	timestamp: 2022-04-20T18:43:46.866
	src MAC: 00:0c:29:64:af:ce
	dst MAC: 00:50:56:e6:ae:40
	frame length: 98 bytes
	src IP: 192.168.6.128
	dst IP: 142.251.37.110

	0x0000:  00 50 56 e6 ae 40 00 0c  29 64 af ce 08 00 45 00  .PV..@..)d....E.
	0x0010:  00 54 1b d4 40 00 40 01  a3 43 c0 a8 06 80 8e fb  .T..@.@..C......
	0x0020:  25 6e 08 00 0e 50 00 08  00 01 42 38 60 62 00 00  %n...P....B8`b..
	0x0030:  00 00 7b 39 0d 00 00 00  00 00 10 11 12 13 14 15  ..{9............
	0x0040:  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25  .......... !"#$%
	0x0050:  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35  &'()*+,-./012345
	0x0060:  36 37                                             67

	timestamp: 2022-04-20T18:43:46.885
	src MAC: 00:50:56:e6:ae:40
	dst MAC: 00:0c:29:64:af:ce
	frame length: 98 bytes
	src IP: 142.251.37.110
	dst IP: 192.168.6.128

	0x0000:  00 0c 29 64 af ce 00 50  56 e6 ae 40 08 00 45 00  ..)d...PV..@..E.
	0x0010:  00 54 30 91 00 00 80 01  8e 86 8e fb 25 6e c0 a8  .T0.........%n..
	0x0020:  06 80 00 00 16 50 00 08  00 01 42 38 60 62 00 00  .....P....B8`b..
	0x0030:  00 00 7b 39 0d 00 00 00  00 00 10 11 12 13 14 15  ..{9............
	0x0040:  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25  .......... !"#$%
	0x0050:  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35  &'()*+,-./012345
	0x0060:  36 37                                             67

	timestamp: 2022-04-20T18:43:47.867
	src MAC: 00:0c:29:64:af:ce
	dst MAC: 00:50:56:e6:ae:40
	frame length: 98 bytes
	src IP: 192.168.6.128
	dst IP: 142.251.37.110

	0x0000:  00 50 56 e6 ae 40 00 0c  29 64 af ce 08 00 45 00  .PV..@..)d....E.
	0x0010:  00 54 1c 91 40 00 40 01  a2 86 c0 a8 06 80 8e fb  .T..@.@.........
	0x0020:  25 6e 08 00 05 4b 00 08  00 02 43 38 60 62 00 00  %n...K....C8`b..
	0x0030:  00 00 83 3d 0d 00 00 00  00 00 10 11 12 13 14 15  ...=............
	0x0040:  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25  .......... !"#$%
	0x0050:  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35  &'()*+,-./012345
	0x0060:  36 37                                             67

  ```
  ```
Target:	Print packet using UDP protocol captured on port 443 (dst or src): 
Call:	./ipk-sniffer -i ens33 -p 443 -u 
Output:	timestamp: 2022-04-20T18:47:08.967
	src MAC: 00:50:56:c0:00:08
	dst MAC: ff:ff:ff:ff:ff:ff
	frame length: 86 bytes
	src IP: 192.168.6.1
	dst IP: 192.168.6.255
	src port: 57621
	dst port: 57621

	0x0000:  ff ff ff ff ff ff 00 50  56 c0 00 08 08 00 45 00  .......PV.....E.
	0x0010:  00 48 41 2c 00 00 80 11  6b 28 c0 a8 06 01 c0 a8  .HA,....k(......
	0x0020:  06 ff e1 15 e1 15 00 34  3c 65 53 70 6f 74 55 64  .......4.eSpotUd
	0x0030:  70 30 d4 5f 40 51 54 1b  15 ef 00 01 00 04 48 95  p0._@QT.......H.
	0x0040:  c2 03 99 e1 e7 1d 77 71  70 f1 55 4e 33 36 c5 4b  ......wqp.UN36.K
	0x0050:  ce 1c 4a 49 91 38                                 ..JI.8

  ```

## Contributors

*Lucia Makaiová*  [xmakai00]

## Sources

Copyright 2002 Tim Carstens
https://www.tcpdump.org/pcap.html
Copyright © 2000, 2001, 2002, 2007, 2008 Free Software Foundation, Inc. 
https://www.gnu.org/software/libc/manual/html\_node/Example-of-Getopt.html
Copyright 1993 David Metcalfe (david@prism.demon.co.uk)
https://man7.org/linux/man-pages/man3/strftime.3.html
Copyright © 1993–2022 Free Software Foundation, Inc. 
https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
