#include "./pcap.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int parsing_Eth(const u_char*packet){
	struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr *) packet;

	// tcp 패킷인지 확인
	if(eth_header->ether_type!=0x08){
		return 0;
	}

	// parsing데이터 출력
    printf("Ethernet Header\n");
    printf("   |-Source MAC      : ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x:", eth_header->ether_shost[i]);
    printf("\n");

    printf("   |-Destination MAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++)
        printf("%02x:", eth_header->ether_dhost[i]);
    printf("\n");

	return 1;
}

void parsing_IP(const u_char*packet){
	struct libnet_ipv4_hdr* ipv4_header = (struct libnet_ipv4_hdr *)(packet+sizeof(libnet_ethernet_hdr));
	
	// 데이터 출력
	printf("IP Header\n");
    printf("   |-Source IP        : %s\n", inet_ntoa(ipv4_header->ip_src));
    printf("   |-Destination IP   : %s\n", inet_ntoa(ipv4_header->ip_dst));
}

void parsing_TCP(const u_char*packet){
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr));

	//데이터 출력
	printf("TCP Header\n");
    printf("   |-Source Port        : %u\n", ntohs(tcp_hdr->th_sport));
    printf("   |-Destination Port   : %u\n", ntohs(tcp_hdr->th_dport));
}


void parsing_DATA(const u_char* packet) {
    const u_char* data = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
    int data_len = ntohs(((struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr)))->ip_len) - (sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));

    printf("Data Payload\n");
    printf("   |-data (%d bytes):\n", data_len);

	char Decoded_data[data_len];
    for (int i = 0; i < data_len && i <20; i++) {
        Decoded_data[i] = data[i];
		printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
	printf("\n   |-Decode DATA:  \n");
	printf("%s", Decoded_data);
	printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

void parsing_information(const u_char*packet){
	int is_TCP;
	is_TCP = parsing_Eth(packet);
	if(is_TCP){
		parsing_IP(packet);
		parsing_TCP(packet);
		parsing_DATA(packet);
	}
}

int main(int argc, char* argv[]) {
    //입력값 확인
    if (!parse(&param, argc, argv))
		return -1;

    pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    
    //오류처리 - 잡힌 패킷 없음
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

        //캡쳐한 패킷을 분석
		int res = pcap_next_ex(pcap, &header, &packet);
        //error 처리
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        //파싱 시작
        parsing_information(packet);
	}
	pcap_close(pcap);
}
