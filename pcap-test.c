#include <pcap.h> // pcap 라이브러리 헤더
#include <stdbool.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;// 네트워크 인터페이스 이름
} Param;

Param param = {
    .dev_ = NULL
};

// Ethernet header
struct ethhdr {
    u_int8_t dst_mac[6]; // dst mac
    u_int8_t src_mac[6]; // src mac
    u_int16_t eth_type; // ether type
};

// IP header
struct iphdr {
    u_int8_t ihl:4, version:4; // IP version and length
    u_int8_t tos; // Type of service
    u_int16_t tot_len; // Total length
    u_int16_t id; // Identification number
    u_int16_t frag_off; // Fragment offset
    u_int8_t ttl; // Time to live
    u_int8_t protocol; // Protocol(TCP, UDP, ICMP, etc.)
    u_int16_t checksum; // IP checksum
    uint8_t src_ip[4]; // Source IP address
    uint8_t dst_ip[4]; // Destination IP address
};

// TCP header
struct tcphdr {
    u_int16_t src_port; // Source Port
    u_int16_t dst_port; // Destination Port
    u_int32_t seq; // Sequence number
    u_int32_t ack_seq; // Acknowledgement number
    u_int16_t flags; // Flags (SYN, ACK, etc.)
    u_int16_t window; // Window size
    u_int16_t check; // TCP checksum
    u_int16_t urg_ptr; // Urgent pointer
};

void print_mac(u_int8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(struct in_addr* ip) {
    printf("%s", inet_ntoa(*ip));
}

void print_payload(const u_char* payload, int len) {
    int i;
    printf("Payload(Data): ");
    for (i = 0; i < len; i++) {
        printf("%02x ", payload[i]);
        if (i == 9) break;  // 최대 10바이트까지 출력
    }
    printf("\n");
}


bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];// 첫 번째 인수를 네트워크 인터페이스 이름으로 설정?!
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))  // 명령행 인수 파싱 실패 시
        return -1;

    print_mac(mac);

    char errbuf[PCAP_ERRBUF_SIZE]; // pcap_open_live() 함수가 실패할 경우 오류 메시지를 저장할 버퍼
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // 네트워크 인터페이스로부터 패킷을 캡처하기 위한 세션 생성
    if (pcap == NULL) { // pcap_open_live() 함수가 실패한 경우
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) { // 패킷 캡처 루프
        struct pcap_pkthdr* header;// 패킷 헤더 구조체 포인터
        const u_char* packet;// 패킷 데이터 버퍼 포인터
        int res = pcap_next_ex(pcap, &header, &packet);// 다음 패킷 캡처
        if (res == 0) continue;// 패킷이 존재하지 않는 경우 다음 패킷으로 건너뛰기
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {// 패킷이 존재하지 않는 경우 다음 패킷으로 건너뛰기
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;// 루프 종료
        }
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcap);
}
