#include <iostream>
#include <pcap.h>
#include "PacketParser.h"

// Windows 환경에서 Winsock 초기화를 위한 코드
#ifdef _WIN32
#include <winsock2.h>

// WSAStartup/WSACleanup을 자동으로 처리하기 위한 RAII 클래스
class WinSockInit {
public:
    WinSockInit() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed." << std::endl;
            exit(1);
        }
    }
    ~WinSockInit() {
        WSACleanup();
    }
};
#endif


void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    parser->parse(header, packet);
}

int main(int argc, char* argv[]) {
    // Windows 환경일 경우, main 함수 시작 시 Winsock을 초기화합니다.
    #ifdef _WIN32
        WinSockInit winSockInit;
    #endif

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open pcap file " << argv[1] << ": " << errbuf << std::endl;
        return 2;
    }

    PacketParser parser; // PacketParser 객체 생성
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }
    
    std::cout << "Deep Packet Inspection complete." << std::endl;
    pcap_close(handle);
    return 0;
}
