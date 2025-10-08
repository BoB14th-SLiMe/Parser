#include <iostream>
#include <pcap.h>
#include "packet_parser/PacketParser.h"

// pcap_loop 콜백 함수
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    parser->parse(header, packet);
}

int main(int argc, char* argv[]) {
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

    PacketParser parser;

    // pcap_loop를 통해 파일의 모든 패킷을 처리
    // -1은 파일 끝까지 모든 패킷을 처리하라는 의미
    if (pcap_loop(handle, -1, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 3;
    }

    std::cout << "Packet processing finished." << std::endl;

    pcap_close(handle);
    return 0;
}