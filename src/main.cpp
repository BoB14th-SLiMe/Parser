#include <iostream>
#include <pcap.h>
#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    // (수정) 파서에 패킷의 전체 길이를 전달
    parser->parse(packet, header->caplen);
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
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }
    
    // (추가) 파싱 종료 후, 알려지지 않은 프로토콜의 프로파일링 결과를 파일로 저장
    parser.save_profiles();

    std::cout << "Deep Packet Inspection and Profiling complete." << std::endl;
    pcap_close(handle);
    return 0;
}

