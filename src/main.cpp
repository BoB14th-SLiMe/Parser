#include <iostream>
#include <pcap.h>
#include "packet_parser/PacketParser.h"
#include "packet_parser/network_headers.h"

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);
    const EthernetHeader* eth_header = (const EthernetHeader*)packet;
    if (ntohs(eth_header->eth_type) == 0x0800) { // IPv4
         parser->parse(packet);
    }
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

    // output/ 디렉토리가 미리 생성되어 있어야 합니다.
    PacketParser parser("output/tcp_packets.csv", "output/udp_packets.csv");

    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&parser)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }

    std::cout << "CSV file generation complete." << std::endl;
    pcap_close(handle);
    return 0;
}