#include "ArpParser.h"
#include "../UnifiedWriter.h"
#include "../network/network_headers.h"
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

ArpParser::ArpParser() {}
ArpParser::~ArpParser() {}

std::string ArpParser::getName() const {
    return "arp";
}

bool ArpParser::isProtocol(const PacketInfo& info) const {
    return info.eth_type == 0x0806;
}

void ArpParser::parse(const PacketInfo& info) {
    // size_t로 캐스팅하여 signed/unsigned 비교 경고 제거
    if (static_cast<size_t>(info.payload_size) < sizeof(ARPHeader)) return;

    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(info.payload);

    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (void*)arp_header->spa, spa_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (void*)arp_header->tpa, tpa_str, INET_ADDRSTRLEN);

    uint16_t op_code = ntohs(arp_header->oper);
    std::string sha_str = mac_to_string(arp_header->sha);
    std::string tha_str = mac_to_string(arp_header->tha);

    // Create UnifiedRecord manually to match wireshark_parser's ARP handling
    // wireshark_parser leaves sp/dp empty and sets sq/ak/fl/len to "0" for ARP
    UnifiedRecord record;
    record.timestamp = info.timestamp;
    record.protocol = getName();
    record.smac = info.src_mac;
    record.dmac = info.dst_mac;
    record.sip = "";  // ARP doesn't have IP in the same way
    record.sp = "";   // ARP doesn't have ports
    record.dip = "";
    record.dp = "";
    record.sq = "0";  // ARP doesn't have sequence numbers
    record.ak = "0";  // ARP doesn't have ack numbers
    record.fl = "0";  // ARP doesn't have flags
    record.dir = "unknown";  // wireshark_parser sets ARP dir to "unknown"
    record.len = "0";  // wireshark_parser sets ARP len to "0"
    // Note: ARP packets don't have src_asset/dst_asset in wireshark_parser (no IP layer)

    // Python과 일치: arp.op, arp.smac, arp.sip, arp.tmac, arp.tip
    record.arp_op = std::to_string(op_code);
    record.arp_smac = sha_str;
    record.arp_sip = spa_str;
    record.arp_tmac = tha_str;
    record.arp_tip = tpa_str;

    addUnifiedRecord(record);
}