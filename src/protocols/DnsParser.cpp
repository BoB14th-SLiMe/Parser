#include "DnsParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

DnsParser::~DnsParser() {}

std::string DnsParser::getName() const {
    return "dns";
}

bool DnsParser::isProtocol(const PacketInfo& info) const {
    return info.protocol == 17 &&  // IPPROTO_UDP = 17
           (info.dst_port == 53 || info.src_port == 53) &&
           info.payload_size >= 12;
}

void DnsParser::parse(const PacketInfo& info) {
    if (info.payload_size < 12) return;
    
    uint16_t tid = ntohs(*(uint16_t*)(info.payload));
    uint16_t flags = ntohs(*(uint16_t*)(info.payload + 2));
    uint16_t qdcount = ntohs(*(uint16_t*)(info.payload + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(info.payload + 6));
    
    std::string direction = (flags & 0x8000) ? "response" : "request";

    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set payload length (common field for all protocols)
    record.len = std::to_string(info.payload_size);

    record.dns_tid = std::to_string(tid);
    record.dns_fl = std::to_string(flags);
    record.dns_qc = std::to_string(qdcount);
    record.dns_ac = std::to_string(ancount);
    
    std::stringstream details_ss;
    details_ss << R"({"tid":)" << tid << R"(,"fl":)" << flags
               << R"(,"qc":)" << qdcount << R"(,"ac":)" << ancount << "}";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}