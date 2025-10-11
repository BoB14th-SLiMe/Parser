#include "DnsParser.h"
#include <sstream>
#include <arpa/inet.h>

// --- MODIFICATION: Provide an explicit definition for the destructor ---
DnsParser::~DnsParser() {}

std::string DnsParser::getName() const {
    return "dns";
}

bool DnsParser::isProtocol(const u_char* payload, int size) const {
    // DNS typically uses UDP port 53, minimum header size is 12 bytes.
    // This check is basic as port info is not available here.
    return size >= 12;
}

void DnsParser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    if (info.payload_size >= 12) {
        uint16_t tid = ntohs(*(uint16_t*)(info.payload));
        uint16_t flags = ntohs(*(uint16_t*)(info.payload + 2));
        uint16_t qdcount = ntohs(*(uint16_t*)(info.payload + 4)); // Question count
        uint16_t ancount = ntohs(*(uint16_t*)(info.payload + 6)); // Answer count
        
        details_ss << "{\"tid\":" << tid << ",\"fl\":" << flags
                   << ",\"qc\":" << qdcount << ",\"ac\":" << ancount << "}";
    } else {
        details_ss << "{\"len\":" << info.payload_size << "}";
    }

    writeOutput(info, details_ss.str());
}

