#include "Dnp3Parser.h"
#include <sstream>

std::string Dnp3Parser::getName() const {
    return "dnp3";
}

bool Dnp3Parser::isProtocol(const u_char* payload, int size) const {
    // DNP3 Link Layer Start Bytes: 0x05 0x64
    return size >= 2 && payload[0] == 0x05 && payload[1] == 0x64;
}

void Dnp3Parser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    if (info.payload_size >= 10) { // Minimum link layer header size
        uint8_t len = info.payload[2];
        uint8_t ctrl = info.payload[3];
        uint16_t dest = *(uint16_t*)(info.payload + 4);
        uint16_t src = *(uint16_t*)(info.payload + 6);
        details_ss << "{\"len\":" << (int)len << ",\"ctrl\":" << (int)ctrl 
                   << ",\"dest\":" << dest << ",\"src\":" << src << "}";
    } else {
        details_ss << "{\"len\":" << info.payload_size << "}";
    }
    
    // Corrected function call
    writeOutput(info, details_ss.str());
}

