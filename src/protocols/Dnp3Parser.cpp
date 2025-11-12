#include "Dnp3Parser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <sstream>

Dnp3Parser::~Dnp3Parser() {}

std::string Dnp3Parser::getName() const {
    return "dnp3";
}

bool Dnp3Parser::isProtocol(const PacketInfo& info) const {
    return (info.protocol == 6 || info.protocol == 17) &&  // TCP or UDP
           (info.dst_port == 20000 || info.src_port == 20000) &&
           info.payload_size >= 2 &&
           info.payload[0] == 0x05 &&
           info.payload[1] == 0x64;
}

void Dnp3Parser::parse(const PacketInfo& info) {
    uint8_t len = 0, ctrl = 0;
    uint16_t dest = 0, src = 0;
    std::string direction = "unknown";
    
    if (info.payload_size >= 10) {
        len = info.payload[2];
        ctrl = info.payload[3];
        dest = *(uint16_t*)(info.payload + 4);
        src = *(uint16_t*)(info.payload + 6);
        direction = (ctrl & 0x80) ? "request" : "response";
    }
    
    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set payload length (common field for all protocols)
    record.len = std::to_string(info.payload_size);

    record.dnp3_len = std::to_string(len);
    record.dnp3_ctrl = std::to_string(ctrl);
    record.dnp3_dest = std::to_string(dest);
    record.dnp3_src = std::to_string(src);
    
    std::stringstream details_ss;
    details_ss << R"({"len":)" << (int)len << R"(,"ctrl":)" << (int)ctrl
               << R"(,"dest":)" << dest << R"(,"src":)" << src << "}";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}