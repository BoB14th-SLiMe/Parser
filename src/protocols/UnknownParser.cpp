#include "UnknownParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <sstream>

UnknownParser::~UnknownParser() {}

std::string UnknownParser::getName() const {
    return "unknown";
}

bool UnknownParser::isProtocol(const PacketInfo& info) const {
    return true;
}

void UnknownParser::parse(const PacketInfo& info) {
    UnifiedRecord record = createUnifiedRecord(info, "unknown");
    record.len = std::to_string(info.payload_size);
    
    std::stringstream details_ss;
    details_ss << R"({"len":)" << info.payload_size << "}";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}