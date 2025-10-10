#include "UnknownParser.h"
#include <sstream>

std::string UnknownParser::getName() const {
    return "unknown";
}

bool UnknownParser::isProtocol(const u_char* payload, int size) const {
    // This parser should be called last and handles any packet.
    return true;
}

void UnknownParser::parse(const PacketInfo& info) {
    std::stringstream details_ss;
    details_ss << "{\"len\":" << info.payload_size << "}";

    // Corrected function call
    writeOutput(info, details_ss.str());
}

