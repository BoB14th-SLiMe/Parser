#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include <string>
#include "pcap.h"

class ArpParser {
public:
    ArpParser();
    ~ArpParser();
    
    // --- MODIFICATION: Ensure signature takes 2 arguments ---
    std::string parse(const u_char* arp_payload, int size);

private:
    std::string mac_to_string(const uint8_t* mac);
};

#endif // ARP_PARSER_H

