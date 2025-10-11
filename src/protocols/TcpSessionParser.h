#ifndef TCP_SESSION_PARSER_H
#define TCP_SESSION_PARSER_H

#include <string>
#include <sstream>
#include <cstdint>

class TcpSessionParser {
public:
    TcpSessionParser();
    ~TcpSessionParser();

    // Generates a simple JSON string from TCP session information.
    std::string parse(uint32_t seq, uint32_t ack, uint8_t flags) const;
    
    // Returns the name of the parser.
    std::string getName() const;
};

#endif // TCP_SESSION_PARSER_H

