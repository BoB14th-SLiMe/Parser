#ifndef IPROTOCOL_PARSER_H
#define IPROTOCOL_PARSER_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

// Forward declaration
class UnifiedWriter;
class AssetManager;
struct UnifiedRecord;

// Packet information structure
struct PacketInfo {
    std::string timestamp;
    std::string flow_id;
    std::string src_mac;
    std::string dst_mac;
    uint16_t eth_type = 0;
    std::string src_ip;
    uint16_t src_port = 0;
    std::string dst_ip;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;
    const unsigned char* payload = nullptr;
    int payload_size = 0;
};

class IProtocolParser {
public:
    virtual ~IProtocolParser();

    virtual std::string getName() const = 0;
    virtual bool isProtocol(const PacketInfo& info) const = 0;
    virtual void parse(const PacketInfo& info) = 0;

    virtual void setUnifiedWriter(UnifiedWriter* writer) = 0;
    virtual void setAssetManager(AssetManager* assetManager) = 0;
    virtual void setDirectBackendCallback(std::function<void(const UnifiedRecord&)> callback) = 0;
};

#endif // IPROTOCOL_PARSER_H