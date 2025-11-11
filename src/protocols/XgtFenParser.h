#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h"
#include <chrono>
#include <cstdint>
#include <vector>
#include <string>

struct XgtFenHeader {
    std::string companyId;
    uint16_t reserved1;
    uint16_t plcInfo;
    uint8_t cpuInfo;
    uint8_t sourceOfFrame;
    uint16_t invokeId;
    uint16_t length;
    uint8_t fenetPosition;
    uint8_t reserved2;
};

struct XgtFenInstruction {
    uint16_t command;
    uint16_t dataType;
    bool is_continuous;
    uint16_t reserved;
    uint16_t blockCount;
    std::vector<std::pair<uint16_t, std::string>> variables;
    std::string variableName;
    uint16_t dataSize;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> writeData;
    uint16_t errorStatus = 0;
    uint16_t errorInfoOrBlockCount = 0;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> readData;
    std::vector<uint8_t> continuousReadData;
};

class XgtFenParser : public BaseProtocolParser {
public:
    explicit XgtFenParser(AssetManager& assetManager);
    ~XgtFenParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

private:
    AssetManager& m_assetManager;
    bool parseHeader(const u_char* payload, size_t size, XgtFenHeader& header);
    bool parseInstruction(const u_char* instruction_payload, size_t instruction_size, const XgtFenHeader& header, XgtFenInstruction& instruction);
    std::string bytesToHexString(const uint8_t* bytes, size_t size);
};

template <typename T>
T read_le(const u_char* buffer);

#endif // XGT_FEN_PARSER_H