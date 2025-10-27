#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h" // AssetManager 헤더 포함
#include <cstdint>
#include <vector>
#include <string>

// Structure to hold parsed XGT FEnet Header information
struct XgtFenHeader {
    std::string companyId;
    uint16_t reserved1;
    uint16_t plcInfo;
    uint8_t cpuInfo;
    uint8_t sourceOfFrame;
    uint16_t invokeId;
    uint16_t length; // Length of Application Instruction
    uint8_t fenetPosition;
    uint8_t reserved2; // Sometimes referred to as BCC, but seems reserved in examples
};

// Structure to hold parsed XGT FEnet Instruction information
struct XgtFenInstruction {
    uint16_t command;
    uint16_t dataType;
    bool is_continuous; // <<< Added this flag
    uint16_t reserved;
    uint16_t blockCount;
    // For variable read/write
    std::vector<std::pair<uint16_t, std::string>> variables; // Length + Name
    // For continuous read/write
    std::string variableName;
    uint16_t dataSize; // Size for continuous read request, or total data size in response
    // For individual write
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> writeData; // Length + Data
    // For read response
    uint16_t errorStatus = 0; // Initialize to 0 (success)
    uint16_t errorInfoOrBlockCount = 0; // Depends on errorStatus
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> readData; // Length + Data for individual read response
    std::vector<uint8_t> continuousReadData; // Data for continuous read response
};


class XgtFenParser : public BaseProtocolParser {
public:
    // AssetManager 참조를 받는 생성자
    explicit XgtFenParser(AssetManager& assetManager);
    ~XgtFenParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    AssetManager& m_assetManager; // AssetManager 참조 저장

    // Helper functions for parsing
    bool parseHeader(const u_char* payload, size_t size, XgtFenHeader& header);
    bool parseInstruction(const u_char* instruction_payload, size_t instruction_size, const XgtFenHeader& header, XgtFenInstruction& instruction);
    std::string bytesToHexString(const uint8_t* bytes, size_t size);
};

// Helper function to read little-endian values
template <typename T>
T read_le(const u_char* buffer);

#endif // XGT_FEN_PARSER_H

