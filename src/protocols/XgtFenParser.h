#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h" // AssetManager 헤더 포함

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
};

#endif // XGT_FEN_PARSER_H
