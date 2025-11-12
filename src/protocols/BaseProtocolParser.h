#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"
#include <string>
#include <fstream>

// Forward declaration
class UnifiedWriter;
class AssetManager;
struct UnifiedRecord;

class BaseProtocolParser : public IProtocolParser {
public:
    virtual ~BaseProtocolParser();

    static std::string mac_to_string(const uint8_t* mac);

    void setUnifiedWriter(UnifiedWriter* writer) override {
        m_unified_writer = writer;
    }

    // AssetManager 설정
    void setAssetManager(AssetManager* assetManager) {
        m_asset_manager = assetManager;
    }

    // 직접 백엔드 전송을 위한 콜백 설정
    void setDirectBackendCallback(std::function<void(const UnifiedRecord&)> callback) {
        m_direct_backend_callback = callback;
    }

    bool isProtocol(const PacketInfo& info) const override {
        (void)info;
        return false;
    }

protected:
    UnifiedRecord createUnifiedRecord(const PacketInfo& info, const std::string& direction);
    void addUnifiedRecord(const UnifiedRecord& record);
    std::string escape_csv(const std::string& s);

    UnifiedWriter* m_unified_writer = nullptr;
    AssetManager* m_asset_manager = nullptr;
    std::function<void(const UnifiedRecord&)> m_direct_backend_callback;  // 추가
};

#endif // BASE_PROTOCOL_PARSER_H