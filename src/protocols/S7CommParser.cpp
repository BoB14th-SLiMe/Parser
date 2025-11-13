#include "S7CommParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

S7CommParser::S7CommParser(AssetManager& assetManager)
    : m_assetManager(assetManager),
      m_last_cleanup(std::chrono::steady_clock::now()) {}

S7CommParser::~S7CommParser() {}

static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

static uint32_t s7_addr_to_int(const u_char* ptr) {
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

std::string S7CommParser::getName() const {
    return "s7comm";
}

bool S7CommParser::isProtocol(const PacketInfo& info) const {
    // TCP port 102 check
    if (info.protocol != 6 || (info.dst_port != 102 && info.src_port != 102)) {
        return false;
    }

    // Minimum length check (TPKT 4 + COTP min 2 + S7comm 10 = 16 bytes)
    if (info.payload_size < 16) {
        return false;
    }

    // TPKT version check (RFC 1006)
    if (info.payload[0] != 0x03) {
        return false;
    }

    // TPKT reserved byte should be 0x00
    if (info.payload[1] != 0x00) {
        return false;
    }

    // COTP Length Indicator (LI field) - at byte[4]
    uint8_t cotp_hdr_len = info.payload[4];

    // S7comm PDU starts after: TPKT (4 bytes) + LI byte (1) + COTP header
    int s7_offset = 4 + 1 + cotp_hdr_len;

    // Check if S7comm PDU exists after COTP header
    if (info.payload_size < s7_offset + 10) {
        return false;
    }

    // S7comm Protocol ID check (0x32)
    if (info.payload[s7_offset] != 0x32) {
        return false;
    }

    // ROSCTR (PDU Type) check: must be 0x01-0x07
    uint8_t rosctr = info.payload[s7_offset + 1];
    if (rosctr < 0x01 || rosctr > 0x07) {
        return false;
    }

    return true;
}

void S7CommParser::parse(const PacketInfo& info) {
    // Periodic cleanup of old requests
    cleanupOldRequests();

    // Parse TPKT and COTP headers to find S7comm PDU offset
    // TPKT: 4 bytes | COTP LI: 1 byte | COTP header: variable
    uint8_t cotp_hdr_len = info.payload[4];
    int s7_offset = 4 + 1 + cotp_hdr_len;

    const u_char* s7_pdu = info.payload + s7_offset;
    int s7_pdu_len = info.payload_size - s7_offset;
    if (s7_pdu_len < 10) return;

    uint16_t pdu_ref = safe_ntohs(s7_pdu + 4);
    uint8_t rosctr = s7_pdu[1];
    uint16_t param_len = safe_ntohs(s7_pdu + 6);
    uint16_t data_len = safe_ntohs(s7_pdu + 8);
    int header_size = (rosctr == 0x01 || rosctr == 0x07) ? 10 : 12;

    bool is_request = (info.dst_port == 102);
    std::string flow_key = generateFlowKey(info, is_request);
    std::string direction;
    S7CommRequestInfo* req_info_ptr = nullptr;

    // Handle all ROSCTR types
    if (rosctr == 0x01) {
        // JOB - Request
        direction = "request";
        S7CommRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        new_req.pdu_ref = pdu_ref;

        if (param_len > 0 && (s7_pdu_len >= 10 + param_len)) {
            const u_char* param = s7_pdu + 10;
            new_req.function_code = param[0];
            if ((new_req.function_code == 0x04 || new_req.function_code == 0x05) && param_len >= 2) {
                uint8_t item_count = param[1];
                new_req.items.resize(item_count);
            }
        }
        m_pending_requests[flow_key][pdu_ref] = new_req;
        req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
    } else if (rosctr == 0x02) {
        // ACK - Acknowledgement without data
        direction = "ack";
        if (m_pending_requests[flow_key].count(pdu_ref)) {
            req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
        }
    } else if (rosctr == 0x03) {
        // ACK_DATA - Response with data
        direction = "response";
        if (m_pending_requests[flow_key].count(pdu_ref)) {
            req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
        }
    } else if (rosctr == 0x07) {
        // USERDATA - Alarms, diagnostics, etc.
        direction = "userdata";
        // Userdata packets don't necessarily have matching requests
    } else {
        // Unknown ROSCTR - skip
        return;
    }

    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set S7Comm datagram length (S7Comm PDU length, not total TCP payload)
    // Total COTP header is 7 bytes, so s7_pdu_len is the S7Comm protocol data length
    record.len = std::to_string(s7_pdu_len);

    record.s7_prid = std::to_string(pdu_ref);
    record.s7_ros = std::to_string(rosctr);

    if (param_len > 0 && (s7_pdu_len >= header_size + param_len)) {
        const u_char* param = s7_pdu + header_size;
        record.s7_fn = std::to_string(param[0]);

        if ((param[0] == 0x04 || param[0] == 0x05) && param_len >= 2) {
            uint8_t item_count = param[1];
            record.s7_ic = std::to_string(item_count);

            const u_char* item_ptr = param + 2;
            for(int i = 0; i < item_count; ++i) {
                if ((item_ptr + 12) > (param + param_len)) break;

                uint8_t area = item_ptr[8];
                uint16_t db_num = 0;
                if (area == 0x84) {
                    db_num = safe_ntohs(item_ptr + 6);
                }
                uint32_t addr = s7_addr_to_int(item_ptr + 9) >> 3;

                if (i == 0) {
                    record.s7_syn = std::to_string(item_ptr[2]);
                    record.s7_tsz = std::to_string(item_ptr[3]);
                    record.s7_amt = std::to_string(safe_ntohs(item_ptr + 4));
                    record.s7_ar = std::to_string(area);
                    record.s7_addr = std::to_string(addr);
                    if (area == 0x84) {
                        record.s7_db = std::to_string(db_num);
                    }

                    std::string translated_addr = m_assetManager.translateS7Address(
                        record.s7_ar, record.s7_db, record.s7_addr);
                    record.s7_description = m_assetManager.getDescription(translated_addr);
                }

                item_ptr += 12;
            }
        }
    }

    if (data_len > 0 && (s7_pdu_len >= header_size + param_len + data_len)) {
        const u_char* data_ptr = s7_pdu + header_size + param_len;

        if (rosctr == 3 && req_info_ptr && !req_info_ptr->items.empty()) {
            const u_char* data_item_ptr = data_ptr;

            for(size_t i = 0; i < req_info_ptr->items.size(); ++i) {
                if ((data_item_ptr + 1) > (data_ptr + data_len)) break;

                uint8_t return_code = data_item_ptr[0];

                if (i == 0) {
                    record.s7_rc = std::to_string(return_code);
                }

                if (return_code == 0xff) {
                    if ((data_item_ptr + 4) > (data_ptr + data_len)) {
                        data_item_ptr++;
                        continue;
                    }
                    uint16_t read_len_bits = safe_ntohs(data_item_ptr + 2);
                    uint16_t read_len_bytes = (read_len_bits + 7) / 8;

                    if (i == 0) {
                        record.s7_len = std::to_string(read_len_bytes);
                    }

                    if((data_item_ptr + 4 + read_len_bytes) <= (data_ptr + data_len)) {
                        data_item_ptr += 4 + read_len_bytes;
                        if (read_len_bytes % 2 != 0) data_item_ptr++;
                    } else {
                        data_item_ptr += 4;
                    }
                } else {
                    data_item_ptr++;
                }
            }
        }
    }

    addUnifiedRecord(record);

    // Clean up matched request
    if (direction == "response" || direction == "ack") {
        m_pending_requests[flow_key].erase(pdu_ref);
    }
}

void S7CommParser::cleanupOldRequests() {
    auto now = std::chrono::steady_clock::now();

    // Cleanup every 60 seconds
    if (std::chrono::duration_cast<std::chrono::seconds>(now - m_last_cleanup).count() < 60) {
        return;
    }

    m_last_cleanup = now;

    // Remove requests older than 60 seconds
    for (auto it = m_pending_requests.begin(); it != m_pending_requests.end(); ) {
        auto& request_map = it->second;

        for (auto req_it = request_map.begin(); req_it != request_map.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - req_it->second.timestamp).count() > 60) {
                req_it = request_map.erase(req_it);
            } else {
                ++req_it;
            }
        }

        // Remove empty flow entries
        if (request_map.empty()) {
            it = m_pending_requests.erase(it);
        } else {
            ++it;
        }
    }
}

std::string S7CommParser::generateFlowKey(const PacketInfo& info, bool is_request) const {
    std::string client_ip, server_ip;
    uint16_t client_port, server_port;

    if (is_request) {
        // Request: src is client, dst is server
        client_ip = info.src_ip;
        client_port = info.src_port;
        server_ip = info.dst_ip;
        server_port = info.dst_port;
    } else {
        // Response: src is server, dst is client
        server_ip = info.src_ip;
        server_port = info.src_port;
        client_ip = info.dst_ip;
        client_port = info.dst_port;
    }

    return client_ip + ":" + std::to_string(client_port) + "->" +
           server_ip + ":" + std::to_string(server_port);
}