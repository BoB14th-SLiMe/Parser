#ifndef UNIFIED_WRITER_H
#define UNIFIED_WRITER_H

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <mutex>
#include <ctime>
#include <functional>

// 통합 레코드 구조체
struct UnifiedRecord {
    // 공통 필드
    std::string timestamp;
    std::string protocol;
    std::string smac;
    std::string dmac;
    std::string sip;
    std::string sp;
    std::string dip;
    std::string dp;
    std::string sq;
    std::string ak;
    std::string fl;
    std::string dir;

    // 자산 정보
    std::string src_asset_id;
    std::string src_asset_name;
    std::string src_asset_group;
    std::string src_asset_location;
    std::string dst_asset_id;
    std::string dst_asset_name;
    std::string dst_asset_group;
    std::string dst_asset_location;

    // 프로토콜별 상세 정보 (JSON 형태)
    std::string details_json;
    
    // ARP
    std::string arp_op;
    std::string arp_tmac;
    std::string arp_tip;
    
    // DNS
    std::string dns_tid;
    std::string dns_fl;
    std::string dns_qc;
    std::string dns_ac;
    
    // DNP3
    std::string dnp3_len;
    std::string dnp3_ctrl;
    std::string dnp3_dest;
    std::string dnp3_src;
    
    // Generic/Unknown
    std::string len;
    
    // Modbus TCP
    std::string modbus_tid;
    std::string modbus_fc;
    std::string modbus_err;
    std::string modbus_bc;
    std::string modbus_addr;
    std::string modbus_qty;
    std::string modbus_val;
    std::string modbus_regs_addr;
    std::string modbus_regs_val;
    std::string modbus_translated_addr;
    std::string modbus_description;
    
    // S7Comm
    std::string s7_prid;
    std::string s7_ros;
    std::string s7_fn;
    std::string s7_ic;
    std::string s7_syn;
    std::string s7_tsz;
    std::string s7_amt;
    std::string s7_db;
    std::string s7_ar;
    std::string s7_addr;
    std::string s7_rc;
    std::string s7_len;
    std::string s7_description;
    
    // XGT FEnet
    std::string xgt_prid;
    std::string xgt_companyId;
    std::string xgt_plcinfo;
    std::string xgt_cpuinfo;
    std::string xgt_source;
    std::string xgt_len;
    std::string xgt_fenetpos;
    std::string xgt_cmd;
    std::string xgt_dtype;
    std::string xgt_blkcnt;
    std::string xgt_errstat;
    std::string xgt_errinfo;
    std::string xgt_vars;
    std::string xgt_datasize;
    std::string xgt_data;
    std::string xgt_translated_addr;
    std::string xgt_description;
};

class UnifiedWriter {
public:
    UnifiedWriter(const std::string& output_dir, int interval_minutes);
    ~UnifiedWriter();
    
    // 레코드 추가 (스레드 안전)
    void addRecord(const UnifiedRecord& record);
    
    // 파일 플러시 및 로테이션
    void flush();
    
    // 백엔드 전송 콜백 설정 (추가)
    void setBackendCallback(std::function<void(const UnifiedRecord&)> callback) {
        m_backend_callback = callback;
    }

private:
    std::string m_output_dir;
    int m_interval_minutes;
    
    // 시간 슬롯별로 레코드 저장
    std::map<std::string, std::vector<UnifiedRecord>> m_time_slots;
    std::mutex m_mutex;
    
    // 백엔드 전송 콜백 (추가)
    std::function<void(const UnifiedRecord&)> m_backend_callback;
    
    // 타임스탬프로부터 시간 슬롯 계산
    std::string getTimeSlot(const std::string& timestamp);
    
    // 시간 슬롯별 파일 작성
    void writeTimeSlot(const std::string& time_slot);
    
    // CSV/JSONL 헤더 작성
    void writeCsvHeader(std::ofstream& out);
    
    // CSV 이스케이프
    std::string escapeCSV(const std::string& s);
};

#endif // UNIFIED_WRITER_H