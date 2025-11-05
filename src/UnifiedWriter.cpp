#include "UnifiedWriter.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

UnifiedWriter::UnifiedWriter(const std::string& output_dir, int interval_minutes)
    : m_output_dir(output_dir), m_interval_minutes(interval_minutes) {
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif
    std::cout << "[INFO] UnifiedWriter initialized with " << interval_minutes << " minute intervals" << std::endl;
}

UnifiedWriter::~UnifiedWriter() {
    if (!m_time_slots.empty()) {
        std::cout << "[WARN] UnifiedWriter destroyed with unflushed data!" << std::endl;
        flush();
    }
}

std::string UnifiedWriter::getTimeSlot(const std::string& timestamp) {
    // timestamp 형식: 2023-05-10T02:24:15.123456Z
    if (timestamp.length() < 19) {
        std::cout << "[WARN] Invalid timestamp format: " << timestamp << std::endl;
        return "";
    }
    
    struct tm tm_time = {};
    std::string ts = timestamp.substr(0, 19);
    
    // 파싱
    sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d",
           &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday,
           &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
    
    tm_time.tm_year -= 1900;
    tm_time.tm_mon -= 1;
    
    // 분을 interval 단위로 내림
    int slot_minute = (tm_time.tm_min / m_interval_minutes) * m_interval_minutes;
    tm_time.tm_min = slot_minute;
    tm_time.tm_sec = 0;
    
    // 출력 형식: output_20230510_0224
    std::stringstream ss;
    ss << "output_"
       << std::setfill('0') << std::setw(4) << (tm_time.tm_year + 1900)
       << std::setfill('0') << std::setw(2) << (tm_time.tm_mon + 1)
       << std::setfill('0') << std::setw(2) << tm_time.tm_mday
       << "_"
       << std::setfill('0') << std::setw(2) << tm_time.tm_hour
       << std::setfill('0') << std::setw(2) << slot_minute;
    
    return ss.str();
}

std::string UnifiedWriter::escapeCSV(const std::string& s) {
    if (s.empty()) return "";
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

void UnifiedWriter::addRecord(const UnifiedRecord& record) {
    std::string time_slot = getTimeSlot(record.timestamp);
    
    if (!time_slot.empty()) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_time_slots[time_slot].push_back(record);
    }
}

void UnifiedWriter::writeCsvHeader(std::ofstream& out) {
    out << "@timestamp,protocol,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,"
        << "arp.op,arp.tmac,arp.tip,"
        << "dns.tid,dns.fl,dns.qc,dns.ac,"
        << "dnp3.len,dnp3.ctrl,dnp3.dest,dnp3.src,"
        << "len,"
        << "modbus.tid,modbus.fc,modbus.err,modbus.bc,modbus.addr,modbus.qty,modbus.val,modbus.regs.addr,modbus.regs.val,modbus.translated_addr,modbus.description,"
        << "s7.prid,s7.ros,s7.fn,s7.ic,s7.syn,s7.tsz,s7.amt,s7.db,s7.ar,s7.addr,s7.rc,s7.len,s7.description,"
        << "xgt.prid,xgt.companyId,xgt.plcinfo,xgt.cpuinfo,xgt.source,xgt.len,xgt.fenetpos,xgt.cmd,xgt.dtype,xgt.blkcnt,xgt.errstat,xgt.errinfo,xgt.vars,xgt.datasize,xgt.data,xgt.translated_addr,xgt.description\n";
}

void UnifiedWriter::writeTimeSlot(const std::string& time_slot) {
    if (m_time_slots[time_slot].empty()) {
        return;
    }
    
    std::vector<UnifiedRecord>& records = m_time_slots[time_slot];
    std::sort(records.begin(), records.end(), 
        [](const UnifiedRecord& a, const UnifiedRecord& b) {
            return a.timestamp < b.timestamp;
        });
    
    // CSV 파일
    std::string csv_filepath = m_output_dir + "/" + time_slot + ".csv";
    std::ofstream csv_out(csv_filepath);
    
    if (!csv_out.is_open()) {
        std::cerr << "[ERROR] Could not open CSV file " << csv_filepath << std::endl;
        return;
    }
    
    writeCsvHeader(csv_out);
    
    // JSONL 파일
    std::string jsonl_filepath = m_output_dir + "/" + time_slot + ".jsonl";
    std::ofstream jsonl_out(jsonl_filepath);
    
    if (!jsonl_out.is_open()) {
        std::cerr << "[ERROR] Could not open JSONL file " << jsonl_filepath << std::endl;
        csv_out.close();
        return;
    }
    
    std::cout << "[INFO] Writing time slot: " << time_slot << " with " << records.size() << " records" << std::endl;
    
    for (const auto& record : records) {
        // CSV 작성
        csv_out << escapeCSV(record.timestamp) << ","
                << escapeCSV(record.protocol) << ","
                << escapeCSV(record.smac) << ","
                << escapeCSV(record.dmac) << ","
                << escapeCSV(record.sip) << ","
                << escapeCSV(record.sp) << ","
                << escapeCSV(record.dip) << ","
                << escapeCSV(record.dp) << ","
                << escapeCSV(record.sq) << ","
                << escapeCSV(record.ak) << ","
                << escapeCSV(record.fl) << ","
                << escapeCSV(record.dir) << ","
                << escapeCSV(record.arp_op) << ","
                << escapeCSV(record.arp_tmac) << ","
                << escapeCSV(record.arp_tip) << ","
                << escapeCSV(record.dns_tid) << ","
                << escapeCSV(record.dns_fl) << ","
                << escapeCSV(record.dns_qc) << ","
                << escapeCSV(record.dns_ac) << ","
                << escapeCSV(record.dnp3_len) << ","
                << escapeCSV(record.dnp3_ctrl) << ","
                << escapeCSV(record.dnp3_dest) << ","
                << escapeCSV(record.dnp3_src) << ","
                << escapeCSV(record.len) << ","
                << escapeCSV(record.modbus_tid) << ","
                << escapeCSV(record.modbus_fc) << ","
                << escapeCSV(record.modbus_err) << ","
                << escapeCSV(record.modbus_bc) << ","
                << escapeCSV(record.modbus_addr) << ","
                << escapeCSV(record.modbus_qty) << ","
                << escapeCSV(record.modbus_val) << ","
                << escapeCSV(record.modbus_regs_addr) << ","
                << escapeCSV(record.modbus_regs_val) << ","
                << escapeCSV(record.modbus_translated_addr) << ","
                << escapeCSV(record.modbus_description) << ","
                << escapeCSV(record.s7_prid) << ","
                << escapeCSV(record.s7_ros) << ","
                << escapeCSV(record.s7_fn) << ","
                << escapeCSV(record.s7_ic) << ","
                << escapeCSV(record.s7_syn) << ","
                << escapeCSV(record.s7_tsz) << ","
                << escapeCSV(record.s7_amt) << ","
                << escapeCSV(record.s7_db) << ","
                << escapeCSV(record.s7_ar) << ","
                << escapeCSV(record.s7_addr) << ","
                << escapeCSV(record.s7_rc) << ","
                << escapeCSV(record.s7_len) << ","
                << escapeCSV(record.s7_description) << ","
                << escapeCSV(record.xgt_prid) << ","
                << escapeCSV(record.xgt_companyId) << ","
                << escapeCSV(record.xgt_plcinfo) << ","
                << escapeCSV(record.xgt_cpuinfo) << ","
                << escapeCSV(record.xgt_source) << ","
                << escapeCSV(record.xgt_len) << ","
                << escapeCSV(record.xgt_fenetpos) << ","
                << escapeCSV(record.xgt_cmd) << ","
                << escapeCSV(record.xgt_dtype) << ","
                << escapeCSV(record.xgt_blkcnt) << ","
                << escapeCSV(record.xgt_errstat) << ","
                << escapeCSV(record.xgt_errinfo) << ","
                << escapeCSV(record.xgt_vars) << ","
                << escapeCSV(record.xgt_datasize) << ","
                << escapeCSV(record.xgt_data) << ","
                << escapeCSV(record.xgt_translated_addr) << ","
                << escapeCSV(record.xgt_description) << "\n";
        
        // JSONL 작성
        jsonl_out << R"({"@timestamp":")" << record.timestamp << R"(",)"
                  << R"("protocol":")" << record.protocol << R"(",)"
                  << R"("sip":")" << record.sip << R"(",)"
                  << R"("dip":")" << record.dip << R"(",)"
                  << R"("sp":)" << record.sp << R"(,)"
                  << R"("dp":)" << record.dp << R"(,)"
                  << R"("sq":)" << record.sq << R"(,)"
                  << R"("ak":)" << record.ak << R"(,)"
                  << R"("fl":)" << record.fl << R"(,)"
                  << R"("dir":")" << record.dir << R"(",)"
                  << R"("d":)" << record.details_json << R"(})" << std::endl;
    }
    
    csv_out.close();
    jsonl_out.close();
    
    std::cout << "[SUCCESS] Written " << records.size() << " records to " << time_slot << std::endl;
}

void UnifiedWriter::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_time_slots.empty()) {
        std::cout << "[INFO] No data to flush" << std::endl;
        return;
    }
    
    std::cout << "[INFO] Flushing UnifiedWriter - " << m_time_slots.size() << " time slots" << std::endl;
    
    for (const auto& slot : m_time_slots) {
        writeTimeSlot(slot.first);
    }
    
    m_time_slots.clear();
    std::cout << "[INFO] Flush complete" << std::endl;
}