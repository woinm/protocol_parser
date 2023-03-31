/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#ifndef DNSPARSER_H
#define DNSPARSER_H

#include "ParserBase.h"
#include <list>
#include <memory>
#include <string>

namespace protocol {
namespace parser {
namespace dns {

///***DNS*****///
/// \brief The DnsFlags struct
///
enum {
  EN_QUERY_NAME_END_CODE = 0x0, // 规范域名结束符
  EN_QUERY_NAME_MAX_LEN = 63,   // 每段域名最大长度

  // DNS响应资源记录解码类型
  EN_ANSWER = 0,          // 回答列表
  EN_AUTHORITY = 1,       // 授权列表
  EN_ADDITIONAL = 2,      // 额外信息列表
  EN_RESOURCE_RECORD = 3, //
};

/**
 * 查询名或者响应体中ResourceRecord的类型码
 */
enum {
  EN_DNS_QUESTION_A = 1,     // IP地址
  EN_DNS_QUESTION_NS = 2,    // 名字服务器
  EN_DNS_QUESTION_MD = 3,    // a mail destination (Obsolete - use MX)
  EN_DNS_QUESTION_MF = 4,    // a mail forwarder (Obsolete - use MX)
  EN_DNS_QUESTION_CNAME = 5, // 域名
  EN_DNS_QUESTION_PTR = 12,  // 指针记录
  EN_DNS_QUESTION_HNFO = 13, // 主机信息
  EN_DNS_QUESTION_MX = 15,   // 邮件交换记录
  EN_DNS_QUESTION_TXT = 16,  // 邮件交换记录
  EN_DNS_QUESTION_AFSDB =
      18, // Andrew File System）数据库核心的位置，于域名以外的 AFS
          // 客户端常用来联系 AFS 核心。这个记录的子类型是被过时的的
          // DCE/DFS（DCE Distributed File System）所使用。
  EN_DNS_QUESTION_AAAA = 28,  // IPV6地址
  EN_DNS_QUESTION_AXFR = 252, // 对区域转换的请求
  EN_DNS_QUESTION_MAILB =
      253, // A request for mailbox-related records (MB, MG or MR)
  EN_DNS_QUESTION_MAILA =
      254,                  // A request for mail agent RRs (Obsolete - see MX)
  EN_DNS_QUESTION_ANY = 255 // 对所有记录的请求
};

/**
 * @brief The DnsFlags struct dns协议头中flags详细字段
 */
struct DnsFlags {
  uint8_t rd : 1;     // recursion desired
  uint8_t tc : 1;     // truncated message
  uint8_t aa : 1;     // authoritive answer
  uint8_t opcode : 4; // purpose of message
  uint8_t qr : 1;     // query/response flag

  uint8_t rcode : 4; // response code
  uint8_t cd : 1;    // checking disabled
  uint8_t ad : 1;    // authenticated data
  uint8_t z : 1;     // its z! reserved
  uint8_t ra : 1;    // recursion available
};

/**
 * @brief The DnsHeader struct dns协议头
 */
struct DnsHeader {
  uint16_t transaction_id; // identification number
  uint16_t flags;          // dns 标志
  uint16_t question_count; // number of question entries
  uint16_t
      resource_record_count[EN_RESOURCE_RECORD]; // number of respone entries
};

/**
 * @brief The DnsQuestion struct 查询名或者资源记录的类型码以及类
 */
struct DnsQuestion {
  uint16_t question_type;
  uint16_t question_class;
};

/**
 * @brief The DnsQuery struct dsn查询体
 */
struct DnsQuery {
  std::string domain_name;
  struct DnsQuestion question;
};
typedef std::list<DnsQuery> DnsQueryList;

/**
 * @brief The ReuseAddr struct 复用域名格式
 */
#define GET_SHORT_BIT(num, pos) (0x1 == (((num) >> (pos)) & 0x1))
struct ReuseAddr {

  uint16_t reuse_addr;
  bool is_reuse() {
    return (GET_SHORT_BIT(reuse_addr, 15) && GET_SHORT_BIT(reuse_addr, 14));
  }

  uint16_t get_offset() {
    return (reuse_addr ^ (((uint16_t)1 << 15) | ((uint16_t)1 << 14)));
  }

  ReuseAddr(const char *ptr) {
    if (NULL != ptr) {
      reuse_addr = htons(*(uint16_t *)ptr);
    }
  }
};

/**
 * @brief The ResourceRecord struct dsn响应资源记录字段格式
 */
struct ResourceRecord {
  std::string domain_name;
  struct DnsQuestion question;
  uint32_t time2live;
  uint16_t data_length;
  std::string resource_data;
};
typedef std::list<ResourceRecord> DnsResourceRecordList;

/**
 * @brief The DnsProtocolInfo struct dns协议体
 */
struct DnsProtocolInfo : public ProtocolInfo {
  DnsHeader dns_header;       // 协议头
  DnsQueryList dns_questions; // 查询列表
  DnsResourceRecordList
      dns_resource_records[EN_RESOURCE_RECORD]; // 响应资源列表

  DnsProtocolInfo() {}
  virtual ~DnsProtocolInfo() {}
};
typedef std::shared_ptr<DnsProtocolInfo> DnsProtocolInfoPtr;

class DnsParser : public CParser {
public:
  DnsParser();
  ~DnsParser();

  /**
   * @brief dns_protocol_analysis 解析dns协议
   * @param request http 请求内容
   * @param req
   * @return
   */
  ProtocolInfoPtr decode(const std::string &data);

  /**
   * @brief show_http_protocol 打印解析出的http协议内容
   * @brief show_dns_protocol 打印解析出的dns协议内容
   * @param req
   */
  void show(const ProtocolInfoPtr req);

private:
  /**
   * @brief domain_name_decode    解析dns协议中的域名
   * @param buffer                    dns协议码流起始位置
   * @param offset                    域名所在偏移量
   * @param domain_name               域名
   * @return 解析失败返回-1， 解析成功返回域名占用码流长度
   */
  int domain_name_decode(const char *buffer, size_t buffer_length,
                         size_t offset, std::string &domain_name);

  /**
   * @brief dns_querys_decode[in] 解析DNS查询问题列表
   * @param question_count[in]    查询问题数量
   * @param buffer[in]            dns协议码流起始地址
   * @param buffer_length[in]     dns协议码流长度
   * @param decode_len            已经解析完协议的长度(当前偏移量)
   * @param dns_querys[out]       DNS查询问题列表
   * @return  0: 解析成功； 解析失败，错误码
   */
  int querys_decode(uint16_t question_count, const char *buffer,
                    size_t buffer_length, size_t &decode_len,
                    DnsQueryList &dns_querys);

  void resource_data_decode(const char *buffer, size_t buffer_length,
                            size_t offset, const uint16_t type,
                            ResourceRecord &resource_record);

  /**
   * @brief dns_resource_record_decod[in] 解析DNS资源记录列表
   * @param rr_count[in]                  resource record count 资源记录数量
   * @param buffer[in]                    dns协议码流起始地址
   * @param buffer_length[in]             dns协议码流长度
   * @param decode_len                    已经解析完协议的长度(当前偏移量)
   * @param dns_querys[out]               资源记录列表
   * @return  0: 解析成功，解析失败；错误码
   */
  int resource_record_decode(uint16_t rr_count, const char *buffer,
                             size_t buffer_length, size_t &decode_len,
                             DnsResourceRecordList &dns_querys);

private:
};
} // namespace dns
} // namespace parser
} // namespace protocol

#endif // DNSPARSER_H
