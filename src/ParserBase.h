/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#ifndef PARSERBASE_H
#define PARSERBASE_H

#include <memory>

namespace protocol {
namespace parser {

enum EProtocolType {
  EN_UNKNOWN_PROTOCOL,
  EN_HTTP_PROTOCOL,
  EN_DNS_PROTOCOL,
};

enum DecodeErrorCode {
  EN_DECODE_SUCCESS = 0,
  EN_DECODE_FAILED = -1, // 失败
  EN_ADDR_ERROR = -2,
  // http
  EN_INCOMPLETE = -3, // 不完整
  // dns
  EN_DNS_DOMAIN_NAME_ERROR = -4,
  EN_DNS_QUESTION_ERROR = -5,
  EN_DNS_TIME2LIVE_ERROR = -6,
  EN_DNS_RESOURCE_RECORD_ERROR = -7,
};

struct ProtocolInfo {
  int protocol_type;
  int decode_status;
  ProtocolInfo()
      : protocol_type(EN_UNKNOWN_PROTOCOL), decode_status(EN_DECODE_FAILED) {}
  virtual ~ProtocolInfo() {}
};
typedef std::shared_ptr<ProtocolInfo> ProtocolInfoPtr;

class CParser {
public:
  CParser() = default;
  ~CParser() = default;

  /**
   * @brief 协议解码
   *
   * @param data
   * @return ProtocolInfoPtr
   */
  virtual ProtocolInfoPtr decode(const std::string &data) = 0;

  /**
   * @brief show 打印解析出的协议内容
   * @param req
   */
  virtual void show(const ProtocolInfoPtr req) = 0;
};
} // namespace parser
} // namespace protocol

#endif // PARSERBASE_H
