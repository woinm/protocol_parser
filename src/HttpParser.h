/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#ifndef HTTPPARSER_H
#define HTTPPARSER_H

#include "ParserBase.h"
#include <boost/regex.hpp>
#include <map>
#include <string>

namespace protocol {
namespace parser {
namespace http {
struct HttpProtocolInfo : public ProtocolInfo {
  HttpProtocolInfo() {}
  virtual ~HttpProtocolInfo() {}

  std::string method;
  std::string version;
  std::string url;
  std::map<std::string, std::string> headers;

  std::string parameters;
  // std::list<std::string> parameters;
};
typedef std::shared_ptr<HttpProtocolInfo> HttpProtocolInfoPtr;

class HttpParser : public ProtocolInfo {
public:
  HttpParser();
  ~HttpParser();
  /**
   * @brief 协议解码
   *
   * @param data
   * @return ProtocolInfoPtr
   */
  ProtocolInfoPtr decode(const std::string &data);

  /**
   * @brief 打印解析出的http协议内容
   *
   * @param req
   */
  void show(const ProtocolInfoPtr req);

private:
  int protocol_headers(const std::string &data,
                       std::map<std::string, std::string> &headers);

private:
  boost::regex m_http_regex;
  boost::regex m_http_header_regex;
  std::string m_http_parameter_split;
};
} // namespace http
} // namespace parser
} // namespace protocol

#endif // HTTPPARSER_H
