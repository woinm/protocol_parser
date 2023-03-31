/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#include "HttpParser.h"
#include <iostream>

namespace protocol {
namespace parser {
namespace http {
HttpParser::HttpParser()
    : m_http_regex("(\\S+) (\\S+) HTTP/(\\d+.\\d+)"),
      m_http_header_regex("(\\S+): ([\\s\\S]*)"),
      m_http_parameter_split("\r\n\r\n") {
  // TODO:
}

HttpParser::~HttpParser() {
  // TODO:
}

int HttpParser::protocol_headers(const std::string &data,
                                 std::map<std::string, std::string> &headers) {
  int header_count = 0;
#if 0
    std::vector<string> http_headers;
    edr3::utils::string::split(request, "\r\n", http_headers);
    std::vector<string>::iterator iter = http_headers.begin();
    for(; http_headers.end() != iter; ++iter)
    {
        boost::cmatch groups;
        if (boost::regex_search((*iter).c_str(), groups, m_http_header_regex))
        {
            headers[groups[1].str()] = groups[2].str();
            header_count++;
        }
    }
#endif
  return header_count;
}

ProtocolInfoPtr HttpParser::decode(const std::string &data) {
  HttpProtocolInfoPtr http_protocol;
  boost::cmatch groups;
  if (boost::regex_search(data.c_str(), groups, m_http_regex)) {
    http_protocol = std::make_shared<HttpProtocolInfo>();
    http_protocol->protocol_type = EN_HTTP_PROTOCOL;
    http_protocol->method = groups[1].str();
    http_protocol->url = groups[2].str();
    http_protocol->version = groups[3].str();

    size_t index = data.find(m_http_parameter_split.c_str());
    if (index != std::string::npos &&
        (index + m_http_parameter_split.size() != data.size())) {
      http_protocol->parameters =
          data.substr(index + m_http_parameter_split.size(), std::string::npos);
      std::string http_headers = data.substr(0, index);
      protocol_headers(http_headers, http_protocol->headers);
      if (atoi(http_protocol->headers["Content-Length"].c_str()) !=
          http_protocol->parameters.size()) {
        http_protocol->decode_status = EN_INCOMPLETE;
      }
    } else {
      protocol_headers(data, http_protocol->headers);
    }
    http_protocol->decode_status = EN_DECODE_SUCCESS;
  }

  return http_protocol;
}

void HttpParser::show(const ProtocolInfoPtr xx) {
  auto http_req =
      std::dynamic_pointer_cast<HttpProtocolInfoPtr::element_type>(xx);
  if (NULL == http_req) {
    return;
  }
  printf("====HTTP====\n"
         "completion: %d\n"
         "method: %s \n"
         "version: %s \n"
         "url: %s \n"
         "parameters size: %ld \n"
         "Content-Length: %s \n"
         "parameters: %s \n"
         "header size: %ld\n",
         http_req->decode_status, http_req->method.c_str(),
         http_req->version.c_str(), http_req->url.c_str(),
         http_req->parameters.size(),
         http_req->headers["Content-Length"].c_str(),
         http_req->parameters.c_str(), http_req->headers.size());
  std::map<std::string, std::string>::iterator iter = http_req->headers.begin();
  for (; http_req->headers.end() != iter; ++iter) {
    std::cout << iter->first << ": " << iter->second << std::endl;
  }
  std::cout << "====HTTP====\n" << std::endl;
}
} // namespace http
} // namespace parser
} // namespace protocol
