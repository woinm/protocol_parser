/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#include "DnsParser.h"
#include <__config>
#include <arpa/inet.h>
#include <cstddef>
#include <iostream>
#include <memory>
namespace protocol {
namespace parser {
namespace dns {
std::string inet_n2p(unsigned char addr[], int family) {
  if (nullptr == addr)
    return "";

  char buffer[INET6_ADDRSTRLEN];
  memset(buffer, 0x0, INET6_ADDRSTRLEN);

  size_t buffer_len = AF_INET6 == family ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN;
  const char *ptr = ::inet_ntop(family, (void *)addr, buffer, buffer_len);
  if (nullptr == ptr) {
    return "";
  }
  return buffer;
}

DnsParser::DnsParser() {
  // TODO:
}

DnsParser::~DnsParser() {
  // TODO:
}

ProtocolInfoPtr DnsParser::decode(const std::string &data) {
  size_t decode_length = 0;
  int decode_result = 0;
  DnsProtocolInfoPtr dns_protocol;

  if (data.size() < sizeof(DnsHeader)) {
    return dns_protocol;
  }

  dns_protocol = std::make_shared<DnsProtocolInfo>();
  dns_protocol->protocol_type = EN_DNS_PROTOCOL;

  // 解析dns协议头
  memcpy(&(dns_protocol->dns_header), data.c_str(), sizeof(DnsHeader));
  decode_length += sizeof(DnsHeader);

  // 解析查询列表
  decode_result = querys_decode(htons(dns_protocol->dns_header.question_count),
                                data.c_str(), data.size(), decode_length,
                                dns_protocol->dns_questions);
  if (EN_DECODE_SUCCESS != decode_result) {
    dns_protocol->decode_status = decode_result;
    std::cout << "Invalid code stream decoding querys failed, error code: "
              << decode_result << std::endl;
    return dns_protocol;
  }

  // 解析回答列表
  for (int index = 0; index < EN_RESOURCE_RECORD; ++index) {
    decode_result = resource_record_decode(
        htons(dns_protocol->dns_header.resource_record_count[index]),
        data.c_str(), data.size(), decode_length,
        dns_protocol->dns_resource_records[index]);
    if (decode_result < 0) {
      dns_protocol->decode_status = decode_result;
      std::cout << "Invalid code stream decoding resource record failed"
                << ", resource record type: " << index
                << ", resource record count: "
                << htons(dns_protocol->dns_header.resource_record_count[index])
                << ", error code: " << decode_result << std::endl;
      return dns_protocol;
    }
  }
  dns_protocol->decode_status = EN_DECODE_SUCCESS;
  // show_dns_protocol(dns_protocol);
  return dns_protocol;
}

void DnsParser::show(const ProtocolInfoPtr req) {
  auto dns_info =
      std::dynamic_pointer_cast<DnsProtocolInfoPtr::element_type>(req);

  if (nullptr == dns_info) {
    return;
  }

  printf("====DNS====\n"
         "id: %u\n"
         "flags: 0x%x \n"
         "QuestionCount: %u \n"
         "answer count: %u \n"
         "AuthorityCount: %u \n"
         "AdditionalCount: %u \n",
         htons(dns_info->dns_header.transaction_id),
         htons(dns_info->dns_header.flags),
         htons(dns_info->dns_header.question_count),
         htons(dns_info->dns_header.resource_record_count[EN_ANSWER]),
         htons(dns_info->dns_header.resource_record_count[EN_AUTHORITY]),
         htons(dns_info->dns_header.resource_record_count[EN_ADDITIONAL]));
  for (DnsQueryList::iterator iter = dns_info->dns_questions.begin();
       dns_info->dns_questions.end() != iter; ++iter) {
    std::cout << (*iter).domain_name
              << ", type: " << htons((*iter).question.question_type)
              << ", class: " << htons((*iter).question.question_class)
              << std::endl;
  }

  for (int index = 0; index < EN_RESOURCE_RECORD; ++index) {
    for (DnsResourceRecordList::iterator iter =
             dns_info->dns_resource_records[index].begin();
         dns_info->dns_resource_records[index].end() != iter; ++iter) {
      std::cout << index << " ==> " << (*iter).domain_name
                << ", type: " << htons((*iter).question.question_type)
                << ", class: " << htons((*iter).question.question_class)
                << ", time: " << (*iter).time2live
                << ", data: " << (*iter).resource_data << std::endl;
    }
  }
  std::cout << "====DNS=====\n" << std::endl;
}

int DnsParser::domain_name_decode(const char *buffer, size_t buffer_length,
                                  size_t offset, std::string &domain_name) {
  int decode_length = 0;
  if (NULL == buffer || offset + sizeof(ReuseAddr) > buffer_length) {
    return -1;
  }

  const char *start_addr = &buffer[offset];
  // 如果域名地址是偏移量非标准域名，通过偏移量将起始地址偏移到真实域名的位置
  ReuseAddr domain_header_addr(start_addr);
  if (domain_header_addr.is_reuse()) {
    offset = domain_header_addr.get_offset();
    if (offset > buffer_length) {
      return -1;
    }
    start_addr = &buffer[offset];
  }
  // www.hello.cn
  // 3www5hello2cn
  // 0x03 0x77 0x77 0x77 0x05 0x68 0x65 0x6c 0x6c 0x6f 0x02 0x63 0x6e 0x00
  // 解析查询名（域名），每个查域名都以0x00结束
  // for(; EN_QUERY_NAME_END_CODE != name_len;)
  while (true) {
    uint8_t name_len = start_addr[decode_length];
    decode_length += 1;
    if (name_len < 0 || name_len > EN_QUERY_NAME_MAX_LEN ||
        (offset + decode_length + name_len > buffer_length)) {
      return -1;
    }
    std::string name(&start_addr[decode_length], name_len);
    domain_name.append(name);
    decode_length += name_len;

    // 域名结束符检查
    if (EN_QUERY_NAME_END_CODE == start_addr[decode_length]) {
      decode_length += 1;
      break;
    }
    // 添加域名分隔符
    domain_name.append(".");

    // 检查域名中是否存在地址引用
    ReuseAddr domain_body_addr(&start_addr[decode_length]);
    if (domain_body_addr.is_reuse()) {
      domain_name_decode(buffer, buffer_length, domain_body_addr.get_offset(),
                         domain_name);
      decode_length += sizeof(domain_body_addr);
      break;
    }
  }

  // 如果域名是地址偏移，只返回偏移自字段的长度
  return (domain_header_addr.is_reuse() ? sizeof(domain_header_addr)
                                        : decode_length);
}

int DnsParser::querys_decode(uint16_t question_count, const char *buffer,
                             size_t buffer_length, size_t &decode_len,
                             DnsQueryList &dns_querys) {
  if (NULL == buffer) {
    return EN_ADDR_ERROR;
  }

  // 域名--查询类型--查询类
  for (uint16_t index = 0; index < question_count; ++index) {
    DnsQuery dns_query;
    // 解析域名
    int result = domain_name_decode(buffer, buffer_length, decode_len,
                                    dns_query.domain_name);
    if (result < 0) {
      return EN_DNS_DOMAIN_NAME_ERROR;
    }
    decode_len += result;

    // 长度校验， 查询类型和查询类各占两字节
    if (decode_len + sizeof(DnsQuestion) > buffer_length) {
      return EN_DNS_QUESTION_ERROR;
    }
    // 解析查询类型和查询类
    memcpy(&(dns_query.question), (void *)&buffer[decode_len],
           sizeof(DnsQuestion));
    decode_len += sizeof(DnsQuestion);
    dns_querys.push_back(dns_query);
  }
  return EN_DECODE_SUCCESS;
}

void DnsParser::resource_data_decode(const char *buffer, size_t buffer_length,
                                     size_t offset, const uint16_t type,
                                     ResourceRecord &resource_record) {
  switch (type) {
  case EN_DNS_QUESTION_A:
    // 如果是ipv4就转换成点分十进制
    if (sizeof(int32_t) == resource_record.data_length) {
      int32_t host = *(int32_t *)&(buffer[offset]);
      //   resource_record.resource_data =
      //   edr3::utils::network::get_address(host);
      resource_record.resource_data =
          inet_n2p((unsigned char *)&(host), AF_INET);
    } else {
      resource_record.resource_data.assign(buffer + offset,
                                           resource_record.data_length);
    }
    break;
  case EN_DNS_QUESTION_AAAA:
    // ipv6
    if (16 == resource_record.data_length) {
      resource_record.resource_data =
          inet_n2p((unsigned char *)&(buffer[offset]), AF_INET6);
      std::cout << "ipv6: " << resource_record.data_length
                << ", addr: " << resource_record.resource_data << std::endl;
    } else {
      resource_record.resource_data.assign(buffer + offset,
                                           resource_record.data_length);
    }
    break;
  case EN_DNS_QUESTION_CNAME:
    if (domain_name_decode(buffer, buffer_length, offset,
                           resource_record.resource_data) < 0) {
      resource_record.resource_data.assign(buffer + offset,
                                           resource_record.data_length);
    }
    break;
  default:
    resource_record.resource_data.assign(buffer + offset,
                                         resource_record.data_length);
    break;
  }
}

int DnsParser::resource_record_decode(uint16_t rr_count, const char *buffer,
                                      size_t buffer_length, size_t &decode_len,
                                      DnsResourceRecordList &dns_querys) {
  if (NULL == buffer || decode_len > buffer_length) {
    return EN_ADDR_ERROR;
  }

  for (uint16_t index = 0; index < rr_count; ++index) {
    // ResourceRecord{域名， 类型(int16)，类(int16)，生存时间(int32)，
    // 资源数据{len, data}}
    ResourceRecord resource_record;
    // 域名解析
    // 当报文中域名重复出现的时候，该字段使用2个字节的偏移指针来表示
    // 例如 0xC0 0x0C ==> 11000000 00001100，
    // 最前面的两个高位(11)是标记位，后14位(000000 00001100 == 12)是偏移量，
    // 12正好是头部的长度，其正好指向Queries区域的查询名字字段
    int count = domain_name_decode(buffer, buffer_length, decode_len,
                                   resource_record.domain_name);
    if (count < 0) {
      return EN_DNS_DOMAIN_NAME_ERROR;
    }
    decode_len += count;

    // 解析查询类型和查询类
    // 长度校验， 查询类型和查询类各占两字节
    if (decode_len + sizeof(DnsQuestion) > buffer_length) {
      return EN_DNS_QUESTION_ERROR;
    }
    memcpy(&(resource_record.question), (void *)(&buffer[decode_len]),
           sizeof(DnsQuestion));
    decode_len += sizeof(DnsQuestion);

    // 解析生存时间
    if (decode_len + sizeof(resource_record.time2live) > buffer_length) {
      return EN_DNS_TIME2LIVE_ERROR;
    }
    resource_record.time2live = htonl(*(uint32_t *)(&buffer[decode_len]));
    decode_len += sizeof(resource_record.time2live);

    // 解析资源数据
    if (decode_len + sizeof(resource_record.data_length) > buffer_length) {
      return EN_DNS_RESOURCE_RECORD_ERROR;
    }
    resource_record.data_length = htons(*(uint16_t *)(&buffer[decode_len]));
    decode_len += sizeof(resource_record.data_length);

    if (decode_len + resource_record.data_length > buffer_length) {
      return EN_DNS_RESOURCE_RECORD_ERROR;
    }
    resource_data_decode(buffer, buffer_length, decode_len,
                         htons(resource_record.question.question_type),
                         resource_record);
    decode_len += resource_record.data_length;

    dns_querys.push_back(resource_record);
  }
  return EN_DECODE_SUCCESS;
}

} // namespace dns
} // namespace parser
} // namespace protocol
