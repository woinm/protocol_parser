/**
 * @author zhouyushuang
 * @date 2023/03/31
 */

#include "src/DnsParser.h"
#include <fstream>
#include <iostream>
#include <unistd.h>

bool read_file_lines(const std::string &file_path,
                     std::list<std::string> &file_line_list) {
  if (::access(file_path.c_str(), F_OK)) {
    return false;
  }
  std::ifstream file_handle(file_path.c_str());
  std::string line;

  if (file_handle) {
    // 文件打开成功，按行读取文件
    while (std::getline(file_handle, line)) {
      file_line_list.push_back(line);
    }
  } else {
    return false;
  }
  file_handle.close();
  return true;
}

u_char *hex_to_bin(u_char *dst, u_char *src, size_t len) {
  // 16进制字符串的长度一定是偶数，因为一个字节的高低4位被分别转换成了一个16进制字符
  // 也就是一个2进制字节数据一定对应两个16进制字符，一个字符一个字节，因此是偶数倍
  if (NULL == src || len & 0x01) {
    return (u_char *)NULL;
  }
  u_char t;
  while (len) {
    t = *src++;
    if (t < '0' || t > '9') {
      t = (t >= 'A' && t <= 'F') ? (t | 0x20) : t;
      if (t >= 'a' && t <= 'f') {
        t = t - 'a' + 10; // 需要将字符转换成数值
      } else {
        return (u_char *)NULL;
      }
    } else {
      t = t - '0';
    }
    // 从0位开始计算，奇数位为字节低位，偶数位为字节高位
    if (len-- & 0x01) {
      *dst |= (t & 0x0f);
      dst++;
    } else {
      *dst = (t & 0x0f) << 4;
    }
  }
  return dst;
}

int main(int argc, char *argv[]) {

  // 从文件加载dns码流
  std::list<std::string> dns_protocols;
  if (!read_file_lines("dns_protocol.txt", dns_protocols)) {
    return 0;
  }

  protocol::parser::dns::DnsParser dp;
  for (auto data : dns_protocols) {
    std::string hex_code(data.size() / 2, 0x0);
    u_char *tmp = hex_to_bin((u_char *)hex_code.c_str(), (u_char *)data.c_str(),
                             data.size());
    auto resp = dp.decode(hex_code);
    dp.show(resp);
  }

  //   std::cout << "Hello world!!!" << std::endl;
  return 0;
}
