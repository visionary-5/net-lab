#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return;  // 数据包不完整，丢弃
    }
    
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // Step2: 进行报头检测
    if (ip_hdr->version != IP_VERSION_4) {
        return;  // 版本号不是IPv4，丢弃
    }
    
    uint16_t total_len = swap16(ip_hdr->total_len16);
    if (total_len > buf->len) {
        return;  // 总长度大于实际收到的数据包长度，丢弃
    }
    
    // Step3: 校验头部校验和
    uint16_t original_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t calculated_checksum = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    
    if (original_checksum != calculated_checksum) {
        return;  // 校验和不一致，数据包损坏，丢弃
    }
    
    // 恢复原始校验和
    ip_hdr->hdr_checksum16 = original_checksum;
    
    // Step4: 对比目的IP地址
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;  // 目的IP不是本机，丢弃
    }
    
    // Step5: 去除填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }
    
    // Step6: 去掉IP报头
    buf_remove_header(buf, sizeof(ip_hdr_t));
    
    // Step7: 向上层传递数据包
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) == -1) {
        // 协议不可达，重新加上IP头部并发送ICMP报文
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // Step1: 增加头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // Step2: 填写头部字段
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;  // 首部长度，以4字节为单位
    ip_hdr->tos = 0;  // 服务类型设为0
    ip_hdr->total_len16 = swap16(buf->len);  // 总长度
    ip_hdr->id16 = swap16(id);  // 标识符
    
    // 设置标志和分片偏移
    uint16_t flags_fragment = (offset / IP_HDR_OFFSET_PER_BYTE);  // 偏移以8字节为单位
    if (mf) {
        flags_fragment |= IP_MORE_FRAGMENT;  // 设置MF标志位
    }
    ip_hdr->flags_fragment16 = swap16(flags_fragment);
    
    ip_hdr->ttl = IP_DEFALUT_TTL;  // 生存时间
    ip_hdr->protocol = protocol;  // 上层协议
    
    // 复制源IP和目的IP地址
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    
    // Step3: 计算并填写校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    
    // Step4: 发送数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    static int ip_id = 0;  // IP数据报标识符，从0开始递增
    
    // Step1: 检查数据报包长
    size_t max_payload = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    
    // Step2: 分片处理
    if (buf->len > max_payload) {
        // 需要分片发送
        size_t offset = 0;
        size_t remaining = buf->len;
        
        while (remaining > max_payload) {
            // 初始化分片缓冲区
            buf_t ip_buf;
            buf_init(&ip_buf, max_payload);
            
            // 复制数据
            memcpy(ip_buf.data, buf->data + offset, max_payload);
            
            // 发送分片，mf=1表示还有更多分片
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, offset, 1);
            
            offset += max_payload;
            remaining -= max_payload;
        }
        
        // 发送最后一个分片
        buf_t ip_buf;
        buf_init(&ip_buf, remaining);
        memcpy(ip_buf.data, buf->data + offset, remaining);
        
        // mf=0表示这是最后一个分片
        ip_fragment_out(&ip_buf, ip, protocol, ip_id, offset, 0);
        
        ip_id++;  // 标识符递增
    } else {
        // Step3: 直接发送
        // 不需要分片，直接发送，offset=0, mf=0
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
        ip_id++;  // 标识符递增
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}