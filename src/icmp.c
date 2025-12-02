#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化并封装数据
    buf_init(&txbuf, req_buf->len);
    
    // 复制ICMP数据（包括头部和数据部分）
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    
    // 设置为回显应答类型
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr->code = 0;
    
    // id16和seq16保持不变，直接从请求中复制
    
    // Step2: 填写校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 报头检测
    if (buf->len < sizeof(icmp_hdr_t)) {
        return;  // 数据包不完整，丢弃
    }
    
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    
    // Step2: 查看ICMP类型
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3: 回送回显应答
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写报头
    // ICMP头部 + IP头部 + IP数据报的8个字节
    size_t icmp_data_len = sizeof(ip_hdr_t) + 8;  // IP头部 + 前8字节数据
    buf_init(&txbuf, sizeof(icmp_hdr_t) + icmp_data_len);
    
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    
    // 填写ICMP头部
    icmp_hdr->type = ICMP_TYPE_UNREACH;  // 目的不可达
    icmp_hdr->code = code;  // 协议不可达或端口不可达
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;  // 差错报文中未使用，置0
    icmp_hdr->seq16 = 0;  // 差错报文中未使用，置0
    
    // Step2: 填写数据与校验和
    // 复制IP头部和前8字节数据到ICMP数据部分
    uint8_t *icmp_data = txbuf.data + sizeof(icmp_hdr_t);
    
    // 复制IP头部
    memcpy(icmp_data, recv_buf->data, sizeof(ip_hdr_t));
    
    // 复制IP数据报的前8字节
    size_t data_to_copy = recv_buf->len - sizeof(ip_hdr_t);
    if (data_to_copy > 8) {
        data_to_copy = 8;
    }
    memcpy(icmp_data + sizeof(ip_hdr_t), recv_buf->data + sizeof(ip_hdr_t), data_to_copy);
    
    // 计算校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}