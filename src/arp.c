#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    *arp_pkt = arp_init_pkt; // 使用初始化模板
    
    // Step3: 设置操作类型为ARP_REQUEST，注意大小端转换
    arp_pkt->opcode16 = swap16(ARP_REQUEST);
    
    // 设置目标IP地址
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    
    // 设置目标MAC地址为全0（未知）
    memset(arp_pkt->target_mac, 0, NET_MAC_LEN);
    
    // Step4: 发送ARP报文（广播）
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step2: 填写ARP报头首部
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    *arp_pkt = arp_init_pkt; // 使用初始化模板
    
    // 设置操作类型为ARP_REPLY，注意大小端转换
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    
    // 设置目标IP地址和MAC地址
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    
    // Step3: 发送ARP报文（单播到请求方）
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据长度
    if (buf->len < sizeof(arp_pkt_t)) {
        // 数据包不完整，丢弃
        return;
    }
    
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // Step2: 报头检查
    // 检查硬件类型是否为以太网
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        return;
    }
    
    // 检查上层协议类型是否为IP
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        return;
    }
    
    // 检查MAC硬件地址长度
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        return;
    }
    
    // 检查IP协议地址长度
    if (arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }
    
    // 检查操作类型（只处理REQUEST和REPLY）
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return;
    }
    
    // Step3: 更新ARP表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    
    // Step4: 查看缓存情况
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip);
    
    if (cached_buf != NULL) {
        // 有缓存：发送缓存的数据包
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        // 删除缓存
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 无缓存：检查是否为针对本机的ARP请求
        if (opcode == ARP_REQUEST && 
            memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            // 是请求本机的ARP请求，发送响应
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // Step1: 查找ARP表
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);
    
    // Step2: 找到对应MAC地址
    if (mac != NULL) {
        // 直接发送给以太网层
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // Step3: 未找到对应MAC地址
        // 判断arp_buf中是否已经有包
        if (map_get(&arp_buf, ip) == NULL) {
            // 没有包，缓存数据包并发送ARP请求
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
        // 如果已有包，不处理（正在等待ARP回应）
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL); //初始化ARP表
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy); //初始化数据包缓冲区
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);                             //注册ARP协议处理函数
    arp_req(net_if_ip); //启动时发送ARP请求，更新本机ARP表
}