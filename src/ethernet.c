#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    /* Step1: 数据长度检查: 不足以太网头部则丢弃 */
    if (buf->len < sizeof(ether_hdr_t))
        return;

    /* 读取以太网头部，保存源MAC和协议号 */
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint8_t src_mac[NET_MAC_LEN];
    memcpy(src_mac, hdr->src, NET_MAC_LEN);
    uint16_t protocol = hdr->protocol16;
    /* 协议在包中为网络字节序，转换为主机字节序 */
    protocol = swap16(protocol);

    /* Step2: 移除以太网包头 */
    if (buf_remove_header(buf, sizeof(ether_hdr_t)) < 0)
        return;

    /* Step3: 向上层传递数据包 */
    net_in(buf, protocol, src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    /* Step1: 数据长度检查与填充: 如果数据长度不足46字节，填充0 */
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        size_t pad = ETHERNET_MIN_TRANSPORT_UNIT - buf->len;
        if (buf_add_padding(buf, pad) < 0)
            return;
    }

    /* Step2: 添加以太网包头 */
    if (buf_add_header(buf, sizeof(ether_hdr_t)) < 0)
        return;
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    /* Step3: 填写目的MAC地址 */
    memcpy(hdr->dst, mac, NET_MAC_LEN);

    /* Step4: 填写源MAC地址 */
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);

    /* Step5: 填写协议类型(protocol)，在包中为网络字节序 */
    hdr->protocol16 = swap16((uint16_t)protocol);

    /* Step6: 发送数据帧 */
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}