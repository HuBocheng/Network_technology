#pragma once
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include "pcap.h"
#include <time.h>
#define DATASIZE 128 // ICMP报文数据段大小
using namespace std;
#pragma pack(1)

class Ethernet_header // 14字节
{
public:
    uint8_t DstMAC[6];  // 目的MAC
    uint8_t SrcMAC[6];  // 源MAC
    uint16_t FrameType; // 类型/长度字段
};

class Arp_frame
{
public:
    Ethernet_header frameHeader;
    uint16_t HardwareType;  // 硬件类型
    uint16_t Protocol;      // 协议类型
    uint8_t HardwareAddLen; // 硬件地址长度
    uint8_t ProtocolAddLen; // 协议地址长度
    uint16_t OperationType; // 操作类型
    uint8_t SrcMAC[6];      // 源MAC
    uint32_t SourceIp;      // 源IP
    uint8_t DstMAC[6];      // 目的MAC
    uint32_t DestIp;        // 目的IP
};

class IP_header // 20字节
{
public:
    uint8_t IP_header_length : 4, IP_version : 4; // 首部长度（低4位） 版本号（高4位）
    uint8_t Tos;                                  // 服务类型
    uint16_t TotalLen;                            // 总长度
    uint16_t Id;                                  // 标识
    uint16_t Flag_segment;                        // 标志3 + 片偏移13
    uint8_t TTL;                                  // 生存时长
    uint8_t Protocol;                             // 协议
    uint16_t Checksum;                            // 校验和
    uint32_t SrcIP;                               // 源地址
    uint32_t DstIP;                               // 目的地址
};

class ICMP // 14+20+8+128字节
{
public:
    Ethernet_header EntherHeader;
    IP_header IPHeader;
    uint8_t type;        // ICMP消息类型
    uint8_t code;        // ICMP代码
    uint16_t checksum;   // 校验和
    uint16_t identifier; // 标识符
    uint16_t sequence;   // 序列号
    char dataBuf[DATASIZE];
};

#pragma pack(1)
class ICMPTimeExceededResponse // 14+20+8+20+8字节
{
public:
    Ethernet_header ethernetHeader; // 以太网帧头
    IP_header ipHeader;             // IP头
    uint8_t type;                   // ICMP消息类型，对于超时响应为11
    uint8_t code;                   // ICMP代码，对于超时响应为0
    uint16_t checksum;              // 校验和
    uint32_t unused;                // 未使用字段，通常为0
    uint8_t originalIPHeader[20];   // 原始IP头部（假设没有选项字段）
    uint8_t originalData[8];        // 原始数据包的前8个字节

    ICMPTimeExceededResponse()
    {
        memset(this, 0, sizeof(*this));
    }

    void setup(const ICMP &originalPacket)
    {
        // 打印originalPacket的

        memcpy(ethernetHeader.DstMAC, originalPacket.EntherHeader.SrcMAC, 6);
        memcpy(ethernetHeader.SrcMAC, originalPacket.EntherHeader.DstMAC, 6);
        ethernetHeader.FrameType = htons(0x0800); // IP类型

        // 设置IP头部
        ipHeader.IP_version = 4;
        ipHeader.IP_header_length = 5;
        ipHeader.Tos = 0;
        ipHeader.TotalLen = htons(sizeof(IP_header) + sizeof(ICMPTimeExceededResponse));
        ipHeader.Id = 9999; // 可以随机生成或使用特定值
        ipHeader.Flag_segment = 0;
        ipHeader.TTL = 128;                             // 默认TTL
        ipHeader.Protocol = 1;                          // ICMP
        ipHeader.Checksum = 0;                          // 初始化为0，稍后计算
        ipHeader.SrcIP = originalPacket.IPHeader.DstIP; // 使用路由器的IP地址
        ipHeader.DstIP = originalPacket.IPHeader.SrcIP;

        // 设置ICMP头部
        type = 11;    // 超时响应类型
        code = 0;     // 超时代码
        checksum = 0; // 初始化为0，稍后计算
        unused = 0;

        // 包含原始IP头部和数据包的前8个字节
        memcpy(originalIPHeader, &originalPacket.IPHeader, sizeof(originalPacket.IPHeader)); // 复制原始IP头部
        // memcpy(originalData, &originalPacket, 8);  //这个不对啊啊啊啊啊                     // 只复制ICMP头部的前8个字节
        memcpy(originalData, &originalPacket.type, 8);
    }

    void send(pcap_t *dev)
    {
        // 发送逻辑
        // ...
    }
};
