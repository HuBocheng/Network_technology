#pragma once
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include "pcap.h"
#include <time.h>
#define DATASIZE 128 // ICMP�������ݶδ�С
using namespace std;
#pragma pack(1)

class Ethernet_header // 14�ֽ�
{
public:
    uint8_t DstMAC[6];  // Ŀ��MAC
    uint8_t SrcMAC[6];  // ԴMAC
    uint16_t FrameType; // ����/�����ֶ�
};

class Arp_frame
{
public:
    Ethernet_header frameHeader;
    uint16_t HardwareType;  // Ӳ������
    uint16_t Protocol;      // Э������
    uint8_t HardwareAddLen; // Ӳ����ַ����
    uint8_t ProtocolAddLen; // Э���ַ����
    uint16_t OperationType; // ��������
    uint8_t SrcMAC[6];      // ԴMAC
    uint32_t SourceIp;      // ԴIP
    uint8_t DstMAC[6];      // Ŀ��MAC
    uint32_t DestIp;        // Ŀ��IP
};

class IP_header // 20�ֽ�
{
public:
    uint8_t IP_header_length : 4, IP_version : 4; // �ײ����ȣ���4λ�� �汾�ţ���4λ��
    uint8_t Tos;                                  // ��������
    uint16_t TotalLen;                            // �ܳ���
    uint16_t Id;                                  // ��ʶ
    uint16_t Flag_segment;                        // ��־3 + Ƭƫ��13
    uint8_t TTL;                                  // ����ʱ��
    uint8_t Protocol;                             // Э��
    uint16_t Checksum;                            // У���
    uint32_t SrcIP;                               // Դ��ַ
    uint32_t DstIP;                               // Ŀ�ĵ�ַ
};

class ICMP // 14+20+8+128�ֽ�
{
public:
    Ethernet_header EntherHeader;
    IP_header IPHeader;
    uint8_t type;        // ICMP��Ϣ����
    uint8_t code;        // ICMP����
    uint16_t checksum;   // У���
    uint16_t identifier; // ��ʶ��
    uint16_t sequence;   // ���к�
    char dataBuf[DATASIZE];
};

#pragma pack(1)
class ICMPTimeExceededResponse // 14+20+8+20+8�ֽ�
{
public:
    Ethernet_header ethernetHeader; // ��̫��֡ͷ
    IP_header ipHeader;             // IPͷ
    uint8_t type;                   // ICMP��Ϣ���ͣ����ڳ�ʱ��ӦΪ11
    uint8_t code;                   // ICMP���룬���ڳ�ʱ��ӦΪ0
    uint16_t checksum;              // У���
    uint32_t unused;                // δʹ���ֶΣ�ͨ��Ϊ0
    uint8_t originalIPHeader[20];   // ԭʼIPͷ��������û��ѡ���ֶΣ�
    uint8_t originalData[8];        // ԭʼ���ݰ���ǰ8���ֽ�

    ICMPTimeExceededResponse()
    {
        memset(this, 0, sizeof(*this));
    }

    void setup(const ICMP &originalPacket)
    {
        // ��ӡoriginalPacket��

        memcpy(ethernetHeader.DstMAC, originalPacket.EntherHeader.SrcMAC, 6);
        memcpy(ethernetHeader.SrcMAC, originalPacket.EntherHeader.DstMAC, 6);
        ethernetHeader.FrameType = htons(0x0800); // IP����

        // ����IPͷ��
        ipHeader.IP_version = 4;
        ipHeader.IP_header_length = 5;
        ipHeader.Tos = 0;
        ipHeader.TotalLen = htons(sizeof(IP_header) + sizeof(ICMPTimeExceededResponse));
        ipHeader.Id = 9999; // ����������ɻ�ʹ���ض�ֵ
        ipHeader.Flag_segment = 0;
        ipHeader.TTL = 128;                             // Ĭ��TTL
        ipHeader.Protocol = 1;                          // ICMP
        ipHeader.Checksum = 0;                          // ��ʼ��Ϊ0���Ժ����
        ipHeader.SrcIP = originalPacket.IPHeader.DstIP; // ʹ��·������IP��ַ
        ipHeader.DstIP = originalPacket.IPHeader.SrcIP;

        // ����ICMPͷ��
        type = 11;    // ��ʱ��Ӧ����
        code = 0;     // ��ʱ����
        checksum = 0; // ��ʼ��Ϊ0���Ժ����
        unused = 0;

        // ����ԭʼIPͷ�������ݰ���ǰ8���ֽ�
        memcpy(originalIPHeader, &originalPacket.IPHeader, sizeof(originalPacket.IPHeader)); // ����ԭʼIPͷ��
        // memcpy(originalData, &originalPacket, 8);  //������԰���������                     // ֻ����ICMPͷ����ǰ8���ֽ�
        memcpy(originalData, &originalPacket.type, 8);
    }

    void send(pcap_t *dev)
    {
        // �����߼�
        // ...
    }
};
