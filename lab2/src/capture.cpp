#include <pcap.h>
#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <bitset>
#include <iomanip> // Add this line to include the iomanip header file
#include "capture.h"

using namespace std;

uint16_t ip_header::cal_checksum()
{
    uint32_t sum = 0;
    uint16_t *ptr = reinterpret_cast<uint16_t *>(this); // 转成指向16位无符号整数指针，十六位十六位处理
    // 将校验和字段置为0，因为checksum本来也是16位的
    this->Checksum = 0;
    // 将IP首部中的每16位相加
    for (int i = 0; i < sizeof(ip_header) / 2; ++i)
    {
        sum += ntohs(ptr[i]); // noths函数将一个无符号短整型数从网络字节顺序转换为主机字节顺序
    }
    // 把高16位和低16位相加
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // 返回校验和
    return static_cast<uint16_t>(~sum);
}

void ip_header::showIPPacket()
{
    cout << "<---------------开始解析IP层数据包----------------> " << endl;
    cout << "版本号：" << (this->Ver_HLen >> 4) << endl;
    cout << "首部长度：" << (this->Ver_HLen & 0x0F) * 4 << endl;
    cout << "服务类型：" << (int)this->TOS << endl; // 3位的优先级子字段
    // 优先级子字段用于指定数据包的优先级
    switch ((int)this->TOS >> 5)
    {
    case 0:
        cout << "优先级：Routine,数据包不需要特殊处理。" << endl;
        break;
    case 1:
        cout << "优先级：Priority,数据包不需要特殊处理。" << endl;
        break;
    case 2:
        cout << "优先级：Immediate,数据包需要立即处理。" << endl;
        break;
    case 3:
        cout << "优先级：Flash,数据包需要快速处理。" << endl;
        break;
    case 4:
        cout << "优先级：Flash Override,数据包需要立即处理，并覆盖其他数据包的处理。" << endl;
        break;
    case 5:
        cout << "优先级：CRITIC/ECP,数据包是关键数据或网络控制数据，需要最高优先级处理。" << endl;
        break;
    case 6:
        cout << "优先级：Internetwork Control,数据包是网络控制数据，需要高优先级处理。" << endl;
        break;
    case 7:
        cout << "优先级：Network Control,数据包是网络控制数据，需要最高优先级处理。" << endl;
        break;
    }
    cout << "总长度：" << ntohs(this->TotalLen) << endl;
    cout << "标识：" << ntohs(this->ID) << endl;
    cout << "标志：" << bitset<3>(ntohs(this->Flag_Segment) >> 13) << endl;
    cout << "对应标志：保留位、不分片（DF）位和更多分片（MF）位。" << endl;
    cout << "片偏移：" << (ntohs(this->Flag_Segment) & 0x1FFF) << endl;
    cout << "生存时间：" << (int)this->TTL << endl;
    cout << "协议编号：" << (int)this->Protocol << endl;
    switch ((int)this->Protocol)
    {
    case 1:
        cout << "协议类型：ICMP" << endl;
        break;
    case 2:
        cout << "协议类型：IGMP" << endl;
        break;
    case 6:
        cout << "协议类型：TCP" << endl;
        break;
    case 17:
        cout << "协议类型：UDP" << endl;
        break;
    case 58:
        cout << "协议类型：ICMPv6" << endl;
        break;
    case 89:
        cout << "协议类型：OSPF" << endl;
        break;
    case 132:
        cout << "协议类型：SCTP" << endl;
        break;
    case 255:
        cout << "协议类型：RAW" << endl;
        break;
    }
    cout << "首部校验和：" << ntohs(this->Checksum) << endl;
    cout << "验证首部校验和：" << this->cal_checksum() << endl;

    // inet_ntoa() 函数被用于将IP数据包的源IP地址转换为点分十进制的字符串表示
    cout << "源IP地址：" << inet_ntoa(*(struct in_addr *)&this->SrcIP) << endl;
    cout << "目的IP地址：" << inet_ntoa(*(struct in_addr *)&this->DstIP) << endl;
    cout << "<---------------完成IP层数据包解析----------------> " << endl;
}

void analysis_IP(u_char *user_data, const struct pcap_pkthdr *pkInfo, const u_char *packet)
{
    // 参数解释
    //  user_data传递用户定义的数据到回调函数中，通常用不到
    //  pkInfo保存了此数据包的时间信息和长度信息
    //  packet是数据包的内容

    ip_header *ip_protocol;
    ip_protocol = (struct ip_header *)(packet + 14); // 获取IP头，14 是因为以太网帧头部通常是 14 字节

    ip_protocol->showIPPacket();
}

void ether_header::showEtherPacket(ip_header *ip_protocol)
{
    uint16_t type = ntohs(this->Ether_Type);
    cout << "<------------------开始解析以太网帧数据包-------------------> " << endl;
    cout << "目的MAC地址：" << hex << (int)this->Ether_Dhost[0] << ":" << (int)this->Ether_Dhost[1] << ":" << (int)this->Ether_Dhost[2] << ":" << (int)this->Ether_Dhost[3] << ":" << (int)this->Ether_Dhost[4] << ":" << (int)this->Ether_Dhost[5] << endl;
    cout << "源MAC地址：" << hex << (int)this->Ether_Shost[0] << ":" << (int)this->Ether_Shost[1] << ":" << (int)this->Ether_Shost[2] << ":" << (int)this->Ether_Shost[3] << ":" << (int)this->Ether_Shost[4] << ":" << (int)this->Ether_Shost[5] << endl;
    cout << "以太网类型：" << setfill('0') << setw(4) << hex << type << endl;
    switch (type)
    {
    case 0x0800:
        cout << "以太网类型：IPv4" << endl;
        ip_protocol->showIPPacket();
        break;
    case 0x0806:
        cout << "以太网类型：ARP" << endl;
        break;
    case 0x8035:
        cout << "以太网类型：RARP" << endl;
        break;
    case 0x86DD:
        cout << "以太网类型：IPv6" << endl;
        break;
    default:
        cout << "以太网类型：其他" << endl;
        break;
    }
    cout << "<------------------完成以太网帧数据包解析-------------------> " << endl
         << endl;
}

void analysis_Ethernet(u_char *user_data, const struct pcap_pkthdr *pkInfo, const u_char *packet)
{
    ether_header *ethernet_protocol = (struct ether_header *)packet; // 获取以太网帧头部
    ip_header *ip_protocol = (struct ip_header *)(packet + 14);      // 获取以太网帧头部
    ethernet_protocol->showEtherPacket(ip_protocol);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // 参数解释
    //   user_data传递用户定义的数据到回调函数中，通常用不到
    //   pkInfo保存了此数据包的时间信息和长度信息
    //   packet是数据包的内容
    static int packet_count = 0;

    packet_count++;

    cout << "Now Packet Number: " << dec << packet_count << endl;

    analysis_Ethernet(user_data, pkthdr, packet);
}

void showDevice()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息的缓冲
    pcap_if_t *it;                 // pcap_if_t结构体链表，描述网络接口
    int r;

    r = pcap_findalldevs(&it, errbuf); // 获取网络接口列表，结果连接在it后面，返回-1执行失败
    if (r == -1)
    {
        printf("err:%s\n", errbuf);
        exit(-1);
    }

    while (it)
    {
        printf(":%s\n", it->name);

        it = it->next;
    }
}

int main()
{
    pcap_if_t *alldevs, *device;   // 网络适配器列表的指针；pcap_if_t，pcap_if_t结构体链表，描述网络接口
                                   // 包含了接口的名称、描述、地址等信息，但不涉及任何与捕获会话相关的操作。
    pcap_t *adhandle;              // 适配器句柄，代表一个活跃的数据包捕获会话与pcap_if_t不同
    char errbuf[PCAP_ERRBUF_SIZE]; // 用于储存错误消息的缓冲区

    /*
    pcap_if_t 是用于识别和选择网络接口的。
    pcap_t 是用于处理实际的数据包捕获的。*/

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) // 错误消息会存在errbuf中，返回0成功，-1失败
    {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // 显示设备列表
    std::cout << "Available devices are:\n";
    int i = 0;
    for (device = alldevs; device; device = device->next)
    {
        std::cout << ++i << ". " << device->name << " ";
        // 打印有名称的设备
        if (device->description)
            std::cout << "(" << device->description << ")\n";
        else
            std::cout << "(No description available)\n";
    }

    if (i == 0)
    {
        std::cout << "\nNo interfaces found! Make sure pcap is installed.\n";
        return 1;
    }

    // 选择一个设备
    int inum;
    std::cout << "Enter the interface number (1-" << i << "):";
    std::cin >> inum;

    if (inum < 1 || inum > i)
    {
        std::cout << "\nInterface number out of range.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 跳转到选定的适配器
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++)
        ;

    // 打开设备
    // 设备名称、捕获长度、混杂模式（接收所有经过的数据包）、读超时、错误缓冲区
    if ((adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        std::cerr << "\nUnable to open the adapter. " << device->name << " is not supported by pcap\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\nListening on " << device->description << "...\n";

    // 释放设备列表
    pcap_freealldevs(alldevs);

    // 开始捕获
    int packetNum = 0;
    cout << "你想一共捕获多少个数据包";
    cin >> packetNum;
    pcap_loop(adhandle, packetNum, packet_handler, NULL);
    // packet_handler 是一个回调函数，每当捕获到一个数据包时，这个函数都会被调用

    // 关闭句柄
    pcap_close(adhandle);

    return 0;
}
