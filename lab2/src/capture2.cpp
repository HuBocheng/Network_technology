#include <pcap.h>
#include <iostream>
#include <string>
#include "capture.h" // 假设这个头文件包含了之前提供的代码中的类和函数声明

using namespace std;

uint16_t ip_header::cal_checksum()
{
    uint32_t sum = 0;
    uint16_t *ptr = reinterpret_cast<uint16_t *>(this);
    // 将校验和字段置为0
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
    cout << "===========开始解析IP层数据包======== " << endl;
    cout << "版本号：" << (this->Ver_HLen >> 4) << endl;
    cout << "首部长度：" << (this->Ver_HLen & 0x0F) * 4 << endl;
    cout << "服务类型：" << (int)this->TOS << endl;
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
    cout << "源IP地址：" << inet_ntoa(*(struct in_addr *)&this->SrcIP) << endl;
    cout << "目的IP地址：" << inet_ntoa(*(struct in_addr *)&this->DstIP) << endl;
    cout << "===========完成IP层数据包解析======== " << endl;
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

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    analysis_IP(user_data, pkthdr, packet);
}

int main()
{
    pcap_if_t *alldevs, *device;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
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
    pcap_loop(adhandle, 0, packet_handler, NULL);

    // 关闭句柄
    pcap_close(adhandle);

    return 0;
}
