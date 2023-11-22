#include <iostream>
#include <pcap.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#define ETHERNET_TYPE_ARP 0x0806  // 以太网帧类型，0x0806表示ARP协议
#define ARP_OPCODE_REQUEST 0x0001 // ARP操作码，1表示ARP请求

// Ethernet header
struct ethernet_header
{
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short type;
};

// ARP header
struct arp_header
{
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_len;
    u_char protocol_len;
    u_short opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

void send_arp_request(pcap_t *adhandle, in_addr local_ip, u_char *local_mac, in_addr target_ip)
{
    u_char packet[sizeof(ethernet_header) + sizeof(arp_header)]; // 数据包内容，大小为以太网帧头部 + ARP帧头部
    // 强转分离出以太网帧头部和ARP帧头部
    ethernet_header *eth = (ethernet_header *)packet;
    arp_header *arp = (arp_header *)(packet + sizeof(ethernet_header));

    // 填充以太网帧头部
    for (int i = 0; i < 6; i++)
    {
        eth->dest_mac[i] = 0xff;        // 广播地址
        eth->src_mac[i] = local_mac[i]; // 本机MAC地址
    }
    eth->type = htons(ETHERNET_TYPE_ARP); // 以太网帧类型

    // 填充ARP帧头部
    arp->hardware_type = htons(1);           // 硬件类型，1表示以太网
    arp->protocol_type = htons(0x0800);      // 协议类型，0x0800表示IP协议
    arp->hardware_len = 6;                   // 硬件地址长度，6表示MAC地址长度
    arp->protocol_len = 4;                   // 协议地址长度，4表示IP地址长度
    arp->opcode = htons(ARP_OPCODE_REQUEST); // ARP操作码，1表示ARP请求
    // 复制到ARP帧头部各个字段
    memcpy(arp->sender_mac, local_mac, 6);
    memcpy(arp->sender_ip, &local_ip.S_un.S_addr, 4);
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, &target_ip.S_un.S_addr, 4);

    if (pcap_sendpacket(adhandle, packet, sizeof(packet)) != 0) // pcap_sendpacket函数发送数据包
    {
        std::cerr << "Error sending the packet: " << pcap_geterr(adhandle) << std::endl;
    }
}

bool receive_arp_response(pcap_t *adhandle, in_addr target_ip, u_char *target_mac)
{
    struct pcap_pkthdr *header;                           // 数据包头部
    const u_char *packet;                                 // 数据包内容
    while (pcap_next_ex(adhandle, &header, &packet) >= 0) // 从 pcap 句柄中读取下一个数据包
    {
        ethernet_header *eth = (ethernet_header *)packet; // 强转为以太网帧头部
        if (ntohs(eth->type) != ETHERNET_TYPE_ARP)
            continue;

        arp_header *arp = (arp_header *)(packet + sizeof(ethernet_header));                         // 强转为ARP帧头部
        if (ntohs(arp->opcode) == 0x0002 && memcmp(arp->sender_ip, &target_ip.S_un.S_addr, 4) == 0) // 如果是ARP响应包且源IP地址是目标IP地址
        {
            memcpy(target_mac, arp->sender_mac, 6); // 拷贝MAC地址到target_mac
            return true;
        }
    }
    return false;
}

int main()
{
    pcap_if_t *alldevs;            // 链接所有网络适配器的信息
    pcap_if_t *d;                  // 当前网络适配器的指针
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲区
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    int i = 0;
    for (d = alldevs; d; d = d->next, ++i)
    {
        std::cout << i << ": " << (d->description ? d->description : "No description") << std::endl;
    }

    std::cout << "Select a device (index): ";
    int devIndex;
    std::cin >> devIndex;
    for (d = alldevs, i = 0; i < devIndex; d = d->next, ++i)
        ;

    pcap_t *adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf); // 打开d->name对应的适配器并返回一个pcap_t类型的指针
    if (adhandle == NULL)
    {
        std::cerr << "Unable to open the adapter: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    IP_ADAPTER_INFO AdapterInfo[16];                          // 网络适配器信息的数组
    DWORD dwBufLen = sizeof(AdapterInfo);                     // 缓冲区
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen); // 获取网络适配器信息，dwstatus表示状态
    if (dwStatus != ERROR_SUCCESS)                            // 等于ERROR_SUCCESS表示成功
    {
        std::cerr << "GetAdaptersInfo failed" << std::endl;
        return 1;
    }

    in_addr local_ip; // 本机IP
    u_char local_mac[6];
    bool found = false;
    // std::cout << "d->name + 8: " << d->name + 12 << std::endl;
    // std::cout << "d->name: " << d->name << std::endl;
    // 遍历所有网络适配器，找到d->name + 12对应的适配器
    for (PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; pAdapterInfo; pAdapterInfo = pAdapterInfo->Next)
    {
        // std::cout << pAdapterInfo->AdapterName << std::endl;
        if (strcmp(pAdapterInfo->AdapterName, d->name + 12) == 0)
        {
            // 拷贝MAC地址
            for (i = 0; i < pAdapterInfo->AddressLength; i++)
            {
                local_mac[i] = pAdapterInfo->Address[i];
                // local_mac[i] = 0xff;
            }
            // 6字节的MAC地址后面跟着2字节的填充，用S_un.S_addr
            local_ip.S_un.S_addr = inet_addr(pAdapterInfo->IpAddressList.IpAddress.String); // 将点分十进制IP地址转换为网络字节序整数
            found = true;
            break;
        }
    }
    if (!found)
    {
        std::cerr << "Failed to find IP and MAC for the selected device" << std::endl;
        return 1;
    }

    std::cout << "Enter target IP: ";
    char target_ip_str[16];
    std::cin >> target_ip_str;
    in_addr target_ip;
    target_ip.S_un.S_addr = inet_addr(target_ip_str); // inet_addr()用于将点分十进制IP地址转换为网络字节序整数
    // target_ip.S_un.S_addr意思是将结构体in_addr中的S_un结构体中的S_addr赋值给target_ip
    // target_ip.S_un.S_addr是一个32位无符号整数，而S_un是一个联合体，S_addr是联合体中的一个成员，所以可以这样赋值
    send_arp_request(adhandle, local_ip, local_mac, target_ip);
    u_char target_mac[6];
    if (receive_arp_response(adhandle, target_ip, target_mac))
    {
        printf("MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_ip_str,
               target_mac[0], target_mac[1], target_mac[2],
               target_mac[3], target_mac[4], target_mac[5]);
    }
    else
    {
        std::cout << "Failed to get MAC address for " << target_ip_str << std::endl;
    }

    pcap_close(adhandle);
    pcap_freealldevs(alldevs);
    return 0;
}
