#include "router.h"
using namespace std;
#define ARP_TIMEOUT 5 // ARP超时时间

pcap_if_t *alldevs;	 // 指向设备链表首部的指针
pcap_t *dev;		 // 选择打开的网卡
uint8_t LocalMac[6]; // 源网卡设备的mac地址
uint8_t DstMac[6];	 // 目的网卡设备的mac地址

char curIp[2][INET_ADDRSTRLEN];	  // 本地IP
char curMask[2][INET_ADDRSTRLEN]; // 掩码

int ARP_count = 0;	// 表项个数
int ICMP_count = 1; // 转发的ICMP数据包个数

int getSrcMac()
{
	cout << "==========正在发送ARP请求获取本机MAC地址==========" << endl;
	struct pcap_pkthdr *pkt_header; // 以太数据包头
	const u_char *pkt_data;			// 以太数据包数据
	Arp_frame arp;					// arp报文
	int flag;
	int ret = 1;

	// 封装ARP
	arp.frameHeader.FrameType = htons(0x0806); // 0x806代表ARP
	memset(arp.frameHeader.DstMAC, 0xff, 6);   // 目的MAC是广播地址
	memset(arp.DstMAC, 0x00, 6);			   // 随便填
	for (int i = 0; i < 6; i++)
	{
		arp.frameHeader.SrcMAC[i] = arp.SrcMAC[i] = 0x11; // 随便填
	}

	arp.HardwareType = htons(1);  // Ethernet
	arp.Protocol = htons(0x0800); // IP
	arp.HardwareAddLen = 6;		  // MAC地址长度为6
	arp.ProtocolAddLen = 4;		  // IP地址长度为4
	arp.OperationType = htons(1); // ARP请求
	arp.SourceIp = inet_addr("10.0.0.1");
	arp.DestIp = inet_addr(curIp[0]);

	// 发包
	pcap_sendpacket(dev, (uint8_t *)&arp, sizeof(Arp_frame));

	// 收包
	time_t start = clock();
	while ((flag = pcap_next_ex(dev, &pkt_header, &pkt_data) >= 0))
	{
		time_t end = clock();
		if ((end - start) / CLOCKS_PER_SEC >= ARP_TIMEOUT)
		{
			cout << "【Error】获取ARP响应超时" << endl;
			ret = -1;
			break;
		}
		if (flag == 0)
		{
			continue;
		}
		else if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) && *(uint16_t *)(pkt_data + 20) == htons(2) && *(uint32_t *)(pkt_data + 28) == arp.DestIp)
		{ // 报文检查是ARP包、arp响应、ip来源正确
			cout << "成功获得自身主机的MAC地址" << endl;
			cout << "自身MAC为: ";
			for (int i = 0; i < 6; i++)
			{
				LocalMac[i] = *(uint8_t *)(pkt_data + 22 + i);
				printf("%02x", LocalMac[i]);
				if (i != 5)
					printf(":");
			}
			cout << endl;
			break;
		}
	}
	if (flag < 0)
	{
		printf("【Error】获取自身MAC失败\n");
		pcap_freealldevs(alldevs);
		ret = -1;
	}

	cout << "==========获取本机MAC地址完毕==========" << endl
		 << endl
		 << endl;
	return ret;
}
// 打开网卡获取本机信息
int getSrcIp()
{
	pcap_if_t *device;	   // 适配器列表
	pcap_addr_t *adhandle; // 适配器句柄
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
		return -1;
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
		for (adhandle = device->addresses; adhandle; adhandle = adhandle->next)
		{
			if (adhandle->addr->sa_family == AF_INET)
			{
				char str[22];
				strcpy(str, inet_ntoa(((struct sockaddr_in *)adhandle->addr)->sin_addr));
				printf("IP地址: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in *)adhandle->netmask)->sin_addr));
				printf("网络掩码: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in *)adhandle->broadaddr)->sin_addr));
				printf("广播地址: %s\n", str);
			}
		}
	}

	if (i == 0)
	{
		std::cout << "\nNo interfaces found! Make sure pcap is installed.\n";
		return 1;
	}

	// 选择网卡
	cout << "\n输入要选择打开的网卡号" << endl;
	int choice;
	int k;
	cin >> choice;
	if (choice < 1 || choice > i)
	{
		printf("【Error】网卡号超出范围\n");
		pcap_freealldevs(alldevs); // 释放设备列表
		return -1;
	}
	for (device = alldevs, k = 0; k < choice - 1; k++)
		device = device->next;

	int j = 0;
	for (adhandle = device->addresses; adhandle; adhandle = adhandle->next)
	{ // 要用二维数组存两个接口IP
		if (adhandle->addr->sa_family == AF_INET)
		{
			strcpy(curIp[j], inet_ntoa(((struct sockaddr_in *)adhandle->addr)->sin_addr));
			strcpy(curMask[j++], inet_ntoa(((struct sockaddr_in *)adhandle->netmask)->sin_addr));
		}
	}

	if ((dev = pcap_open(device->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		printf("【Error】无法打开适配器!请检查设备\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	return 1;
}

// 获取MAC-IP 映射关系(当在缓存表查不到的时候)
int getDstMac(uint32_t DstIp, uint8_t *macDst)
{
	cout << "缓存表中没有找到ARP缓存，正在发送ARP请求索要目标MAC地址" << endl;
	cout << "==========正在发送ARP请求获取目标MAC地址==========" << endl;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	Arp_frame arp;
	int flag;
	int ret = 1;

	// 封装ARP
	arp.frameHeader.FrameType = htons(0x0806);
	memset(arp.frameHeader.DstMAC, 0xff, 6); // 广播全255
	memset(arp.DstMAC, 0x00, 6);			 // 随意
	for (int i = 0; i < 6; i++)
	{
		arp.frameHeader.SrcMAC[i] = arp.SrcMAC[i] = LocalMac[i]; // 源MAC填本机MAC
	}

	arp.HardwareType = htons(1);  // Ethernet
	arp.Protocol = htons(0x0800); // IP
	arp.HardwareAddLen = 6;		  // MAC地址长度为6 MAC
	arp.ProtocolAddLen = 4;		  // IP地址长度为4 IP
	arp.OperationType = htons(1); // arp ARP请求
	arp.SourceIp = inet_addr(curIp[0]);
	arp.DestIp = DstIp;

	// 发包
	pcap_sendpacket(dev, (uint8_t *)&arp, sizeof(Arp_frame));
	cout << ("已经发出ARP请求") << endl;

	// 收包
	time_t start = clock();
	while ((flag = pcap_next_ex(dev, &pkt_header, &pkt_data) >= 0))
	{
		// 等待响应超时 直接退出
		time_t end = clock();
		if ((end - start) / CLOCKS_PER_SEC >= ARP_TIMEOUT)
		{
			printf("【Error】获取ARP响应超时\n");
			ret = -1;
			break;
		}
		if (flag == 0)
		{
			continue; //  break
		}
		else if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) // arp 以太帧的上层协议类型
				 && *(uint16_t *)(pkt_data + 20) == htons(2)   // 响应 arp操作类型
				 && *(uint32_t *)(pkt_data + 28) == arp.DestIp)
		{ // ip来源正确
			cout << ("目标MAC获取成功") << endl;
			cout << ("目标MAC为: ") << endl;
			for (int i = 0; i < 6; i++)
			{
				macDst[i] = *(uint8_t *)(pkt_data + 22 + i);
				printf("%02x", macDst[i]); // 占位符 位宽2 空白补零
				if (i != 5)
					printf(":");
			}
			cout << endl;
			break;
		}
	}
	if (flag < 0 || ret == -1)
	{
		printf("【Error】获取目的MAC失败\n");
		pcap_freealldevs(alldevs);
		ret = -1;
	}

	cout << "==========获取目标MAC地址完毕==========" << endl
		 << endl
		 << endl;
	return ret;
}

// 转发
void packageForward(ICMP &icmp, uint8_t *mac)
{
	ICMP *pack = (ICMP *)&icmp;
	pack->IPHeader.TTL = pack->IPHeader.TTL - 1;			   // 递减TTL
	cout << "TLL减1之后为" << (int)pack->IPHeader.TTL << endl; // test point
	if (pack->IPHeader.TTL <= 0)
	{
		printf("【Error】丢弃报文\n");
		// 创建并发送 ICMP 超时响应
		ICMPTimeExceededResponse *timeExceededResponse = new ICMPTimeExceededResponse();
		timeExceededResponse->setup(*pack);
		timeExceededResponse->ipHeader.SrcIP = inet_addr(curIp[0]);
		setChecksum(timeExceededResponse);
		IP_header *ipHeader = &(timeExceededResponse->ipHeader);
		setChecksum(ipHeader);
		cout << "==========转发报文信息如下==========" << endl;
		printinfo(timeExceededResponse);
		int ret = pcap_sendpacket(dev, (const uint8_t *)timeExceededResponse, sizeof(ICMPTimeExceededResponse));
		if (ret == 0)
		{
			cout << "tracert发送成功" << endl;
		}
		return;
	}
	// 替换以太帧中的源MAC 和 目的MAC
	memcpy(pack->EntherHeader.SrcMAC, pack->EntherHeader.DstMAC, 6);
	memcpy(pack->EntherHeader.DstMAC, mac, 6);
	setChecksum(&(pack->IPHeader)); // 修改IP校验和
	cout << "==========转发报文信息如下==========" << endl;
	printinfo(pack);
	pcap_sendpacket(dev, (const uint8_t *)pack, sizeof(ICMP));
}

class ArpTable
{
	// 静态成员变量声明
	static ArpTable ArpItems[60];

public:
	uint32_t IP;
	uint8_t MAC[6];

	static int insert(uint32_t DstIp, uint8_t *mac)
	{ // 添加新表项
		cout << "没有找到ARP缓存，正在发送ARP请求索要目标MAC地址" << endl;
		int ret = 1;
		if (getDstMac(DstIp, mac) == -1)
		{ // 若获取失败 返回-1
			ret = -1;
			return ret;
		}
		ArpItems[ARP_count].IP = DstIp;
		for (int i = 0; i < 6; i++)
		{
			ArpItems[ARP_count].MAC[i] = mac[i];
		}
		ARP_count++; // tracert 流程报告、虚拟机打包
		return ret;
	}

	// 查询arp缓存 返回目的MAC地址
	static int search(uint32_t ip, uint8_t *mac)
	{
		for (int i = 0; i < ARP_count; i++)
		{
			if (ip == ArpItems[i].IP)
			{
				for (int j = 0; j < 6; j++)
				{
					mac[j] = ArpItems[i].MAC[j];
				}
				cout << "在ARP缓存中成功找到所需MAC" << endl;
				return 1;
			}
		}
		cout << "【Error】在ARP缓存中没有找到所需MAC" << endl;
		return 0;
	} // 查询
};
ArpTable ArpTable::ArpItems[60];

// 控制流程线程
DWORD WINAPI handler(LPVOID lparam)
{
	while (1)
	{

		pcap_pkthdr *pkt_header;
		const u_char *pkt_data;
		while (1)
		{
			int i = pcap_next_ex(dev, &pkt_header, &pkt_data);
			if (i != 0)
			{ // 0 超时
				if (i == -1)
					printf("【Error】接受线程的接收函数有误\n");
				break;
			}
		}
		//  解析报文
		Ethernet_header *header = (Ethernet_header *)pkt_data;
		if (cmp(header->DstMAC, LocalMac) && ntohs(header->FrameType) == 0x0800)
		{
			// 检查MAC地址
			ICMP *data = (ICMP *)pkt_data;
			IP_header *ipHeader = &(data->IPHeader);
			if (!check(ipHeader))
			{
				cout << "【Error】收到校验和错误，丢弃报文" << endl;
				continue;
			}
			cout << "开始转发报文" << endl;
			cout << "====================这是要转发的第" << ICMP_count++ << "个报文====================" << endl;
			printinfo(data);

			if (data->IPHeader.DstIP == inet_addr(curIp[0]) || data->IPHeader.DstIP == inet_addr(curIp[1]))
			{
				cout << ("***投递方式：直接投递") << endl;
				continue;
			}
			RouterTable rtable = *(RouterTable *)(LPVOID)lparam;
			uint32_t dstIp, nextIp;
			dstIp = data->IPHeader.DstIP;
			if ((nextIp = rtable.search(data->IPHeader.DstIP)) == -1)
			{
				// 查找路由表中是否有对应表项
				cout << "【warning】无对应路由项，转发失败，丢弃报文" << endl;
				continue;
			}
			else
			{
				cout << ("***投递方式：路由转发，下一条IP为:");
				outputIp(nextIp);
				printf("\n");
				ICMP *pack = (ICMP *)pkt_data;
				ICMP temp = *pack;
				uint8_t mac[6];
				int ret = 1;
				if (!ArpTable::search(nextIp, mac))
					ret = ArpTable::insert(nextIp, mac);
				if (ret == 1)
				{
					packageForward(temp, mac); // 转发
					cout << "转发成功" << endl;
				}
			}
		}
	}
}

int main()
{
	if (getSrcIp() == -1)
	{
		printf("【Error】本机IP获取失败");
		return 0;
	}
	if (getSrcMac() == -1)
	{
		printf("【Error】本机MAC获取失败");
		return 0;
	}
	cout << "网卡信息读取完毕，正在初始化路由表" << endl;
	RouterTable RT(curIp, curMask);
	RT.print();
	bool ifopen = false; // 是否已经打开 避免多次重复建立线程
	while (1)
	{
		cout << ("select opreation:\n");
		cout << ("1.add\n2.delete\n3.print\n4.start route\n");
		int choice;
		cin >> choice;

		switch (choice)
		{
		case 1:
		{
			RouterItem *newItem = new RouterItem;
			newItem->type = 1; // 手动添加
			char buf[INET_ADDRSTRLEN];
			printf("目的网络:\n");
			scanf("%s", &buf);
			newItem->destNet = inet_addr(buf);
			printf("网络掩码:\n");
			scanf("%s", &buf);
			newItem->mask = inet_addr(buf);
			printf("下一跳IP:\n");
			scanf("%s", &buf);
			newItem->nextSkip = inet_addr(buf);
			RT.insert(newItem);
			break;
		}
		case 2:
		{
			printf("输入想要删除的序号: ");
			int index;
			scanf("%d", &index);
			RT.remove(index);
			break;
		}
		case 3:
		{
			RT.print();
			break;
		}
		case 4:
		{
			if (ifopen == false)
			{
				CreateThread(NULL, 0, handler, &RT, 0, NULL);
				cout << "路由服务已成功开启" << endl;
				ifopen = true;
			}
			else
			{
				cout << "请勿重复开启服务" << endl;
			}
			break;
		}
		default:
			printf("【Error】输入有误\n");
		}
	}
	// system("pasuse");
	return 0;
}
