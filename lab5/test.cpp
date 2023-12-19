#include "router.h"
using namespace std;
#define ARP_TIMEOUT 5 // ARP��ʱʱ��

pcap_if_t *alldevs;	 // ָ���豸�����ײ���ָ��
pcap_t *dev;		 // ѡ��򿪵�����
uint8_t LocalMac[6]; // Դ�����豸��mac��ַ
uint8_t DstMac[6];	 // Ŀ�������豸��mac��ַ

char curIp[2][INET_ADDRSTRLEN];	  // ����IP
char curMask[2][INET_ADDRSTRLEN]; // ����

int ARP_count = 0;	// �������
int ICMP_count = 1; // ת����ICMP���ݰ�����

int getSrcMac()
{
	cout << "==========���ڷ���ARP�����ȡ����MAC��ַ==========" << endl;
	struct pcap_pkthdr *pkt_header; // ��̫���ݰ�ͷ
	const u_char *pkt_data;			// ��̫���ݰ�����
	Arp_frame arp;					// arp����
	int flag;
	int ret = 1;

	// ��װARP
	arp.frameHeader.FrameType = htons(0x0806); // 0x806����ARP
	memset(arp.frameHeader.DstMAC, 0xff, 6);   // Ŀ��MAC�ǹ㲥��ַ
	memset(arp.DstMAC, 0x00, 6);			   // �����
	for (int i = 0; i < 6; i++)
	{
		arp.frameHeader.SrcMAC[i] = arp.SrcMAC[i] = 0x11; // �����
	}

	arp.HardwareType = htons(1);  // Ethernet
	arp.Protocol = htons(0x0800); // IP
	arp.HardwareAddLen = 6;		  // MAC��ַ����Ϊ6
	arp.ProtocolAddLen = 4;		  // IP��ַ����Ϊ4
	arp.OperationType = htons(1); // ARP����
	arp.SourceIp = inet_addr("10.0.0.1");
	arp.DestIp = inet_addr(curIp[0]);

	// ����
	pcap_sendpacket(dev, (uint8_t *)&arp, sizeof(Arp_frame));

	// �հ�
	time_t start = clock();
	while ((flag = pcap_next_ex(dev, &pkt_header, &pkt_data) >= 0))
	{
		time_t end = clock();
		if ((end - start) / CLOCKS_PER_SEC >= ARP_TIMEOUT)
		{
			cout << "��Error����ȡARP��Ӧ��ʱ" << endl;
			ret = -1;
			break;
		}
		if (flag == 0)
		{
			continue;
		}
		else if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) && *(uint16_t *)(pkt_data + 20) == htons(2) && *(uint32_t *)(pkt_data + 28) == arp.DestIp)
		{ // ���ļ����ARP����arp��Ӧ��ip��Դ��ȷ
			cout << "�ɹ��������������MAC��ַ" << endl;
			cout << "����MACΪ: ";
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
		printf("��Error����ȡ����MACʧ��\n");
		pcap_freealldevs(alldevs);
		ret = -1;
	}

	cout << "==========��ȡ����MAC��ַ���==========" << endl
		 << endl
		 << endl;
	return ret;
}
// ��������ȡ������Ϣ
int getSrcIp()
{
	pcap_if_t *device;	   // �������б�
	pcap_addr_t *adhandle; // ���������
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
		return -1;
	}

	// ��ʾ�豸�б�
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
				printf("IP��ַ: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in *)adhandle->netmask)->sin_addr));
				printf("��������: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in *)adhandle->broadaddr)->sin_addr));
				printf("�㲥��ַ: %s\n", str);
			}
		}
	}

	if (i == 0)
	{
		std::cout << "\nNo interfaces found! Make sure pcap is installed.\n";
		return 1;
	}

	// ѡ������
	cout << "\n����Ҫѡ��򿪵�������" << endl;
	int choice;
	int k;
	cin >> choice;
	if (choice < 1 || choice > i)
	{
		printf("��Error�������ų�����Χ\n");
		pcap_freealldevs(alldevs); // �ͷ��豸�б�
		return -1;
	}
	for (device = alldevs, k = 0; k < choice - 1; k++)
		device = device->next;

	int j = 0;
	for (adhandle = device->addresses; adhandle; adhandle = adhandle->next)
	{ // Ҫ�ö�ά����������ӿ�IP
		if (adhandle->addr->sa_family == AF_INET)
		{
			strcpy(curIp[j], inet_ntoa(((struct sockaddr_in *)adhandle->addr)->sin_addr));
			strcpy(curMask[j++], inet_ntoa(((struct sockaddr_in *)adhandle->netmask)->sin_addr));
		}
	}

	if ((dev = pcap_open(device->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		printf("��Error���޷���������!�����豸\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	return 1;
}

// ��ȡMAC-IP ӳ���ϵ(���ڻ����鲻����ʱ��)
int getDstMac(uint32_t DstIp, uint8_t *macDst)
{
	cout << "�������û���ҵ�ARP���棬���ڷ���ARP������ҪĿ��MAC��ַ" << endl;
	cout << "==========���ڷ���ARP�����ȡĿ��MAC��ַ==========" << endl;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	Arp_frame arp;
	int flag;
	int ret = 1;

	// ��װARP
	arp.frameHeader.FrameType = htons(0x0806);
	memset(arp.frameHeader.DstMAC, 0xff, 6); // �㲥ȫ255
	memset(arp.DstMAC, 0x00, 6);			 // ����
	for (int i = 0; i < 6; i++)
	{
		arp.frameHeader.SrcMAC[i] = arp.SrcMAC[i] = LocalMac[i]; // ԴMAC���MAC
	}

	arp.HardwareType = htons(1);  // Ethernet
	arp.Protocol = htons(0x0800); // IP
	arp.HardwareAddLen = 6;		  // MAC��ַ����Ϊ6 MAC
	arp.ProtocolAddLen = 4;		  // IP��ַ����Ϊ4 IP
	arp.OperationType = htons(1); // arp ARP����
	arp.SourceIp = inet_addr(curIp[0]);
	arp.DestIp = DstIp;

	// ����
	pcap_sendpacket(dev, (uint8_t *)&arp, sizeof(Arp_frame));
	cout << ("�Ѿ�����ARP����") << endl;

	// �հ�
	time_t start = clock();
	while ((flag = pcap_next_ex(dev, &pkt_header, &pkt_data) >= 0))
	{
		// �ȴ���Ӧ��ʱ ֱ���˳�
		time_t end = clock();
		if ((end - start) / CLOCKS_PER_SEC >= ARP_TIMEOUT)
		{
			printf("��Error����ȡARP��Ӧ��ʱ\n");
			ret = -1;
			break;
		}
		if (flag == 0)
		{
			continue; //  break
		}
		else if (*(uint16_t *)(pkt_data + 12) == htons(0x0806) // arp ��̫֡���ϲ�Э������
				 && *(uint16_t *)(pkt_data + 20) == htons(2)   // ��Ӧ arp��������
				 && *(uint32_t *)(pkt_data + 28) == arp.DestIp)
		{ // ip��Դ��ȷ
			cout << ("Ŀ��MAC��ȡ�ɹ�") << endl;
			cout << ("Ŀ��MACΪ: ") << endl;
			for (int i = 0; i < 6; i++)
			{
				macDst[i] = *(uint8_t *)(pkt_data + 22 + i);
				printf("%02x", macDst[i]); // ռλ�� λ��2 �հײ���
				if (i != 5)
					printf(":");
			}
			cout << endl;
			break;
		}
	}
	if (flag < 0 || ret == -1)
	{
		printf("��Error����ȡĿ��MACʧ��\n");
		pcap_freealldevs(alldevs);
		ret = -1;
	}

	cout << "==========��ȡĿ��MAC��ַ���==========" << endl
		 << endl
		 << endl;
	return ret;
}

// ת��
void packageForward(ICMP &icmp, uint8_t *mac)
{
	ICMP *pack = (ICMP *)&icmp;
	pack->IPHeader.TTL = pack->IPHeader.TTL - 1;			   // �ݼ�TTL
	cout << "TLL��1֮��Ϊ" << (int)pack->IPHeader.TTL << endl; // test point
	if (pack->IPHeader.TTL <= 0)
	{
		printf("��Error����������\n");
		// ���������� ICMP ��ʱ��Ӧ
		ICMPTimeExceededResponse *timeExceededResponse = new ICMPTimeExceededResponse();
		timeExceededResponse->setup(*pack);
		timeExceededResponse->ipHeader.SrcIP = inet_addr(curIp[0]);
		setChecksum(timeExceededResponse);
		IP_header *ipHeader = &(timeExceededResponse->ipHeader);
		setChecksum(ipHeader);
		cout << "==========ת��������Ϣ����==========" << endl;
		printinfo(timeExceededResponse);
		int ret = pcap_sendpacket(dev, (const uint8_t *)timeExceededResponse, sizeof(ICMPTimeExceededResponse));
		if (ret == 0)
		{
			cout << "tracert���ͳɹ�" << endl;
		}
		return;
	}
	// �滻��̫֡�е�ԴMAC �� Ŀ��MAC
	memcpy(pack->EntherHeader.SrcMAC, pack->EntherHeader.DstMAC, 6);
	memcpy(pack->EntherHeader.DstMAC, mac, 6);
	setChecksum(&(pack->IPHeader)); // �޸�IPУ���
	cout << "==========ת��������Ϣ����==========" << endl;
	printinfo(pack);
	pcap_sendpacket(dev, (const uint8_t *)pack, sizeof(ICMP));
}

class ArpTable
{
	// ��̬��Ա��������
	static ArpTable ArpItems[60];

public:
	uint32_t IP;
	uint8_t MAC[6];

	static int insert(uint32_t DstIp, uint8_t *mac)
	{ // ����±���
		cout << "û���ҵ�ARP���棬���ڷ���ARP������ҪĿ��MAC��ַ" << endl;
		int ret = 1;
		if (getDstMac(DstIp, mac) == -1)
		{ // ����ȡʧ�� ����-1
			ret = -1;
			return ret;
		}
		ArpItems[ARP_count].IP = DstIp;
		for (int i = 0; i < 6; i++)
		{
			ArpItems[ARP_count].MAC[i] = mac[i];
		}
		ARP_count++; // tracert ���̱��桢��������
		return ret;
	}

	// ��ѯarp���� ����Ŀ��MAC��ַ
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
				cout << "��ARP�����гɹ��ҵ�����MAC" << endl;
				return 1;
			}
		}
		cout << "��Error����ARP������û���ҵ�����MAC" << endl;
		return 0;
	} // ��ѯ
};
ArpTable ArpTable::ArpItems[60];

// ���������߳�
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
			{ // 0 ��ʱ
				if (i == -1)
					printf("��Error�������̵߳Ľ��պ�������\n");
				break;
			}
		}
		//  ��������
		Ethernet_header *header = (Ethernet_header *)pkt_data;
		if (cmp(header->DstMAC, LocalMac) && ntohs(header->FrameType) == 0x0800)
		{
			// ���MAC��ַ
			ICMP *data = (ICMP *)pkt_data;
			IP_header *ipHeader = &(data->IPHeader);
			if (!check(ipHeader))
			{
				cout << "��Error���յ�У��ʹ��󣬶�������" << endl;
				continue;
			}
			cout << "��ʼת������" << endl;
			cout << "====================����Ҫת���ĵ�" << ICMP_count++ << "������====================" << endl;
			printinfo(data);

			if (data->IPHeader.DstIP == inet_addr(curIp[0]) || data->IPHeader.DstIP == inet_addr(curIp[1]))
			{
				cout << ("***Ͷ�ݷ�ʽ��ֱ��Ͷ��") << endl;
				continue;
			}
			RouterTable rtable = *(RouterTable *)(LPVOID)lparam;
			uint32_t dstIp, nextIp;
			dstIp = data->IPHeader.DstIP;
			if ((nextIp = rtable.search(data->IPHeader.DstIP)) == -1)
			{
				// ����·�ɱ����Ƿ��ж�Ӧ����
				cout << "��warning���޶�Ӧ·���ת��ʧ�ܣ���������" << endl;
				continue;
			}
			else
			{
				cout << ("***Ͷ�ݷ�ʽ��·��ת������һ��IPΪ:");
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
					packageForward(temp, mac); // ת��
					cout << "ת���ɹ�" << endl;
				}
			}
		}
	}
}

int main()
{
	if (getSrcIp() == -1)
	{
		printf("��Error������IP��ȡʧ��");
		return 0;
	}
	if (getSrcMac() == -1)
	{
		printf("��Error������MAC��ȡʧ��");
		return 0;
	}
	cout << "������Ϣ��ȡ��ϣ����ڳ�ʼ��·�ɱ�" << endl;
	RouterTable RT(curIp, curMask);
	RT.print();
	bool ifopen = false; // �Ƿ��Ѿ��� �������ظ������߳�
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
			newItem->type = 1; // �ֶ����
			char buf[INET_ADDRSTRLEN];
			printf("Ŀ������:\n");
			scanf("%s", &buf);
			newItem->destNet = inet_addr(buf);
			printf("��������:\n");
			scanf("%s", &buf);
			newItem->mask = inet_addr(buf);
			printf("��һ��IP:\n");
			scanf("%s", &buf);
			newItem->nextSkip = inet_addr(buf);
			RT.insert(newItem);
			break;
		}
		case 2:
		{
			printf("������Ҫɾ�������: ");
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
				cout << "·�ɷ����ѳɹ�����" << endl;
				ifopen = true;
			}
			else
			{
				cout << "�����ظ���������" << endl;
			}
			break;
		}
		default:
			printf("��Error����������\n");
		}
	}
	// system("pasuse");
	return 0;
}
