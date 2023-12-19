#include "utlis.h"
using namespace std;
// ��ʾIP
void outputIp(uint32_t IP)
{
	in_addr addr;
	addr.s_addr = IP;
	cout << inet_ntoa(addr) << endl;
}

// �Ƚ�MAC�Ƿ���ͬ
bool cmp(uint8_t A[], uint8_t B[])
{
	for (int i = 0; i < 6; i++)
	{
		if (A[i] != B[i])
		{
			return false;
		}
	}
	return true;
}

// ����У���
void setChecksum(ICMP *response)
{
	response->checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // ÿ16λΪһ��
	int size = sizeof(ICMP) - sizeof(Ethernet_header) - sizeof(IP_header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16λ���
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// ȡ��
	response->checksum = (uint16_t)~checkSum;
}

// ����У��� ��У��λ������������ ��Ϊ0xffff
bool check(ICMP *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // ÿ16λΪһ��
	bool checkOut = true;
	for (int i = 0; i < sizeof(ICMP) - sizeof(Ethernet_header) - sizeof(IP_header) / 2; i++)
	{
		checkSum += sec[i];
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	if (sizeof(IP_header) % 2 != 0)
	{
		checkSum += *(uint8_t *)(sec + (sizeof(IP_header) - 1));
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	checkOut = (checkSum == 0xffff) ? true : false;
	return checkOut;
}

// ����У���
void setChecksum(ICMPTimeExceededResponse *response)
{
	response->checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // ÿ16λΪһ��
	int size = sizeof(response->type) + sizeof(response->code) + sizeof(response->checksum) + sizeof(response->unused) + sizeof(response->originalIPHeader) + sizeof(response->originalData);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16λ���
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// ȡ��
	response->checksum = (uint16_t)~checkSum;
}

bool check(const ICMPTimeExceededResponse *response)
{
	uint32_t checkSum = 0;
	// ��ICMP�����ֶο�ʼ����
	const uint16_t *ptr = reinterpret_cast<const uint16_t *>(&response->type);
	int size = sizeof(response->type) + sizeof(response->code) + sizeof(response->checksum) + sizeof(response->unused) + sizeof(response->originalIPHeader) + sizeof(response->originalData);

	while (size > 1)
	{
		checkSum += *ptr++;
		size -= sizeof(uint16_t);
	}

	// ������ݰ�����Ϊ�������������һ���ֽ�
	if (size > 0)
	{
		checkSum += *(reinterpret_cast<const uint8_t *>(ptr));
	}

	// �۵�У���
	while (checkSum >> 16)
	{
		checkSum = (checkSum & 0xFFFF) + (checkSum >> 16);
	}

	// ���У����Ƿ���ȷ
	return (checkSum == 0xFFFF);
}

void setChecksum(IP_header *response)
{
	response->Checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // ÿ16λΪһ��
	int size = sizeof(IP_header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16λ���
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// ȡ��
	response->Checksum = (uint16_t)~checkSum;
}

bool check(IP_header *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // ÿ16λΪһ��
	bool checkOut = true;
	for (int i = 0; i < sizeof(IP_header) / 2; i++)
	{
		checkSum += sec[i];
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	if (sizeof(IP_header) % 2 != 0)
	{
		checkSum += *(uint8_t *)(sec + (sizeof(IP_header) - 1));
		while (checkSum >= 0x10000)
		{
			int c = checkSum >> 16;
			checkSum -= 0x10000;
			checkSum += c;
		}
	}
	checkOut = (checkSum == 0xffff) ? true : false;
	return checkOut;
}

// ��ӡһЩ���ĵĻ�����Ϣ ���Կ��ǵ���дһ��MAC��ӡ����
void printinfo(ICMP *response)
{
	cout << "�����ݰ��������¡�" << endl;
	cout << "***ԴMAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->EntherHeader.SrcMAC[i]); // λ��2 ��λ����
	}
	cout << "\n***Ŀ��MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->EntherHeader.DstMAC[i]); // λ��2 ��λ����
	}
	cout << "\n***ԴIP:";
	outputIp(response->IPHeader.SrcIP);
	cout << "***Ŀ��IP:";
	outputIp(response->IPHeader.DstIP);
	cout << endl;
}

void printinfo(ICMPTimeExceededResponse *response)
{
	cout << "�����ݰ��������¡�" << endl;
	cout << "***ԴMAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->ethernetHeader.SrcMAC[i]); // λ��2 ��λ����
	}
	cout << "\n***Ŀ��MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->ethernetHeader.DstMAC[i]); // λ��2 ��λ����
	}
	cout << "\n***ԴIP:";
	outputIp(response->ipHeader.SrcIP);
	cout << "***Ŀ��IP:";
	outputIp(response->ipHeader.DstIP);
	cout << endl;
}