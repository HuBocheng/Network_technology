#include "utlis.h"
using namespace std;
// 显示IP
void outputIp(uint32_t IP)
{
	in_addr addr;
	addr.s_addr = IP;
	cout << inet_ntoa(addr) << endl;
}

// 比较MAC是否相同
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

// 设置校验和
void setChecksum(ICMP *response)
{
	response->checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // 每16位为一组
	int size = sizeof(ICMP) - sizeof(Ethernet_header) - sizeof(IP_header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16位相加
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// 取反
	response->checksum = (uint16_t)~checkSum;
}

// 检验校验和 在校验位不清零的情况下 和为0xffff
bool check(ICMP *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // 每16位为一组
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

// 设置校验和
void setChecksum(ICMPTimeExceededResponse *response)
{
	response->checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)&response->type; // 每16位为一组
	int size = sizeof(response->type) + sizeof(response->code) + sizeof(response->checksum) + sizeof(response->unused) + sizeof(response->originalIPHeader) + sizeof(response->originalData);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16位相加
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// 取反
	response->checksum = (uint16_t)~checkSum;
}

bool check(const ICMPTimeExceededResponse *response)
{
	uint32_t checkSum = 0;
	// 从ICMP类型字段开始计算
	const uint16_t *ptr = reinterpret_cast<const uint16_t *>(&response->type);
	int size = sizeof(response->type) + sizeof(response->code) + sizeof(response->checksum) + sizeof(response->unused) + sizeof(response->originalIPHeader) + sizeof(response->originalData);

	while (size > 1)
	{
		checkSum += *ptr++;
		size -= sizeof(uint16_t);
	}

	// 如果数据包长度为奇数，处理最后一个字节
	if (size > 0)
	{
		checkSum += *(reinterpret_cast<const uint8_t *>(ptr));
	}

	// 折叠校验和
	while (checkSum >> 16)
	{
		checkSum = (checkSum & 0xFFFF) + (checkSum >> 16);
	}

	// 检查校验和是否正确
	return (checkSum == 0xFFFF);
}

void setChecksum(IP_header *response)
{
	response->Checksum = 0;
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // 每16位为一组
	int size = sizeof(IP_header);
	while (size > 1)
	{
		checkSum += *(sec++);
		// 16位相加
		size -= 2U;
	}
	if (size)
	{
		checkSum += *(uint8_t *)sec;
	}

	checkSum = (checkSum & 0xffff) + (checkSum >> 16);
	checkSum += (checkSum >> 16);
	// 取反
	response->Checksum = (uint16_t)~checkSum;
}

bool check(IP_header *response)
{
	uint32_t checkSum = 0;
	uint16_t *sec = (uint16_t *)response; // 每16位为一组
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

// 打印一些报文的基本信息 可以考虑单独写一个MAC打印函数
void printinfo(ICMP *response)
{
	cout << "【数据包概览如下】" << endl;
	cout << "***源MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->EntherHeader.SrcMAC[i]); // 位宽2 空位补零
	}
	cout << "\n***目的MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->EntherHeader.DstMAC[i]); // 位宽2 空位补零
	}
	cout << "\n***源IP:";
	outputIp(response->IPHeader.SrcIP);
	cout << "***目的IP:";
	outputIp(response->IPHeader.DstIP);
	cout << endl;
}

void printinfo(ICMPTimeExceededResponse *response)
{
	cout << "【数据包概览如下】" << endl;
	cout << "***源MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->ethernetHeader.SrcMAC[i]); // 位宽2 空位补零
	}
	cout << "\n***目的MAC:";
	for (int i = 0; i < 6; i++)
	{

		printf("%02x:", response->ethernetHeader.DstMAC[i]); // 位宽2 空位补零
	}
	cout << "\n***源IP:";
	outputIp(response->ipHeader.SrcIP);
	cout << "***目的IP:";
	outputIp(response->ipHeader.DstIP);
	cout << endl;
}