#include <pcap.h>
#include <iostream>
#include <string>
#include "capture.h" // �������ͷ�ļ�������֮ǰ�ṩ�Ĵ����е���ͺ�������

using namespace std;

uint16_t ip_header::cal_checksum()
{
    uint32_t sum = 0;
    uint16_t *ptr = reinterpret_cast<uint16_t *>(this);
    // ��У����ֶ���Ϊ0
    this->Checksum = 0;
    // ��IP�ײ��е�ÿ16λ���
    for (int i = 0; i < sizeof(ip_header) / 2; ++i)
    {
        sum += ntohs(ptr[i]); // noths������һ���޷��Ŷ��������������ֽ�˳��ת��Ϊ�����ֽ�˳��
    }
    // �Ѹ�16λ�͵�16λ���
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // ����У���
    return static_cast<uint16_t>(~sum);
}

void ip_header::showIPPacket()
{
    cout << "===========��ʼ����IP�����ݰ�======== " << endl;
    cout << "�汾�ţ�" << (this->Ver_HLen >> 4) << endl;
    cout << "�ײ����ȣ�" << (this->Ver_HLen & 0x0F) * 4 << endl;
    cout << "�������ͣ�" << (int)this->TOS << endl;
    switch ((int)this->TOS >> 5)
    {
    case 0:
        cout << "���ȼ���Routine,���ݰ�����Ҫ���⴦��" << endl;
        break;
    case 1:
        cout << "���ȼ���Priority,���ݰ�����Ҫ���⴦��" << endl;
        break;
    case 2:
        cout << "���ȼ���Immediate,���ݰ���Ҫ��������" << endl;
        break;
    case 3:
        cout << "���ȼ���Flash,���ݰ���Ҫ���ٴ���" << endl;
        break;
    case 4:
        cout << "���ȼ���Flash Override,���ݰ���Ҫ���������������������ݰ��Ĵ���" << endl;
        break;
    case 5:
        cout << "���ȼ���CRITIC/ECP,���ݰ��ǹؼ����ݻ�����������ݣ���Ҫ������ȼ�����" << endl;
        break;
    case 6:
        cout << "���ȼ���Internetwork Control,���ݰ�������������ݣ���Ҫ�����ȼ�����" << endl;
        break;
    case 7:
        cout << "���ȼ���Network Control,���ݰ�������������ݣ���Ҫ������ȼ�����" << endl;
        break;
    }
    cout << "�ܳ��ȣ�" << ntohs(this->TotalLen) << endl;
    cout << "��ʶ��" << ntohs(this->ID) << endl;
    cout << "��־��" << bitset<3>(ntohs(this->Flag_Segment) >> 13) << endl;
    cout << "��Ӧ��־������λ������Ƭ��DF��λ�͸����Ƭ��MF��λ��" << endl;
    cout << "Ƭƫ�ƣ�" << (ntohs(this->Flag_Segment) & 0x1FFF) << endl;
    cout << "����ʱ�䣺" << (int)this->TTL << endl;
    cout << "Э���ţ�" << (int)this->Protocol << endl;
    switch ((int)this->Protocol)
    {
    case 1:
        cout << "Э�����ͣ�ICMP" << endl;
        break;
    case 2:
        cout << "Э�����ͣ�IGMP" << endl;
        break;
    case 6:
        cout << "Э�����ͣ�TCP" << endl;
        break;
    case 17:
        cout << "Э�����ͣ�UDP" << endl;
        break;
    case 58:
        cout << "Э�����ͣ�ICMPv6" << endl;
        break;
    case 89:
        cout << "Э�����ͣ�OSPF" << endl;
        break;
    case 132:
        cout << "Э�����ͣ�SCTP" << endl;
        break;
    case 255:
        cout << "Э�����ͣ�RAW" << endl;
        break;
    }
    cout << "�ײ�У��ͣ�" << ntohs(this->Checksum) << endl;
    cout << "ԴIP��ַ��" << inet_ntoa(*(struct in_addr *)&this->SrcIP) << endl;
    cout << "Ŀ��IP��ַ��" << inet_ntoa(*(struct in_addr *)&this->DstIP) << endl;
    cout << "===========���IP�����ݰ�����======== " << endl;
}

void analysis_IP(u_char *user_data, const struct pcap_pkthdr *pkInfo, const u_char *packet)
{
    // ��������
    //  user_data�����û���������ݵ��ص������У�ͨ���ò���
    //  pkInfo�����˴����ݰ���ʱ����Ϣ�ͳ�����Ϣ
    //  packet�����ݰ�������

    ip_header *ip_protocol;
    ip_protocol = (struct ip_header *)(packet + 14); // ��ȡIPͷ��14 ����Ϊ��̫��֡ͷ��ͨ���� 14 �ֽ�

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

    // ��ȡ�豸�б�
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
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
    }

    if (i == 0)
    {
        std::cout << "\nNo interfaces found! Make sure pcap is installed.\n";
        return 1;
    }

    // ѡ��һ���豸
    int inum;
    std::cout << "Enter the interface number (1-" << i << "):";
    std::cin >> inum;

    if (inum < 1 || inum > i)
    {
        std::cout << "\nInterface number out of range.\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // ��ת��ѡ����������
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++)
        ;

    // ���豸
    if ((adhandle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        std::cerr << "\nUnable to open the adapter. " << device->name << " is not supported by pcap\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\nListening on " << device->description << "...\n";

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);

    // ��ʼ����
    pcap_loop(adhandle, 0, packet_handler, NULL);

    // �رվ��
    pcap_close(adhandle);

    return 0;
}
