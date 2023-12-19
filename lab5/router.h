#include "utlis.h"
using namespace std;

class RouterItem
{
public:
    uint32_t mask;     // ����
    uint32_t destNet;  // Ŀ������
    uint32_t nextSkip; // ��һ��IP
    int index;         // ������
    int type;          // ���� ֱ��/��� ֱ�Ӳ���ɾ��
    RouterItem *Next;  // ��һ������

    RouterItem()
    {
        memset(this, 0, sizeof(*this));
    }

    void printItem()
    {
        printf("��������: ");
        outputIp(this->mask);
        printf("  Ŀ������: ");
        outputIp(this->destNet);
        printf("  ��һ��: ");
        outputIp(this->nextSkip);
        switch (this->type)
        {
        case 0:
            cout << "ֱ������";
            break;
        case 1:
            cout << "��Ҫת��";
        }
        printf("\n");
    }
};

class RouterTable
{
public:
    RouterItem *head; // ͷ���
    RouterItem *tail; // β���
    int count;        // �������
    RouterTable(char curIP[][22], char curMask[][22])
    {
        count = 0;
        head = new RouterItem;
        tail = new RouterItem;
        head->Next = tail;
        // ��ʼ����������IP�ı���
        for (int i = 0; i < 2; i++)
        {
            RouterItem *item;
            item = new RouterItem;
            item->type = 0;
            item->destNet = (inet_addr(curIP[i])) & (inet_addr(curMask[i]));
            item->mask = inet_addr(curMask[i]);
            this->insert(item);
        }
    }

    // ·�ɱ����ӣ�ֱ��Ͷ������ǰ��ǰ׺������ǰ��
    void insert(RouterItem *RItem)
    {
        RouterItem *item;
        if (RItem->type != 0)
        {
            // MASK��С��������
            for (item = head->Next; item != tail && item->Next != tail; item = item->Next)
            {
                if ((RItem->mask < item->mask) && (RItem->mask >= item->Next->mask))
                    // �ҵ�Ҫ�����λ��break
                    break;
            }
            RItem->Next = item->Next;
            item->Next = RItem;
        }
        // ֱ��ת���ſ�ͷ
        else if (RItem->type == 0)
        {
            RItem->Next = head->Next;
            head->Next = RItem;
            RItem->type = 0;
        }

        RouterItem *p = head->Next;
        // �������
        for (int i = 0; p != tail; i++)
        {
            p->index = i;
            p = p->Next;
        }
        count++; // ������1
    }

    // ɾ�� ����Ѱ��
    void remove(int index)
    {
        if (count == 0)
        {
            printf("��Error������Ϊ��\n");
            return;
        }
        RouterItem *item;
        for (item = head; item->Next != tail; item = item->Next)
        {
            if (item->Next->index == index)
            {
                if (item->Next->type == 0)
                {
                    cout << "��Error��ֱ�����ɾ��" << endl;
                    return;
                }
                else
                {
                    item->Next = item->Next->Next;
                    cout << ("**ɾ���ɹ�") << endl;
                    return;
                }
            }
        }
        printf("��Error���������\n");
    }

    // ������һ��IP ��ѭ���·��ԭ��
    uint32_t search(uint32_t DstIp)
    {
        RouterItem *item = head->Next;
        for (; item; item = item->Next)
        {
            // ��Ŀ��IP��ÿһ�������MASK��λ��������ŶԱ�
            if ((item->mask & DstIp) == item->destNet)
            {
                if (item->type == 0)
                { // ֱ��Ͷ��
                    return DstIp;
                }
                else
                    return item->nextSkip;
            }
        }
        printf("��Error��δ�ҵ���һ����ַ\n");
        return -1;
    }

    // ����·�ɱ� ��ӡ��
    void print()
    {
        RouterItem *item = head->Next;
        cout << "====================·�ɱ���״====================" << endl;
        for (; item != tail; item = item->Next)
        {
            item->printItem();
        }
        cout << "==================================================" << endl;
    }
};