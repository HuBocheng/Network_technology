#include "utlis.h"
using namespace std;

class RouterItem
{
public:
    uint32_t mask;     // 掩码
    uint32_t destNet;  // 目的网络
    uint32_t nextSkip; // 下一跳IP
    int index;         // 表索引
    int type;          // 类型 直接/间接 直接不可删除
    RouterItem *Next;  // 下一个表项

    RouterItem()
    {
        memset(this, 0, sizeof(*this));
    }

    void printItem()
    {
        printf("网络掩码: ");
        outputIp(this->mask);
        printf("  目的网络: ");
        outputIp(this->destNet);
        printf("  下一跳: ");
        outputIp(this->nextSkip);
        switch (this->type)
        {
        case 0:
            cout << "直接相连";
            break;
        case 1:
            cout << "需要转发";
        }
        printf("\n");
    }
};

class RouterTable
{
public:
    RouterItem *head; // 头结点
    RouterItem *tail; // 尾结点
    int count;        // 表项计数
    RouterTable(char curIP[][22], char curMask[][22])
    {
        count = 0;
        head = new RouterItem;
        tail = new RouterItem;
        head->Next = tail;
        // 初始化两个本机IP的表项
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

    // 路由表的添加，直接投递在最前，前缀长的在前面
    void insert(RouterItem *RItem)
    {
        RouterItem *item;
        if (RItem->type != 0)
        {
            // MASK大小降序排列
            for (item = head->Next; item != tail && item->Next != tail; item = item->Next)
            {
                if ((RItem->mask < item->mask) && (RItem->mask >= item->Next->mask))
                    // 找到要插入的位置break
                    break;
            }
            RItem->Next = item->Next;
            item->Next = RItem;
        }
        // 直接转发放开头
        else if (RItem->type == 0)
        {
            RItem->Next = head->Next;
            head->Next = RItem;
            RItem->type = 0;
        }

        RouterItem *p = head->Next;
        // 更新序号
        for (int i = 0; p != tail; i++)
        {
            p->index = i;
            p = p->Next;
        }
        count++; // 计数加1
    }

    // 删除 遍历寻找
    void remove(int index)
    {
        if (count == 0)
        {
            printf("【Error】表项为空\n");
            return;
        }
        RouterItem *item;
        for (item = head; item->Next != tail; item = item->Next)
        {
            if (item->Next->index == index)
            {
                if (item->Next->type == 0)
                {
                    cout << "【Error】直连项不可删除" << endl;
                    return;
                }
                else
                {
                    item->Next = item->Next->Next;
                    cout << ("**删除成功") << endl;
                    return;
                }
            }
        }
        printf("【Error】表项不存在\n");
    }

    // 查找下一条IP 遵循最短路径原则
    uint32_t search(uint32_t DstIp)
    {
        RouterItem *item = head->Next;
        for (; item; item = item->Next)
        {
            // 将目的IP和每一个表项的MASK按位与后和网络号对比
            if ((item->mask & DstIp) == item->destNet)
            {
                if (item->type == 0)
                { // 直接投递
                    return DstIp;
                }
                else
                    return item->nextSkip;
            }
        }
        printf("【Error】未找到下一跳地址\n");
        return -1;
    }

    // 遍历路由表 打印表
    void print()
    {
        RouterItem *item = head->Next;
        cout << "====================路由表现状====================" << endl;
        for (; item != tail; item = item->Next)
        {
            item->printItem();
        }
        cout << "==================================================" << endl;
    }
};