#include "pcap.h"
#include <stdio.h>
int main()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息的缓冲
    pcap_if_t *it;
    int r;

    r = pcap_findalldevs(&it, errbuf);
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
    return 0;
}
