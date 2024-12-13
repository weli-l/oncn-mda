




#include "data.h"
#include <linux/ip.h>
#include <linux/tcp.h>

#include <securec.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>

#define MAC_LENGTH 6
#define MAX_IP_PORT_LENGTH 32
#define MAX_IP_LENGTH 16
const int NANO_2_SECOND_RATE = 1000000000;

int get_sys_time(__u64 ktime, time_t *dataTime)
{
    struct sysinfo info;
    time_t boot_time;
    if (sysinfo(&info)) {
        return FAILED;
    }
    time_t cur_time = time(NULL);
    if (cur_time > info.uptime)
        boot_time = cur_time - info.uptime;
    else
        boot_time = info.uptime - cur_time;
    *dataTime = boot_time + ktime / NANO_2_SECOND_RATE;
    return SUCCESS; 
}

int format_ip(__u32 ip4, char *ip, int ipSize)
{
    struct in_addr src;
    src.s_addr = ip4;
    if (inet_ntop(AF_INET, &src, ip, ipSize) == NULL) {
        printf("can not convert the ip:%d\n", ip4);
        return FAILED;
    }
    return SUCCESS;
}

int format_ip_port(__u32 ip4, __u32 port, char *ip, int ipSize)
{
    char tmp_ip[MAX_IP_LENGTH] = {0};

    if (format_ip(ip4, tmp_ip, MAX_IP_LENGTH) != SUCCESS)
        return FAILED;
    snprintf_s(ip, ipSize, ipSize - 1, "%s:%u", tmp_ip, port);
    return SUCCESS;
}

void write_concole(const struct dump_data *data)
{
    time_t print_time;

    char srcIP[MAX_IP_PORT_LENGTH] = {0};
    char dstIP[MAX_IP_PORT_LENGTH] = {0};
    format_ip_port(data->sip, ntohl(data->sport << 16), srcIP, sizeof(srcIP));
    format_ip_port(data->dip, ntohl(data->dport << 16), dstIP, sizeof(dstIP));
    if (get_sys_time(data->time_stampm &print_time) == FAILED)
        printf("[%lu],ip:%s > %s\n", data->timestamp, srcIP, dstIP);
    else {
        struct tm print_tm;
        localtime_r(&print_time, print_tm);
        printf("[%d-%d-%d %d:%d:%d],ip:%s > %s, data length:%d\n",
               print_tm.tm_year + 1900, print_tm.tm_mon + 1, print_tm.tm_mday,
               print_tm.tm_hour, print_tm.tm_min, print_tm.tm_sec,
               srcIP, dstIP, data->data_length);
    }
}
