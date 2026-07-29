#ifndef ICMPFLOOD_H
#define ICMPFLOOD_H

#include<cstdlib>
#include<ctime>
#include<random>
#include<libnet.h>

static int alive=-1;
static unsigned long dest=0;
static int PROTO_ICMP=-1;

#define BUFSIZE 64
#define MAX_THREADS 256

// 线程参数结构体
struct thread_arg {
    libnet_t* l;  // libnet 上下文
    uint32_t src_ip;  // 源 IP 地址
    uint32_t dst_ip;  // 目标 IP 地址
    uint16_t id;  // ICMP 报文标识符
    uint16_t seq_start;  // ICMP 报文序列号起始值
    uint16_t seq_end;  // ICMP 报文序列号结束值
};

class icmpflood
{
public:

    icmpflood(char* src_ip,char* dst_ip,char* icmpid,char* start_seq,char* end_seq,char* threads_num);

    static inline long myrandom(int begin,int end){
     int gap=end-begin+1;
     int ret=0;
     srand((unsigned)time(0));
     ret=rand()%gap+begin;
     return ret;
    }
   private:
    static int rawsocket;
    thread_arg tharg;

};

#endif // ICMPFLOOD_H
