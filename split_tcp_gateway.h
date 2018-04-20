#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "pcap/pcap.h"
#include <pthread.h>
#include <cstring>
#include <string.h>
#include <list>
#include <deque>
#include <queue>
#include <assert.h>
#include <math.h>
#include <iostream>
#include <time.h>
#include "es_TIMER.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <bitset>
#include <stdarg.h>
#include <time.h>


using namespace std;

#define PKT_SIZE 1515
#define CIRCULAR_BUF_SIZE 2048*1
#define CIRCULAR_QUEUE_SIZE 1024

#define END_TO_END_DELAY 250000000
#define IPTOSBUFFERS 12

#define MAX_CONN_STATES	65536

#define LOCAL_WINDOW 65535
#define RECEIVE 0
#define SEND 1
#define MTU 1515
#define WIN_SCALE 6   // capacity need 1 or 0

//#define RTT_LIMIT 200000

#define MAX_RTO 1000000
#define MAX_RTO_IETF 1000000

#define NUM_DUP_ACK 3
#define STD_RTT
#define LINUX_RTT

#define TIME_TO_LIVE 10000000 //us


//#define LOG_STAT
#define RESOLUTION 1000000
#define SLIDING_WIN_SIZE 1500

#define SLIDING_GRADIENT_SIZE 10

#define NUM_SACK_BLOCK 1
//#define COMPLETE_SPLITTING_TCP 

/* multi-user extension */
#define TOTAL_NUM_CONN 150
#define CLIENT_SACK_SIZE 5

//#define DEBUG

/* time interval estimation */
#define SLIDE_TIME_INTERVAL 250000
#define FIX_TIME_INTERVAL_EST 
#define SLIDE_TIME_DELTA 2000

typedef int BOOL;
typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long long u_long_long;
typedef signed long long int __int64;

#define FALSE 0
#define TRUE 1

#define MY_SEQ_LT(a, b)  ((int)((a) - (b)) < 0)
#define MY_SEQ_LEQ(a, b)  ((int)((a) - (b)) <= 0)
#define MY_SEQ_GT(a, b)  ((int)((a) - (b)) > 0)
#define MY_SEQ_GEQ(a, b)  ((int)((a) - (b)) >= 0)

//#define PKT_DROP_EMULATOR


#define NUM_PKT_DROP 10
#define DROP_PERIOD 12000000

#define TOTAL_NO_PKT 100//67658955/1448 + 1
#define HTTP_CAP 10

ES_FlashTimer timer;
FILE* test_file;

#define MAX_UPLINK_BW 1500000

u_int APP_PORT_NUM;
u_int APP_PORT_FORWARD;
u_int MAX_SEND_RATE;
u_int MIN_SEND_RATE;
u_int INITIAL_RATE;
u_int SND_BEYOND_WIN;
u_int NUM_PKT_BEYOND_WIN;
u_int RTT_LIMIT;
u_int BDP;

BOOL enable_opp_rtx = TRUE;
#define CTRL_FLIGHT
#define HTTP_CAP 10

#define BUSY_PERIOD_ARRAY_SIZE 512
//#define CHECK_BUSY_PERIOD
//#define USE_TIMESTAMP

#define BW_DELAY_PRO (15*1024*1024/8)*100/1000
#define RRE_BW_DELAY_PRO (15*1024*1024/8)*100/1000
#define MIN_RTT 40000
//#define TCP-RRE
//#define RSFC


#ifndef TCP-REE
#define DYNAMIC_RATE_FIT
//#define PRINT_STATS
#endif

#define SND_WIN_SIZE 6

//#define DOWNLINK_QUEUE_LEN_EST

#define DELAY_TOLERANCE 10000
#define DELAY_THRES 0.0000
#define DELAY_STDDEV 90000

#define QUEUE_THRES 0
#define QUEUE_DELAY_TARGET 0

#define USE_PROBE 1

char filename[7][30] = {"./downlink_0_out.txt", 
                        "./downlink_200000_out.txt", 
                        "./downlink_400000_out.txt", 
                        "./downlink_500000_out.txt", 
                        "./downlink_600000_out.txt", 
                        "./downlink_800000_out.txt", 
                        "./downlink_1000000_out.txt"};

int levels[11] = {0, 100000, 200000, 300000, 400000, 500000, 600000, 700000,  800000, 900000, 1000000};

int find_bw_level(u_int bw) 
{

	for (int i = sizeof(levels)/sizeof(int) - 1; i >= 0; i -- )
	{
		if (bw >= levels[i])
			return i;
		else
			continue;
	}
        
}


u_int init_rate = MAX_SEND_RATE;
u_int init_win = SLIDE_TIME_INTERVAL; 

u_int find_initial_rate_window(double bw, int time)
{
	
	//int throughput = 0;
	//int delay = 0;
	int rate = 0;
	int window = 0;
	int downlink = 0;
	int whichfile = 0;
	int bw_level = (int)bw;
	char filename[3][1000] = {"./2s_rate_maxThput.txt", "./10s_rate_maxThput.txt", "./120s_rate_maxThput.txt"};

	char line[1000];
	
	if (time == 2)
		whichfile = 0;
	else if (time == 10)
		whichfile = 1;
	else if (time == 120)
		whichfile = 2;
	else {
		printf("please input right time parameter!\n");
		exit(-1);
	}

	FILE *onlyread = fopen(filename[whichfile],"r");

	if (onlyread == NULL) {
		printf("File not open!\n");
		exit(-1);
	}
	
	while (fgets(line, 1000, onlyread) != NULL) {
		sscanf(line, "%d %d %d", &downlink, &rate, &window);
		if (downlink/100000 == bw_level) {
			init_rate = rate;
			init_win = window;
		}
	}

	fclose(onlyread);
	return init_rate;
}

enum DIRECTION
{
	SERVER_TO_CLIENT,
	CLIENT_TO_SERVER,
};
struct seg_info
{
	u_long_long forward_time;
	u_int seq_num;
	u_int data_len;
};
struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};
struct psd_header
{
	ip_address saddr;
	ip_address daddr;
	u_char mbz;
	u_char ptoto;
	u_short tcp_len;
};
struct mac_header
{
	u_char mac_src[6];		// mac source address
	u_char mac_dst[6];		// mac destination address
	u_short opt;
};
struct ip_header
{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short tlen;			// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    ip_address	saddr;		// Source address
    ip_address	daddr;		// Destination address
};
struct tcp_header
{
	u_short sport;		     //   Source   port
	u_short dport;		     //   Destination   port
	u_int seq_num;		     //   sequence   number
	u_int ack_num;		     //   acknowledgement   number
	u_short hdr_len_resv_code; //   Datagram   length
	u_short window;			 //   window
	u_short crc;			 //   Checksum
	u_short urg_pointer;     //   urgent   pointer
};
struct tcp_sack_block
{
	u_int left_edge_block;
	u_int right_edge_block;
};

struct tcp_sack
{
	u_char pad_1;
	u_char pad_2;
	u_char kind;
	u_char length;
	tcp_sack_block sack_block[CLIENT_SACK_SIZE];

};
struct sack_header
{
	tcp_sack_block sack_list[CLIENT_SACK_SIZE];
	u_int _size;

	sack_header()
	{
            for (u_short i = 0; i < CLIENT_SACK_SIZE; i ++)
            {
                    sack_list[i].left_edge_block = 0;
                    sack_list[i].right_edge_block= 0;
            }
            _size = 0;
	}

	void inline flush()
	{
            for (u_short i = 0; i < CLIENT_SACK_SIZE; i ++)
            {
                    sack_list[i].left_edge_block = 0;
                    sack_list[i].right_edge_block = 0;
            }
            _size = 0;
	}

	u_int size()
	{
		return _size;
	}

};

struct udp_header
{
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short crc;			// Checksum
};
struct ForwardPkt
{
	void *data;
	struct pcap_pkthdr header;
	u_char pkt_data[PKT_SIZE];
	struct ForwardPkt* next;
	struct ForwardPkt* prev;

	u_int seq_num;
	u_short data_len;
	u_short ctr_flag;
	u_long_long snd_time;
	u_long_long rtx_time;
	u_int num_dup;
	u_long_long rcv_time;
	u_short sPort, dPort;
	u_int index;
	bool occupy;
	u_int tcb;
	bool is_rtx;
        u_int TSval;
        
	void initPkt()
	{
            seq_num = 0;
            data_len = 0;
            ctr_flag = 0;
            snd_time = 0;
            rtx_time = 0;
            rcv_time = 0;
            num_dup = 0;
            sPort = 0;
            dPort = 0;
            occupy = false;
            is_rtx = true;
            index = 0;
            TSval = 0;
	}
	void PktHandler()
	{
		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		mac_header* mh;
		ip_header* ih;
		tcp_header* th;
		udp_header* uh;
		u_int ip_len;
		u_int tcp_len;
		u_int data_len;
		u_int seq_num, ack_num;
		u_short sport, dport;
		u_short ctr_flag;

		local_tv_sec = header.ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		strftime( timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("%s,%.6d len:%d ", timestr, header.ts.tv_usec, header.len);
		mh = (mac_header *) pkt_data;
		printf("%d:%d:%d:%d:%d:%d -> %d:%d:%d:%d:%d:%d ", mh->mac_dst[0],
		mh->mac_dst[1], mh->mac_dst[2], mh->mac_dst[3], mh->mac_dst[4],
		mh->mac_dst[5], mh->mac_src[0], mh->mac_src[1], mh->mac_src[2],
		mh->mac_src[3], mh->mac_src[4], mh->mac_src[5]);
		if (pkt_data[14] != '\0')
		{
                    ih = (ip_header *) (pkt_data + 14); //length of ethernet header
                    ip_len = (ih->ver_ihl & 0xf) * 4;
                    printf("%d.%d.%d.%d -> %d.%d.%d.%d %d ",  ih->saddr.byte1,  ih->saddr.byte2,  ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ih->proto);

                    if ((int)ih->proto == 17) //UDP
                    {
                            printf("UDP ");
                            uh = (udp_header *)((u_char *)ih + ip_len);
                            sport = ntohs(uh->sport);
                            dport = ntohs(uh->dport);
                            printf("%hu -> %hu\n", sport, dport);
                            return;
                    }
                    else if ((int)ih->proto == 6) //TCP
                    {
                            printf("TCP ");
                            th = (tcp_header *)((u_char *)ih + ip_len);
                            sport = ntohs(th->sport);
                            dport = ntohs(th->dport);
                            seq_num = ntohl(th->seq_num);
                            ack_num = ntohl(th->ack_num);
                            tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                            ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
                            if (header.len > 60)
                                    data_len = header.len - 14 - ip_len - tcp_len;
                            else
                                    data_len = 0;
                            printf("%hu ", ntohs(th->hdr_len_resv_code)&0x003f);
                            printf("%hu -> %hu %u %u %u\n", sport, dport, seq_num, ack_num, data_len);
                            return;
                    }
		}

		printf("\n");
		return;
	}
};
struct node
{
    int data;
    node *link;
};
class linklist
{
public:

	node *p;

	linklist()
	{
		p=NULL;
	}

	void append(int num)
	{
		node *q,*t;

		if( p == NULL )
		{
			p = new node;
			p->data = num;
			p->link = NULL;
		}
		else
		{
			q = p;
			while( q->link != NULL )
				q = q->link;

			t = new node;
			t->data = num;
			t->link = NULL;
			q->link = t;
		}
	}
	void add_as_first( int num )
	{
		node *q;

		q = new node;
		q->data = num;
		q->link = p;
		p = q;
	}
	void addafter( int c, int num )
	{
		node *q,*t;
		int i;
		for(i=0,q=p;i<c;i++)
		{
			q = q->link;
			if(q == NULL )
			{
				printf("There are less than %d elements\n", c);
				return;
			}
		}

		t = new node;
		t->data = num;
		t->link = q->link;
		q->link = t;
	}
	void del(int num)
	{
		node *q,*r;
		q = p;
		if( q->data == num )
		{
			 p = q->link;
			 delete q;
			 return;
		}

		r = q;
		while( q!=NULL )
		{
			if( q->data == num )
			{
				r->link = q->link;
				delete q;
				return;
			}

			r = q;
			q = q->link;
		}
		printf("Element %d not Found\n", num);
	}

	void display()
	{
		node *q;
		for(q = p ; q != NULL ; q = q->link)
			printf("%d\n", q->data);
	}

	int count()
	{
		node *q;
		int c=0;
		for( q=p ; q != NULL ; q = q->link )
			c++;

		return c;
	}

	~linklist()
	{
		node *q;
		if( p == NULL )
			return;

		while( p != NULL )
		{
			q = p->link;
			delete p;
			p = q;
		}
	}
};
struct state_array
{
	u_int state_id[TOTAL_NUM_CONN];
	u_int num;
	u_int it;

	state_array()
	{
		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			state_id[i] = 0;
		}

		num = 0;
		it = 0;
	}

	BOOL isEmpty()
	{
		if (!num)
			return TRUE;
		else
			return FALSE;
	}

	void flush()
	{
		num = it = 0;
		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			state_id[i] = 0;
		}
	}

	u_int iterator()
	{
		return it;
	}

	void next()
	{
		if (num)
			it = (it + 1) % num;
	}

	u_int size()
	{
		return num;
	}

	BOOL find(u_int port)
	{
		for (u_int i = 0; i < num; i ++)
		{
			if (state_id[i] == port)
				return TRUE;
		}

		return FALSE;
	}

	void add(u_int port)
	{
		state_id[num] = port;
		num ++;
	}

	void del(u_int index)
	{
		for (u_int i = index; i < num - 1; i ++)
			state_id[i] = state_id[i + 1];
		state_id[num - 1] = 0;
		num --;
		if (num)
			it = index % num;
		else
			it = 0;

	}

	void deleteByValue(u_int port)
	{
		u_int index;
		for (u_int i = 0; i < num; i ++)
		{
			if (state_id[i] == port)
			{
				index = i;
				break;
			}
		}

		del(index);
	}
};
struct ForwardPktBuffer
{
	ForwardPkt* pktQueue;

	u_int capacity, _size, _head, _tail, _unAck, _pkts, _last_head, _last_pkts;
        ForwardPktBuffer(){}
        
	ForwardPktBuffer(u_int size):capacity(size)
	{
		pktQueue = (ForwardPkt *)malloc(sizeof(ForwardPkt)*capacity);
		for (int i = 0; i < capacity; i ++)
			pktQueue[i].initPkt();

		_head = _tail = _size = _unAck = _pkts = _last_head = _last_pkts = 0;
	}

	void inline flush()
	{
		init();
	}

	~ForwardPktBuffer()
	{
		free(pktQueue);
	}

	inline void init()
	{
		for (int i = 0; i < capacity; i ++)
			pktQueue[i].initPkt();

		_head = _tail = _size = _unAck = _pkts = _last_head = _last_pkts = 0;
	}

	inline ForwardPkt* unAck() { return pktQueue + (_unAck % capacity); }
	inline void unAckNext() { _unAck = (_unAck + 1) % capacity; }
	inline ForwardPkt* head() { return pktQueue + (_head % capacity); }
	inline void headNext() { _head = (_head + 1) % capacity; _pkts --; }
	inline void headPrev()
	{
            if (_head == 0)
                _head = capacity - 1;
            else
                _head = (_head - 1) % capacity;

            _pkts ++;
            
	}
	inline void lastHeadNext() { _last_head = (_last_head + 1) % capacity; _last_pkts --; }
	inline void lastHeadPrev()
	{
            if (_last_head == 0)
                _last_head = capacity - 1;
            else
                _last_head = (_last_head - 1) % capacity;

            _last_pkts ++;

	}
        inline ForwardPkt* lastHead() { return pktQueue + (_last_head % capacity); }
	inline ForwardPkt* tail() { return pktQueue + (_tail % capacity); }
	inline void tailNext() { _tail = (_tail + 1) % capacity; _pkts ++; }

	inline ForwardPkt* pkt(u_int _index) { return pktQueue + (_index % capacity); }
	inline u_int pktNext(u_int _index) { return _index = (_index + 1) % capacity; }

	inline u_int size() { return _size; }
	inline u_int pkts() { return _pkts; }

	inline void increase() { _size ++; }
	inline void decrease() { _size --; }
                 
};

        
#define POSITIVE 1
#define NEGATIVE 0

struct Packet
{
	u_int seqNo;
	u_long_long time;
	u_int len;
        int unsent_len;
        u_int future_time;
        BOOL sign;
        
        
	Packet()
	{
		len = seqNo = time = unsent_len = future_time = 0;
                sign = NEGATIVE;
	}

	void flush()
	{
		len = seqNo = time = unsent_len = future_time = 0;
                sign = NEGATIVE;
	}
};
struct SlideWindow
{
	Packet* window;
        Packet* bw_window;
        Packet* unsent_window;
        Packet* unsent_stack;
                        
	u_int _size, _bytes, capacity, delta, interval;
	u_long_long sample_time;
        u_int k, M, unsent_cap;
        
        long heuristic; 
        long heuristic_0;
        long heuristic_1;
        long heuristic_2;
        u_int init_burst;
        
        u_long_long shift_time;
        u_long_long reload_time;
        
        u_int underflow_time;
        
        long upper_heuristic;
        long lower_heuristic;
        long unsent_data; 
        
        long phase_1_sent_bytes;
        long phase_2_sent_bytes;
        long unsent_data_due_schedule_delay;
        long init_burst_unsent_bytes;
        long total_bw_bytes;
        long make_up_bw;
        
        u_int _u_size, _u_head, _u_tail;
        int unsent_delta;
                        
        int counted_unsent_bytes;
        
        u_int nb_unsent_pos;      
        u_int _stack_size;                 
        
        u_int sent_timestamp_rep;
        u_int last_timestamp_rep;
        u_long_long buffer_drain_start_time;
        u_long_long buffer_drain_interval;
        
        int heuristic_bytes;                
	
        int unsent_bytes_rr;
        int nb_rate_update;
        
        int unsent_delay_bytes;
        
#define HEURISTIC_UNSENT_STACK_SIZE 0
        
	SlideWindow(u_int size, u_int _interval, u_int _delta)
	{
            capacity = size;
            delta = _delta;
            interval = _interval;
            M = interval/delta;
            unsent_cap = size * 10;
            
            window = (Packet *)malloc(sizeof(Packet) * size);

            for (int i = 0; i < size; i ++)
                window[i].flush();

            bw_window = (Packet *)malloc(sizeof(Packet) * M);
            for (int i = 0; i < M; i ++)
                bw_window[i].flush();
            
            unsent_window = (Packet *)malloc(sizeof(Packet) * unsent_cap);
            for (int i = 0; i < unsent_cap; i ++)
                unsent_window[i].flush();
            
            unsent_stack = (Packet *)malloc(sizeof(Packet) * capacity);
            for (int i = 0; i < capacity; i ++)
                unsent_stack[i].flush();
            
            _stack_size = 0;
            
            _size = _bytes = sample_time = shift_time = init_burst = upper_heuristic = lower_heuristic = unsent_data = heuristic = 0;
            heuristic_0 = heuristic_1 = heuristic_2 = 0;
            reload_time = 0;
            
            underflow_time = 0;
            
            unsent_data_due_schedule_delay = 0;
            phase_1_sent_bytes = 0;
            phase_2_sent_bytes = 0;
            init_burst_unsent_bytes = 0;
            total_bw_bytes = 0;
            make_up_bw = 0;
            
            k = 1; // the time interval sliding window
            
            _u_size = _u_head = _u_tail = 0;
            
            counted_unsent_bytes = 0;
           
            unsent_delta = 0;
            nb_unsent_pos = 0;            
            sent_timestamp_rep = 0;
            last_timestamp_rep = 0;            
            buffer_drain_start_time = 0;
            buffer_drain_interval = 0;
            
            heuristic_bytes = 0;
            
            unsent_bytes_rr = 0;
            nb_rate_update = 0;
            unsent_delay_bytes = 0;
	}

	~SlideWindow()
	{
		free(window);
                free(bw_window);
                free(unsent_window);
	}

	u_int size()
	{
	  return _size;
	}

	u_int bytes()
	{
            if (_bytes)           
	  return _bytes;
            else
                return 0;
	}

	BOOL isEmpty()
	{
          if (_size == 0)
             return TRUE;
          else
             return FALSE;
	}

	u_int bytesCount()
	{
          if (isEmpty())
          {
             return 0;
          }
          else
             return window[_size-1].seqNo - window[0].seqNo;
	}

	u_long_long frontTime()
	{
            if (isEmpty())
                return 0;
            else
                return window[0].time;
	}

	u_long_long tailTime()
	{
            if (isEmpty())
                return 0;
            else
                return window[_size-1].time;
	}

        u_long_long estmateInterval(u_long_long current_time)
	{
            if (!sample_time)
                return 0;
            else
                return (current_time <= sample_time ? 0 :current_time - sample_time);
	}

	u_long_long nextEstmateSampleTime(u_long_long current_time)
	{
            if (!sample_time)
            {
                sample_time = current_time;
                return sample_time;
            }
            else
            {
                sample_time += delta;
                return sample_time;
            }
	}

	void another_shift()
	{
            while (frontTime() < sample_time && _bytes > 0 && _size > 12)
            {
                shift();
                _size --;
            }

	}
	
	u_long_long timeInterval(u_long_long current_time)
	{
            if (isEmpty())
                return 0;
            else
                return (current_time <= window[0].time ? 0 : current_time - window[0].time);
	}

	void shift()
        {
            _bytes -= window[0].len;
            
            if (window[0].seqNo == 15) // what is it?
                unsent_delay_bytes += window[0].len;
            
            for (u_int i = 0; i < _size - 1; i ++)
            {
                window[i].len = window[i+1].len;
                window[i].time = window[i+1].time;
                window[i].seqNo = window[i+1].seqNo;
                window[i].future_time = window[i+1].future_time;
                window[i].unsent_len = window[i+1].unsent_len;
                window[i].sign = window[i+1].sign;
            }
            
            window[_size - 1].flush();
	}
        
        void pop(u_int len) 
        {
            
            if (_bytes > len && window[_size - 1].len >= len)
            {
                window[_size - 1].len -= len;
                _bytes -= len; 
            }
        }
        
        
        void put_stack(u_int len, u_long_long time, u_int seqNo, BOOL sign, int unsent_len)
	{
            if (HEURISTIC_UNSENT_STACK_SIZE)
            {
                if (_stack_size < HEURISTIC_UNSENT_STACK_SIZE)
                {
                    unsent_stack[_stack_size].len = len;
                    unsent_stack[_stack_size].time = time;
                    unsent_stack[_stack_size].seqNo = seqNo;
                    unsent_stack[_stack_size].sign = sign;
                    unsent_stack[_stack_size].unsent_len = unsent_len; 
                    heuristic_bytes += len;
                    _stack_size ++;
                }
                else
                {                
                    shift_stack();
                    unsent_stack[_stack_size-1].len = len;
                    unsent_stack[_stack_size-1].time = time;
                    unsent_stack[_stack_size-1].seqNo = seqNo;           
                    unsent_stack[_stack_size-1].sign = sign;
                    unsent_stack[_stack_size-1].unsent_len = unsent_len; 
                    heuristic_bytes += len;
                }
            }
	}
        
        void shift_stack()
        {
            heuristic_bytes -= unsent_stack[0].len;                                    
            for (u_int i = 0; i < _stack_size - 1; i ++)
            {
                unsent_stack[i].len = unsent_stack[i+1].len;
                unsent_stack[i].time = unsent_stack[i+1].time;
                unsent_stack[i].seqNo = unsent_stack[i+1].seqNo;
                unsent_stack[i].future_time = unsent_stack[i+1].future_time;
                unsent_stack[i].unsent_len = unsent_stack[i+1].unsent_len;
                unsent_stack[i].sign = unsent_stack[i+1].sign;
            }
            
            unsent_stack[_stack_size - 1].flush();
        }
        
	void put(u_int len, u_long_long time, u_int seqNo)
	{
            if (_size < capacity)
            {
                window[_size].len = len;
                window[_size].time = time;
                window[_size].seqNo = seqNo;
                _bytes += window[_size].len;
                _size ++;
            }
            else
            {                
                shift();
                window[_size-1].len = len;
                window[_size-1].time = time;
                window[_size-1].seqNo = seqNo;
                _bytes += window[_size-1].len;
            }
	}

	void another_put(u_int len, u_long_long time, u_int seqNo)
	{

            if (_size < capacity)
            {
                window[_size].len = len;
                window[_size].time = time;
                window[_size].seqNo = seqNo;
                _bytes += window[_size].len;
                _size ++;
            }
            else
            {

                shift();
                window[_size-1].len = len;
                window[_size-1].time = time;
                window[_size-1].seqNo = seqNo;
                _bytes += window[_size-1].len;
            }

            bw_window[k-1].len += len;                                                
            total_bw_bytes += len;
                
                
	}
        
        void record_unsent_pos(u_long_long current_time)
        {
            another_put(0, current_time, 0);
            window[_size-1].sign = TRUE;
            nb_unsent_pos ++;
        }
        
        void update_unsent_pos(u_int len, u_int rcv_bw, u_long_long current_time)
        {
            for (int i = _size - 1; i >= 0; i --)
            {
                if (window[i].sign)
                {
                    window[i].len += len;
                    _bytes += len;                                        
                    window[i].sign = FALSE;                    
                    nb_unsent_pos --;
                    
                    if (!nb_unsent_pos)
                        break;
                }
            }
            
            u_int updated_bw =  (estmateInterval(current_time) == 0 ? MAX_SEND_RATE :
                (u_long_long)bytes() * (u_long_long)RESOLUTION / 
                    (u_long_long)estmateInterval(current_time));
                   
            updated_bw = (updated_bw > MAX_SEND_RATE ? MAX_SEND_RATE : updated_bw);
            u_int std_dev = DELAY_STDDEV;
            
            /*
            if (rcv_bw > 900000)
                std_dev = 90000;
            else if (rcv_bw > 700000)
                std_dev = 90000;
            else if (rcv_bw > 500000)
                std_dev = 90000;
            else if (rcv_bw > 300000)
                std_dev = 90000;
            else if (rcv_bw > 200000)
                std_dev = 90000;
            else
                std_dev = 90000;
            */
            
            if (updated_bw > rcv_bw + std_dev) {
                window[_size - 1].len -= len;
                _bytes -= len;
            }
            
            
            nb_unsent_pos = 0;
            counted_unsent_bytes = 0;
        }
        
        void update_all_pos(u_int total)
        {
            u_int one = total/_size;
            for (int i = 0; i < _size; i ++)
            {
                window[i].len += one;
                _bytes += one;
            }
        }
        
        int update_rcv_acks(int unrcv_acks, BOOL sign)
        {
            
            if (sign)
            {                
                window[_size-1].len += unrcv_acks;
                _bytes += unrcv_acks;
                unrcv_acks = 0;
            }
            else
            {
                if (window[_size-1].len >= unrcv_acks)
                {
                    window[_size-1].len -= unrcv_acks;
                    _bytes -= unrcv_acks;
                    
                    unrcv_acks = 0;
                }
                else
                {                    
                    
                    for (int i = _size - 1; i >= 0; i --)
                    {
                        if (window[i].len >= unrcv_acks)
                        {
                            window[i].len -= unrcv_acks;
                            _bytes -= unrcv_acks;
                            unrcv_acks = 0;
                            break;
                        }
                        else
                        {
                            window[i].len = 0;
                            _bytes -= window[i].len;
                            unrcv_acks -= window[i].len;
                        }
                    }
                   
                    
                }
            }
            
            return unrcv_acks;
            
        }
        
        inline Packet* uhead() { return unsent_window + (_u_head % unsent_cap); }
	inline void uheadNext() { _u_head = (_u_head + 1) % unsent_cap; _u_size --; }
        inline Packet* utail() { return unsent_window + (_u_tail % unsent_cap); }
        inline void utailNext() { _u_tail = (_u_tail + 1) % unsent_cap; _u_size ++; }
                                 
	void flush()
	{           
            _size = _bytes = sample_time = shift_time = 0;
            for (u_int i = 0; i < capacity; i ++)
                    window[i].flush();

            for (int i = 0; i < M; i ++)
                bw_window[i].flush(); 
            
            for (int i = 0; i < unsent_cap; i ++)
                unsent_window[i].flush(); 
            
            for (int i = 0; i < capacity; i ++)
                unsent_stack[i].flush();
            
            _stack_size = 0;       
            
            init_burst = heuristic = sample_time = shift_time = upper_heuristic = lower_heuristic = unsent_data = 0;
            heuristic_0 = heuristic_1 = heuristic_2 = 0;
            reload_time = 0;
            
            underflow_time = 0;
            
            unsent_data_due_schedule_delay = 0;
            phase_1_sent_bytes = 0;
            phase_2_sent_bytes = 0;
            init_burst_unsent_bytes = 0;
            total_bw_bytes = 0;
            k = 1;
            
            make_up_bw = 0;
            
            _u_size = _u_head = _u_tail = 0;
            
            unsent_delta = 0;
                     
            counted_unsent_bytes = 0;
            nb_unsent_pos = 0;
            
            sent_timestamp_rep = 0;
            last_timestamp_rep = 0;
            buffer_drain_start_time = 0;
            buffer_drain_interval = 0;
            
            heuristic_bytes = 0;      
            
            unsent_bytes_rr = 0;
            nb_rate_update = 0;
            
            unsent_delay_bytes = 0;
	
	}

        void bw_window_shift(u_long_long current_time)
        {                                    
            for (int i = 0; i < M - 1; i ++) 
            {                
                bw_window[i].len = bw_window[i+1].len;
                bw_window[i].time = bw_window[i+1].time;
                bw_window[i].seqNo = bw_window[i+1].seqNo;
                bw_window[i].unsent_len = bw_window[i+1].unsent_len;
                bw_window[i].future_time = bw_window[i+1].future_time;
                bw_window[i].sign = bw_window[i+1].sign;
            }
            
            bw_window[M-1].flush();
            bw_window[M-1].time = current_time;
        }
        
        long threshold(long X)
        {               
            if (k < M)
            {
                heuristic = ((2*M - k + 1)*k*X*(double(delta)/double(RESOLUTION)))/(2*M);
                
               
                for (int i = 1; i <= k; i ++)
                {
                    heuristic -= (M - (k-i))*bw_window[i-1].len/M;                    
                }
                                           
                heuristic_0 = phase_1_sent_bytes - total_bw_bytes;
                unsent_data_due_schedule_delay = heuristic - heuristic_0;
            }
            else
            {
                heuristic = (1 + M)*X*(double(delta)/double(RESOLUTION))/2;
                                 
                for (int i = 1; i <= M; i ++)
                {
                    heuristic -= i*bw_window[i-1].len/M;                   
                }
                
                
                heuristic_0 = phase_2_sent_bytes - total_bw_bytes;                
                unsent_data_due_schedule_delay = heuristic - heuristic_0;
                
            }
                        
                                                
            return heuristic;
        }
        
        u_int unsent_nb_param(u_int rcv_bw)
        {                   
            return 10;
        }
        
        u_int unsent_nb_pos(u_int rcv_bw) 
        {            
            return 0;
        }
        
        u_int delay_thres(u_int rcv_bw) 
        {          
            return DELAY_THRES * RESOLUTION;            
        }
        
        void window_update(u_int current_time, u_int rtt, u_int rtt_limit, u_int queue_len, u_int rcv_bw, u_long_long now)
        {                
            while (_u_size > 0) 
            {                    
                Packet* unsent_data = uhead();                     
                
                if (MY_SEQ_GEQ(current_time, unsent_data->future_time))
                {
                   
                    
                    if ((rtt < rtt_limit + delay_thres(rcv_bw) || queue_len < QUEUE_THRES)) 
                    {                        

                        if (unsent_data->sign)
                        {                                                        
                            counted_unsent_bytes += unsent_data->unsent_len;
                            record_unsent_pos(now);
                        }
                        else
                        {                            
                            counted_unsent_bytes -= unsent_data->unsent_len;                                                        
                            
                            if (counted_unsent_bytes < 0)
                                counted_unsent_bytes = 0;                                                                                                                                                                    
                        }                                                
                            
                        if (nb_unsent_pos > unsent_nb_pos(rcv_bw)) 
                        {                           
                            update_unsent_pos(counted_unsent_bytes * unsent_nb_param(rcv_bw) / 10 / nb_unsent_pos, rcv_bw, now);                           
                        }             
                        
                        uheadNext();
                        unsent_data->flush();  
                    } 
                    else 
                    {   
                      
                        u_int _unsent_len = unsent_data->unsent_len;
                        BOOL _sign = unsent_data->sign;
                        
                        uheadNext();                                                                        
                        unsent_data->flush();          
                        //unsent_bytes_rr = unsent_bytes_rr + unsent_data->unsent_len;                                                             
                        
                        if (_u_size < unsent_cap) 
                        {                                                                        
                            Packet* return_data = utail();
                            return_data->unsent_len = _unsent_len;
                            return_data->sign = _sign;
                            
                            if (last_timestamp_rep && sent_timestamp_rep <= last_timestamp_rep) {
                                return_data->future_time = last_timestamp_rep + 1;
                            } else {                   
                                return_data->future_time = sent_timestamp_rep;
                            }
                            
                            //return_data->future_time = sent_timestamp_rep;
                            //fprintf(stderr, "++++++++++++++++%u+++++++++++++++\n", return_data->future_time);
                            
                            last_timestamp_rep = return_data->future_time;                
                            utailNext();
                        }                                                                                                                                    
                    }                                            
                }
                else 
                {                    
                    break;
                }
            }


            if (!_u_size)
            {                                
                if (nb_unsent_pos && counted_unsent_bytes > 0)
                {                    
                    update_unsent_pos(counted_unsent_bytes * unsent_nb_param(rcv_bw) / 10 / nb_unsent_pos, rcv_bw, now); 
                }                
            }                                       
        } 
        
        
        long threshold_1(u_long_long current_time, u_long_long sample_period, u_int sent_bytes_delta, u_int rcv_thrughput, 
        u_int min_rcv_thrughput, u_int rtt, u_int rtt_limit)
        {
            if (upper_heuristic && _u_size < unsent_cap)
            {
                
                heuristic_1 = upper_heuristic - bw_window[k-1].len;                                                                                  
                u_int send_rate_lower = min_rcv_thrughput;
                u_long_long sending_bytes = ((u_long_long)rcv_thrughput * (u_long_long)sample_period / (u_long_long)RESOLUTION > 
                        (u_long_long)send_rate_lower * (u_long_long)sample_period / (u_long_long)RESOLUTION ? 
                    (u_long_long)rcv_thrughput * (u_long_long)sample_period / (u_long_long)RESOLUTION : 
                            (u_long_long)send_rate_lower * (u_long_long)sample_period / (u_long_long)RESOLUTION);
                BOOL sign;
                
                if (sending_bytes >= sent_bytes_delta)                                
                {
                    unsent_delta = sending_bytes - sent_bytes_delta;
                    sign = POSITIVE;
                    unsent_data += (sending_bytes - sent_bytes_delta);                
                }
                else
                {
                    unsent_delta =  sent_bytes_delta - sending_bytes;
                    sign = NEGATIVE;
                    unsent_data -= (sent_bytes_delta - sending_bytes);
                }         
                
                if (unsent_data < 0)
                {
                    unsent_data = 0;                    
                } 
                                
                Packet* unsent_data = utail();
                unsent_data->unsent_len = unsent_delta;
                unsent_data->sign = sign;
                
                if (last_timestamp_rep && sent_timestamp_rep <= last_timestamp_rep) {
                    unsent_data->future_time = last_timestamp_rep + 1;
                } else {                   
                    unsent_data->future_time = sent_timestamp_rep;
                }
                 
                //unsent_data->future_time = sent_timestamp_rep;
                                
                last_timestamp_rep = unsent_data->future_time;                
                utailNext();                                                                                     
            }
            else
            {
                
                if (unsent_bytes_rr && _u_size < unsent_cap) {
                    
                    Packet* unsent_data = utail();
                    unsent_data->unsent_len = unsent_bytes_rr;
                    
                    if (unsent_bytes_rr >= 0)
                        unsent_data->sign = POSITIVE;
                    else
                        unsent_data->sign = NEGATIVE;
                    
                    if (last_timestamp_rep && sent_timestamp_rep <= last_timestamp_rep) {
                        unsent_data->future_time = last_timestamp_rep + 1;
                    } else {                   
                        unsent_data->future_time = sent_timestamp_rep;
                    }

                    //unsent_data->future_time = sent_timestamp_rep;

                    last_timestamp_rep = unsent_data->future_time;                
                    utailNext();      
                    
                }
                
                unsent_bytes_rr = 0;
            }
                                                    
        }
        
        
        
        long threshold_2()
        {
            if (unsent_data)
            {                
                heuristic_2 = heuristic_0;
                                                    
            }
            
            nb_rate_update = 0;
        }
                           
      
        
        void put_tail(u_int len, u_int seqNo)
        {
            if (_size)
            {
                window[_size-1].len += len;            
                window[_size-1].seqNo = seqNo;
                _bytes += window[_size-1].len;
            }
            else
            {
                window[_size].len = len;            
                window[_size].seqNo = seqNo;
                _bytes += window[_size].len;
            }
            
            bw_window[k-1].len += len;            
        }
        
        u_int tail()
        {
            if (isEmpty())
                return 0;
            else
                return window[_size-1].len;
        }
        
        u_int head()
        {
            if (isEmpty())
                return 0;
            else
                return window[0].len;
        }
                
};

struct busyPeriod
{
    u_long_long idle_start_time;
    u_long_long idle_end_time;
    
    u_int start_seq_no;
    u_int end_seq_no;
    
    u_short start_dport;
    u_short end_dport;
    
    BOOL started;    
    
    busyPeriod()
    {
        init();
    }
    
    void init()
    {
        idle_start_time = idle_end_time = start_seq_no = end_seq_no = start_dport = end_dport = 0;
        started = FALSE;
    }
            
};
struct busyPeriodArray
{
	busyPeriod* window;
	u_int _size, capacity, _head, _tail, prev_tail, _it;
	
        busyPeriodArray(){}
        
	busyPeriodArray(u_int size)
	{
            capacity = size;
            window = (busyPeriod *)malloc(sizeof(busyPeriod)*capacity);
            _size = _head = _tail = _it = prev_tail = 0;
            for (int i = 0; i < capacity; i ++)
            {
                window[i].init();
            }
            
	}
                       
        void flush()
        {
            _size = _head = _tail = _it = prev_tail = 0;
            for (int i = 0; i < capacity; i ++)
            {
                window[i].init();                
                
            }
            
        }
        
        ~busyPeriodArray()
        {
            free(window);
        }
        
        inline busyPeriod* head() { return window + (_head % capacity); }
	inline void headNext() { _head = (_head + 1) % capacity; }
	
        inline busyPeriod* tail() { return window + (_tail % capacity); }
	inline void tailNext() { prev_tail = _tail; _tail = (_tail + 1) % capacity;}
        
        inline void tailPrev() { _tail = prev_tail;}
        inline busyPeriod* pretail() { return window + (prev_tail % capacity); }
        
        inline void increase() { _size ++; }
	inline void decrease() { _size --; }
        inline u_int size() { return _size; }
        
        inline void itNext() { _it = (_it + 1) % capacity; }        
        inline busyPeriod* it() { return window + (_it % capacity); } 
                     
};
struct rtxBusyPeriodArray
{
    busyPeriod* window;
    u_int capacity, _size;
    
    rtxBusyPeriodArray(u_int size)
    {
        capacity = size;        
        window = (busyPeriod *)malloc(sizeof(busyPeriod) * capacity);
        
        for (int i = 0; i < capacity; i ++)
        {
            window[i].init();
        }
    }
            
    ~rtxBusyPeriodArray()
    {
        free(window);
    }
    
    void flush()
    {
        _size = 0;
        for (int i = 0; i < capacity; i ++)
        {
            window[i].init();                

        }
    }
    
       
    
};

struct Forward
{
	pcap_t *dev;
	u_int delay;
	DIRECTION mode;

	ForwardPktBuffer pktQueue;
	pthread_mutex_t mutex;

	pthread_cond_t m_eventElementAvailable;
	pthread_cond_t m_eventSpaceAvailable;

	Forward(pcap_t *_dev, u_int count, u_int _delay, DIRECTION _mode) : dev(_dev), delay(_delay), mode(_mode), pktQueue(count)
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventSpaceAvailable, NULL );
		pthread_cond_init(&m_eventElementAvailable, NULL);

	}

	~Forward()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventElementAvailable);
		pthread_cond_destroy(&m_eventSpaceAvailable);
	}
};
struct DATA
{
	pcap_t *dev_this;
	pcap_t *dev_another;
	char *name_this;
	char *name_another;
	DIRECTION mode;
	Forward *forward, *forward_back;
	DATA(pcap_t *dev_0, pcap_t *dev_1, char *name_0, char *name_1, DIRECTION _mode, Forward *_forward, Forward *_forward_back) : dev_this(dev_0), dev_another(dev_1), name_this(name_0), name_another(name_1), mode(_mode), forward(_forward), forward_back(_forward_back){}

};

/*u_char console_y;

u_char getCursorX(void)
{
CONSOLE_SCREEN_BUFFER_INFO csbInfo;
GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbInfo);
return csbInfo.dwCursorPosition.X;
}
u_char getCursorY(void)
{
CONSOLE_SCREEN_BUFFER_INFO csbInfo;
GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbInfo);
return csbInfo.dwCursorPosition.Y;
}

int gotoTextPos(u_char x, u_char y)
{
	COORD cd;
	cd.X = x;
	cd.Y = y;
	return SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), cd);
}
*/

/*Netflow packet process headers*/
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define FLOW_VERSION_5		        5
#define DEFAULT_V5FLOWS_PER_PACKET	30

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
  u_int16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[DEFAULT_V5FLOWS_PER_PACKET+1 /* safe against buffer overflows */];
} NetFlow5Record;

#define MAX_PACKET_LEN   256


typedef struct ipAddress {
  u_int8_t ipVersion:3 /* Either 4 or 6 */,
    localHost:1, /* -L: filled up during export not before (see exportBucket()) */
    notUsed:4 /* Future use */;

  union {
    struct in6_addr ipv6;
    u_int32_t ipv4; /* Host byte code */
  } ipType;
} IpAddress;

struct generic_netflow_record {
  /* v5 */
  IpAddress srcaddr;    /* Source IP Address */
  IpAddress dstaddr;    /* Destination IP Address */
  IpAddress nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t sentPkts, rcvdPkts;
  u_int32_t sentOctets, rcvdOctets;
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int8_t  minTTL, maxTTL; /* IP Time-to-Live */
  u_int32_t dst_as;     /* dst peer/origin Autonomous System */
  u_int32_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */

  /* v9 */
  u_int16_t vlanId, icmpType;

  /*
    Collected info: if 0 it means they have not been
    set so we use the nprobe default (-E)
  */
  u_int8_t engine_type, engine_id;

  /* IPFIX */
  u_int32_t firstEpoch, lastEpoch;

  struct {
    /* Latency extensions */
    u_int32_t nw_latency_sec, nw_latency_usec;

    /* VoIP Extensions */
    char sip_call_id[50], sip_calling_party[50], sip_called_party[50];
  } ntop;

  struct {
    u_int8_t hasSampling;
    u_int16_t packet_len /* 103 */, original_packet_len /* 312/242 */, packet_offset /* 102 */;
    u_int32_t samplingPopulation /* 310 */, observationPointId /* 300 */;
    u_int16_t selectorId /* 302 */;
    u_char packet[MAX_PACKET_LEN] /* 104 */;

    /* Cisco NBAR 2 */
    u_int32_t nbar2_application_id /* NBAR - 95 */;
  } cisco;

  struct {
    u_int32_t l7_application_id /* 3054.110/35932 */;
    char l7_application_name[64] /* 3054.111/35933 */, /* NOT HANDLED */
      src_ip_country[4] /* 3054.120/35942 */,
      src_ip_city[64] /* 3054.125/35947 */,
      dst_ip_country[4] /* 3054.140/35962 */,
      dst_ip_city[64] /* 3054.145/35967 */,
      os_device_name[64] /* 3054.161/35983 */; /* NOT HANDLED */
  } ixia;
};
