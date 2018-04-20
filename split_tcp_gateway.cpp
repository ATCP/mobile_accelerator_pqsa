/**
 * Mobile Accelerator source fule, all the featured algorithms are implemented here.
 */

/**
 * header file.
 * @see split_tcp_gateway.h
 */
#include "split_tcp_gateway.h"

/**
 * States the mobile accelerator sender and receiver can be in.
 * Sender faces to the mobile receiver
 * Receiver faces to the wired sender
 * The states implemented is similar to TCP states
 */


enum STATE
{
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_REVD,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK,
};

/**
 * phases the mobile accelerator sender can be in.
 * similar to TCP sending phase, such as slow start, loss recovery, etc
 * @NORMAL similar to TCP congestion avoidance phase but the sending rate
 * is adjusted by the bandwidth estimation and adaptation
 * @FAST_RTX transmitting the missing packet
 * @PAUSE obsolete parameter
 * @NORMAL_TIMEOUT enter this phase when timeout and use F-RTO to detect
 * unnecessary timeout and retransmit
 */
enum PHASE
{
	NORMAL,
	FAST_RTX,
	PAUSE,
	NORMAL_TIMEOUT,
};

/**
 * obsolete class.
 */
struct SendDataPktQueue
{
	ForwardPkt* head;
	ForwardPkt* tail;
	u_int size;

	SendDataPktQueue()
	{
		head = tail = NULL;
		size = 0;
	}

	~SendDataPktQueue()
	{
		struct ForwardPkt* h = NULL;
		struct ForwardPkt* p = NULL;

		while(head)
		{
			h = head;
			p = h->next;
			head = h;
			if (head == NULL)
				tail = head;
			else
				head->prev = NULL;
			free(h);
		}

	}

	u_int num()
	{
		return size;
	}

	bool IsEmpty()
	{
		if (head == NULL && tail == NULL)
			return true;
		else
			return false;
	}

	ForwardPkt* FetchPkt(u_int seq_want)
	{
		struct ForwardPkt* p;

		for (p = head; p; p = p->next)
		{
			if (p->seq_num == seq_want)
				return p;
		}
		return NULL;
	}

	bool Dequeue(u_int ack_up)
	{
		struct ForwardPkt* h;
		struct ForwardPkt* p;

		if (head == NULL && tail == NULL)
		{
			printf("Queue is empty\n");
			return true;
		}

		while(ack_up > head->seq_num)
		{
			h = head;
			p = h->next;
			head = p;
			if (head == NULL)
			{
				tail = head;
				free(h);
				size --;
				return false;
			}
			else
				head->prev = NULL;
			free(h);
			size --;
		}
		return false;
	}

	void EnqueueAndSort(u_int seq_num, u_short data_len, u_short flag, DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data)
	{
		ForwardPkt* pkt = (ForwardPkt *)malloc(sizeof(ForwardPkt));
		pkt->seq_num = seq_num;
		pkt->data_len = data_len;
		pkt->ctr_flag = flag;
		pkt->next = NULL;
		pkt->prev = NULL;
		pkt->num_dup = 0;
		pkt->data = (void *)data;
		memcpy(&pkt->header,  header, sizeof(struct pcap_pkthdr));
		memcpy(pkt->pkt_data, pkt_data, header->len);
		size ++;
		//printf("Enqueue packet seq_num: %u\n", pkt->seq_num);

		if (head == NULL && tail == NULL)
		{
			head = tail = pkt;
			return;
		}

		if (pkt->seq_num > tail->seq_num)
		{
			tail->next = pkt;
			pkt->prev = tail;
			tail = pkt;
		}
		else
		{
			struct ForwardPkt* p = NULL;
			for (p = tail; p; p = p->prev)
			{
				if (pkt->seq_num > p->seq_num)
				{
					pkt->next = p->next;
					pkt->prev = p;
					p->next->prev = pkt;
					p->next = pkt;
					return;
				}
				else if (pkt->seq_num == p->seq_num)
				{
					//printf("Duplicate pkt\n");
					pkt->num_dup ++;
					return;
				}
				else
					continue;
			}
			pkt->next = head;
			head->prev = pkt;
			head = pkt;
		}
	}


};

/**
 * Mobile accelerator sender class.
 *
 */
struct serverState
{
	u_short send_data_id;				///< the sent data packet identity.

	STATE state;						///< the state the sender is in.
	PHASE phase;                        ///< the phase the sender is in.

	u_int snd_wnd;						///< advertised window of the mobile receiver.
	u_int snd_nxt;						///< the next sent sequence number.
	u_int snd_una;						///< the sent but unacknowledged sequence number.
	u_int snd_max;						///< the highest sequence number sent.
 	u_int seq_nxt;						///< obsolete variable.

	u_short win_limit;					///< the window threshold the mobile accelerator disable the opportunistic transmission, initially set to 0.

	BOOL ignore_adv_win;				///< whether to ignore the advertised window from mobile receiver, that is, whether to enable the opportunistic transmission.

	u_short win_scale;					///< large window scale option from mobile receiver.

	BOOL SACK_permitted;				///< the SACK option from mobile receiver.


	/*
	 * constructor to initialize the parameters
	 */
	serverState()
	{
		win_limit = 0; // set Adv win limit to be 0
		ignore_adv_win = FALSE;
		SACK_permitted = FALSE;

		phase = NORMAL;
		state = LISTEN;
		win_scale = 0;
		snd_wnd = snd_nxt = snd_una = snd_max = seq_nxt = 0;
	}

	/*
	 * reinitialize the parameters after destruction.
	 */
	void flush()
	{
		snd_wnd = snd_nxt = snd_una = snd_max = seq_nxt = 0;
		win_limit = 0;
		ignore_adv_win = FALSE;
		SACK_permitted = FALSE;
		win_scale = 0;
		state = LISTEN;
		phase = NORMAL;
	}
};

/*
 *
 */
struct clientState
{
	u_short send_data_id;                                   // previous sent data identity

	STATE state;						// connection state

	/* receive sequence variables */
	u_int rcv_wnd;						// advertised by the gateway client to sender
	u_int rcv_nxt;						// receive next
	u_int rcv_adv;						// advertised window by other end
	u_int snd_nxt;
	u_int seq_nxt;
	u_short win_scale;
	u_short sender_win_scale;
	//ForwardPkt *httpRequest;			// http request packet
        ForwardPktBuffer httpRequest;
	u_short ack_count;

	sack_header sack;

	clientState()
	{
            httpRequest.capacity = HTTP_CAP;
            httpRequest.pktQueue = (ForwardPkt *)malloc(sizeof(ForwardPkt)*httpRequest.capacity);
            httpRequest.init();
                
            //httpRequest->initPkt();

            win_scale = sender_win_scale = 0;
            ack_count = 0;
            send_data_id = rcv_wnd = rcv_nxt = rcv_adv =  snd_nxt = seq_nxt = 0;
	}

	void flush()
	{
            send_data_id = rcv_wnd = rcv_nxt = rcv_adv =  snd_nxt = seq_nxt = 0;
            httpRequest.init();
            win_scale = sender_win_scale = 0;
            ack_count = 0;
            state = LISTEN;
            sack.flush();

	}

	~clientState()
	{
            
	}
};

struct conn_stats
{
  u_int RTT;
  u_int downlink_queueing_delay;
  u_int link_bw;
  u_int rtt_samples;
  u_int delay_samples;
  
  conn_stats()
  {
        RTT = downlink_queueing_delay = link_bw = rtt_samples = delay_samples = 0;
  }
  
  void add_rtt_sample(u_int rtt)
  {      
        RTT = (RTT * rtt_samples + rtt) / (rtt_samples + 1);      
        rtt_samples += 1;     
  }
  
  u_int get_avg_rtt()
  {
        return RTT;
  }
  
  void add_delay_sample(u_int delay)
  {
        downlink_queueing_delay = (downlink_queueing_delay*delay_samples + delay) / (delay_samples + 1);      
        delay_samples += 1;
  }
  
  u_int get_delay()
  {
        return downlink_queueing_delay;
  }
  
  void flush()
  {
        RTT = downlink_queueing_delay = link_bw = rtt_samples = delay_samples = 0;
  }
          
};


struct TCB;
struct conn_state
{
    
        conn_stats connStats;
    
	u_long_long initial_time;
        u_long_long close_time;
	u_char client_mac_address[6];
	u_char server_mac_address[6];

	ip_address client_ip_address;
	ip_address server_ip_address;

	u_short cPort;
	u_short sPort;

	ForwardPktBuffer dataPktBuffer;

	pthread_mutex_t mutex;
	pthread_cond_t m_eventElementAvailable;
	pthread_cond_t m_eventSpaceAvailable;
	serverState server_state;
	clientState client_state;

	// For Experiment Output
	FILE* rttFd;

	u_int send_rate;
	u_int RTT;
	u_int LAST_RTT;
	u_int RTT_limit;
	u_int mdev;
	u_int nxt_timed_seqno;

	u_long_long last_ack_rcv_time;
	u_int last_ack_seqno;
	u_long_long cur_ack_rcv_time;
	u_int cur_ack_seqno;

	u_int cumul_ack;
	u_int accounted_for;
	u_int rcv_thrughput_approx;
	u_int rcv_thrughput;
	u_int ack_interarrival_time;
	u_int dft_cumul_ack;

	u_int rto;
	u_int rtt_std_dev;

	tcp_sack_block sack_block[NUM_SACK_BLOCK];
	u_short sack_block_num;
	u_int sack_diff;
	u_int undup_sack_diff;
	u_short sack_target_block;
	u_int max_sack_edge;
	u_int rcv_max_seq_edge;

        u_int opp_rtx_space;
        
	u_long_long ref_ack_time;
	u_int ref_ack_seq_no;

	u_short MSS;
	u_int zero_window_seq_no;
        
	SlideWindow sliding_avg_win;
        SlideWindow sliding_tsval_window;
        SlideWindow sliding_snd_window;
        
        SlideWindow sliding_uplink_window;
        
	u_int FRTO_ack_count;
	u_int FRTO_dup_ack_count;
        BOOL send_out_awin; //use in fast retransmit
	u_int max_data_len;

#ifdef STD_RTT

	u_int RTT_IETF;
	u_int rtt_std_dev_ietf;
	u_int rto_ietf;
	u_int nxt_timed_seqno_ietf;

#endif

	TCB *_tcb;
	u_int index;

        long long downlink_one_way_delay;
        long long min_downlink_one_way_delay;
        u_int downlink_queueing_length;
	u_int rcv_tsval_thruput;
        u_int target_queue_len;
        
        u_int buffer_max;
        u_int buffer_min;
        
        long long uplink_one_way_delay;
        long long min_uplink_one_way_delay;
        u_int uplink_queueing_delay;
        u_int rcv_uplink_thruput;
       
        
        u_long_long startTime;
        u_int totalByteSent;
        
        u_int local_adv_window;
        
        
	conn_state(u_int count): dataPktBuffer(count), 
        sliding_avg_win (SLIDING_WIN_SIZE + 3500, 0, 0), 
        sliding_tsval_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA),
        sliding_snd_window (SND_WIN_SIZE, 0, 0),
        sliding_uplink_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA)
	{
            init_state();
	}

	conn_state(u_char client_mac[], u_char server_mac[], ip_address client_ip, ip_address server_ip, u_short client_port, u_short server_port, u_int count) : 
        client_ip_address(client_ip), server_ip_address(server_ip), cPort(client_port), sPort(server_port), dataPktBuffer(count), 
        sliding_avg_win (SLIDING_WIN_SIZE + 3500, 0, 0),
        sliding_tsval_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA),
        sliding_snd_window (SND_WIN_SIZE, 0, 0),
        sliding_uplink_window(SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA)
	{
            client_ip_address = client_ip;
            server_ip_address = server_ip;
            cPort = client_port;
            sPort = server_port;

            initial_time = timer.Start();
            close_time = 0;
            memcpy(client_mac_address, client_mac, 6);
            memcpy(server_mac_address, server_mac, 6);
            init_state();
	}

	void inline init_state()
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventSpaceAvailable, NULL );
		pthread_cond_init(&m_eventElementAvailable, NULL);
		rttFd = NULL;

		_tcb = NULL;

		initial_time = 0;
                close_time = 0;
		RTT = 0; //us
		LAST_RTT = 0; //us
		RTT_limit = RTT_LIMIT; //us
		rtt_std_dev = 0;

		mdev = 0;
		last_ack_rcv_time = last_ack_seqno = cur_ack_rcv_time = cur_ack_seqno = cumul_ack = 
			accounted_for = rcv_thrughput_approx = rcv_thrughput = ref_ack_time = ref_ack_seq_no = 0;

		ack_interarrival_time = dft_cumul_ack = 0;
		rto = MAX_RTO; //us

		sack_block_num = 0;
		sack_target_block = 0;
		rcv_max_seq_edge = 0;
		sack_diff = 0;
		max_sack_edge = 0;

		undup_sack_diff = 0;
		for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
		{
			sack_block[i].left_edge_block = sack_block[i].right_edge_block = 0;
		}

	
		send_out_awin = FALSE;

		MSS = 1460; //wired network
		//nxt_ack_seqno = 0;
		nxt_timed_seqno = 0;
		zero_window_seq_no = 0;
		max_data_len = 1380;

#ifdef STD_RTT

		RTT_IETF = 0;
		rtt_std_dev_ietf = 0;
		rto_ietf = MAX_RTO_IETF;
		nxt_timed_seqno_ietf = 0;

#endif
                
		FRTO_ack_count = FRTO_dup_ack_count = 0;		
                opp_rtx_space = 0;
                
                downlink_one_way_delay = 0;
                min_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                
                uplink_one_way_delay = 0;
                min_uplink_one_way_delay =   0x7FFFFFFFFFFFFFFF;
                
                downlink_queueing_length = 0;
                uplink_queueing_delay = 0;
                
                rcv_tsval_thruput = 0;                
                target_queue_len = RRE_BW_DELAY_PRO;
                
                send_rate = INITIAL_RATE;
                
                buffer_max = target_queue_len + RRE_BW_DELAY_PRO/2;
                buffer_min = target_queue_len - RRE_BW_DELAY_PRO/2;
                
                startTime = timer.Start();
                totalByteSent = 0;
                
                rcv_uplink_thruput = 0;
                local_adv_window = 0;
                
               
	}

	void inline init_state_ex(u_char client_mac[], u_char server_mac[], ip_address client_ip, ip_address server_ip, u_short client_port, u_short server_port, TCB *tcb, u_int conn_index)
	{
		client_ip_address = client_ip;
		server_ip_address = server_ip;
		cPort = client_port;
		sPort = server_port;

		initial_time = timer.Start();
                close_time = 0;
		_tcb = tcb;
		index = conn_index;

		memcpy(client_mac_address, client_mac, 6);
		memcpy(server_mac_address, server_mac, 6);
	}

	void inline flush()
	{
		if (rttFd)
		{
			fclose(rttFd);
			rttFd = NULL;
		}

		sliding_avg_win.flush();
                sliding_snd_window.flush();
                sliding_tsval_window.flush();
                
                sliding_uplink_window.flush();
                
		client_state.flush();
		server_state.flush();
		dataPktBuffer.flush();

		_tcb = NULL;

                close_time = 0;
		RTT = 0; //ms
		LAST_RTT = 0; //ms
		RTT_limit = RTT_LIMIT; //ms
		rtt_std_dev = 0;

		mdev = 0;
		last_ack_rcv_time = last_ack_seqno = cur_ack_rcv_time = cur_ack_seqno = cumul_ack = accounted_for 
			= rcv_thrughput_approx = rcv_thrughput = ref_ack_time = ref_ack_seq_no = 0;

		ack_interarrival_time = dft_cumul_ack = 0;
		rto = MAX_RTO; //ms

		sack_block_num = 0;
		sack_target_block = 0;
		rcv_max_seq_edge = 0;
		sack_diff = 0;
		max_sack_edge = 0;

		undup_sack_diff = 0;
		for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
		{
                    sack_block[i].left_edge_block = sack_block[i].right_edge_block = 0;
		}

		
		send_out_awin = FALSE;

		MSS = 1460; //wired network
		//nxt_ack_seqno = 0;
		nxt_timed_seqno = 0;
		zero_window_seq_no = 0;
		max_data_len = 1380;

#ifdef STD_RTT

		RTT_IETF = 0;
		rtt_std_dev_ietf = 0;
		rto_ietf = MAX_RTO_IETF;
		nxt_timed_seqno_ietf = 0;

#endif
		
		FRTO_ack_count = FRTO_dup_ack_count = 0;

		initial_time = 0;
                opp_rtx_space = 0; 	
                
                downlink_one_way_delay = 0;
                min_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                
                downlink_queueing_length = 0;
                uplink_queueing_delay = 0;
                
                 
                uplink_one_way_delay = 0;
                min_uplink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                
                
                rcv_tsval_thruput = 0;                                
                target_queue_len = RRE_BW_DELAY_PRO;
                uplink_queueing_delay = 0;
                
                send_rate = INITIAL_RATE;
                
                buffer_max = target_queue_len + RRE_BW_DELAY_PRO/2;
                buffer_min = target_queue_len - RRE_BW_DELAY_PRO/2;
                
                startTime = timer.Start();
                totalByteSent = 0;
                local_adv_window = 0;
	}

	~conn_state()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventElementAvailable);
		pthread_cond_destroy(&m_eventSpaceAvailable);
	}
};

struct TCB
{
	conn_state* conn[MAX_CONN_STATES + 1];

	u_int send_rate;
	u_int send_rate_lower;
	u_int send_rate_upper;
	u_int aggre_bw_estimate;
	u_int send_beyong_win;
	u_int sample_rate;

	pthread_cond_t m_eventConnStateAvailable;
	pthread_mutex_t mutex;
	state_array states;
	
	SlideWindow sliding_avg_window;
	SlideWindow sliding_snd_window;
	SlideWindow sliding_uplink_window;
	SlideWindow sliding_tsval_window;
        SlideWindow sliding_gradient_window;
        
	u_int rcv_thrughput;
	u_int rcv_thrughput_approx;

	u_long_long initial_time;
        u_long_long close_time;
	ip_address client_ip_address;
	ip_address server_ip_address;

	u_int totalByteSent;
	u_int RTT;
        u_int RTT_INST;
	u_int RTT_limit;
	u_long_long startTime;
	int pkts_transit;

        busyPeriodArray BusyPeriod;
        
        u_int unsent_data_bytes;        
        busyPeriod idleTime;
        
        u_int delay_size;
        int unsent_size;
        
        FILE* out_file;
       
	u_long_long ref_rcv_time;
	u_int ref_TSval;	
	u_int minRTT;
	u_long_long first_rcv_time;
        u_int first_TSval;
        u_int cur_TSval;
	u_int cur_TSecr;
        u_int rcv_tsval_est_thruput;
        
	int delay_var;
	int last_delay_var;
        
        u_int rcv_uplink_thruput;
        u_int rcv_uplink_thruput_approx;
                
        u_int timestamp_granularity;
        u_long_long time_diff;
        
        long long uplink_one_way_delay;
        long long min_uplink_one_way_delay;
        
        long long downlink_one_way_delay;
        long long min_downlink_one_way_delay;
        
        u_int downlink_queueing_delay;
        u_int downlink_queueing_length;
        
        long long ack_downlink_one_way_delay;
        long long min_ack_downlink_one_way_delay;
        long long thrughput_gradient;
        
        u_int thrughput_prediction;
        u_int sent_bytes_counter;
       	
        u_int mean_throughput;
        
        u_int cur_ack_TSval;
        u_int cur_ack_TSecr;
        
        u_int snd_wnd;
        u_int last_snd_wnd;
        u_int snd_wnd_count;
        u_long_long round_start;
        u_int probe_state;  
        u_int toggle;        
        	        
        double increase_factor;
        u_int delay_threshold;
        
	TCB():sliding_avg_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA), 
	sliding_snd_window (SND_WIN_SIZE, 0, 0), 
        BusyPeriod(BUSY_PERIOD_ARRAY_SIZE), 
	sliding_uplink_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA), 
        sliding_tsval_window(SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA), 
        sliding_gradient_window(SLIDING_GRADIENT_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA)
	{
		send_rate = rcv_thrughput_approx = rcv_thrughput = INITIAL_RATE; //Bps
		send_rate_lower = MIN_SEND_RATE; //Bps
		send_rate_upper = MAX_SEND_RATE; //- 50000; //Bps
		send_beyong_win = SND_BEYOND_WIN; // send beyong the advertising window
                
                snd_wnd = BDP;
                last_snd_wnd = snd_wnd;
                snd_wnd_count = 0;
                round_start = 0;
                probe_state = USE_PROBE;
                
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventConnStateAvailable, NULL );
		for (int i = 0; i < MAX_CONN_STATES + 1; i ++) {
			conn[i] = NULL;
		}

		sample_rate = initial_time = pkts_transit = 0;
                close_time = 0;
		totalByteSent = RTT = 0;
                
		RTT_limit = RTT_LIMIT;
		startTime = timer.Start();

		out_file = NULL;
		unsent_data_bytes = 0;
		idleTime.init();

		toggle = FALSE;		
		ref_rcv_time = ref_TSval = cur_TSval = cur_TSecr = 0;		
		minRTT = 0x7FFFFFFF;
		delay_var = last_delay_var = 0;
                timestamp_granularity = 1000;
		rcv_uplink_thruput = rcv_uplink_thruput_approx = MAX_UPLINK_BW;
                first_TSval = first_rcv_time = 0;
                
                rcv_tsval_est_thruput = time_diff = delay_size = 0;
                unsent_size = 0;
                
                uplink_one_way_delay = 0;
                min_uplink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                
                min_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                downlink_one_way_delay = 0;
                
                downlink_queueing_delay = 0;
                downlink_queueing_length = 0;
                
                ack_downlink_one_way_delay = 0;
                min_ack_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                thrughput_gradient = 0;
                
                thrughput_prediction = sent_bytes_counter = 0;
                
                cur_ack_TSval = 0;
                cur_ack_TSecr = 0;
                
                RTT_INST = 0;
                mean_throughput = INITIAL_RATE;
                
                increase_factor = 1.0;
                delay_threshold = 0;
	}

	void init_tcb(ip_address client_ip, ip_address server_ip)
	{
		initial_time = startTime = timer.Start();
		
                close_time = 0;
		client_ip_address = client_ip;
		server_ip_address = server_ip;

	}

        
	void flush()
	{
		send_rate = rcv_thrughput_approx = rcv_thrughput = INITIAL_RATE; //Bps
		send_rate_lower = MIN_SEND_RATE; //Bps
		send_rate_upper = MAX_SEND_RATE; //- 50000; //Bps
		send_beyong_win = SND_BEYOND_WIN; // send beyong the advertising window
                
                snd_wnd = BDP;
                last_snd_wnd = snd_wnd;
                snd_wnd_count = 0;
                round_start = 0;
                probe_state = USE_PROBE;
                
		for (int i = 0; i < MAX_CONN_STATES + 1; i ++) 
                {
                    conn[i] = NULL;
		}

		sample_rate = initial_time = pkts_transit = 0;
		close_time = 0;
		states.flush();
		sliding_avg_window.flush();
                sliding_uplink_window.flush();
                sliding_tsval_window.flush();
                sliding_gradient_window.flush();
                //snd_window.flush();

                BusyPeriod.flush();                
                
		totalByteSent = RTT = 0;
		RTT_limit = RTT_LIMIT;
		startTime = timer.Start();
                
                if (out_file)
                {
                    fclose(out_file);
                    out_file = NULL;
                }

                unsent_data_bytes = 0;                
                idleTime.init();                
                toggle = FALSE;		
		ref_rcv_time = ref_TSval = cur_TSval = cur_TSecr = 0;		
		minRTT = 0x7FFFFFFF;		
		delay_var = last_delay_var = 0;
		rcv_uplink_thruput = rcv_uplink_thruput_approx = MAX_UPLINK_BW;
                timestamp_granularity = 1000;
                first_TSval = first_rcv_time = 0;
                rcv_tsval_est_thruput = time_diff = delay_size = 0;
                unsent_size = 0;
                
                uplink_one_way_delay = 0;
                min_uplink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                
                min_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                downlink_one_way_delay = 0;
                
                downlink_queueing_delay = 0;
                downlink_queueing_length = 0;
                
                ack_downlink_one_way_delay = 0;
                min_ack_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
                thrughput_gradient = 0;
                
                thrughput_prediction = sent_bytes_counter = 0;
                
                cur_ack_TSval = 0;
                cur_ack_TSecr = 0;
                
                RTT_INST = 0;

                mean_throughput = INITIAL_RATE;
                                
                increase_factor = 1.0;
                delay_threshold = 0;
	}

	void add_conn(u_short sport, conn_state *new_conn)
	{
		conn[sport] = new_conn;
		states.add(sport);
                pthread_cond_signal(&m_eventConnStateAvailable);
	}

        void flush_tcb_partially()
        {
            send_rate = rcv_thrughput_approx = rcv_thrughput = INITIAL_RATE;
            send_rate_lower = MIN_SEND_RATE; 
            send_rate_upper = MAX_SEND_RATE; 
            send_beyong_win = SND_BEYOND_WIN; 

            snd_wnd = BDP;
            last_snd_wnd = snd_wnd;
            snd_wnd_count = 0;
            round_start = 0;
            probe_state = USE_PROBE;
                
            
            sample_rate = pkts_transit = 0;
            
            sliding_avg_window.flush();
            sliding_uplink_window.flush();
            sliding_tsval_window.flush();
	    sliding_gradient_window.flush();
           
            totalByteSent = RTT = 0;
            RTT_limit = RTT_LIMIT;    
	   	    
            if (out_file)
            {
                fclose(out_file);
                out_file = NULL;
            }   

            unsent_data_bytes = 0;             
            idleTime.init();            
            toggle = FALSE;
	    ref_rcv_time = ref_TSval = cur_TSval = cur_TSecr = 0;	
	    minRTT = 0x7FFFFFFF;
	    
	    delay_var = last_delay_var = 0;
            timestamp_granularity = 1000;
	    rcv_uplink_thruput = rcv_uplink_thruput_approx = MAX_UPLINK_BW;
            
            rcv_tsval_est_thruput = time_diff = delay_size = 0;
            unsent_size = 0;
            
            uplink_one_way_delay = 0;
            min_uplink_one_way_delay = 0x7FFFFFFFFFFFFFFF;

            min_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
            downlink_one_way_delay = 0;

            downlink_queueing_delay = 0;
            downlink_queueing_length = 0;

            ack_downlink_one_way_delay = 0;
            min_ack_downlink_one_way_delay = 0x7FFFFFFFFFFFFFFF;
            thrughput_gradient = 0;
            
            thrughput_prediction = sent_bytes_counter = 0;
            
            cur_ack_TSval = 0;
            cur_ack_TSecr = 0;
            
            RTT_INST = 0;
            mean_throughput = INITIAL_RATE;
            
            
            increase_factor = 1.0;
            delay_threshold = 0;
        }
        
	~TCB()
	{
		pthread_cond_destroy(&m_eventConnStateAvailable);
		pthread_mutex_destroy(&mutex);
		for (int i = 0; i < MAX_CONN_STATES + 1; i ++)
		{
			if (conn[i] != NULL)
				conn[i] = NULL;
		}

	}
};

conn_state *conn_table[TOTAL_NUM_CONN];
TCB *tcb_table[TOTAL_NUM_CONN];

struct mem_pool
{
	state_array ex_tcb;
	//state_array ex_conn;
	pthread_cond_t m_eventConnStateAvailable;
	pthread_mutex_t mutex;

	u_int _size;

	mem_pool()
	{
		printf("MOBILE ACCELERATOR INITIALIZES THE CONNECTION TABLES\n");
		if ((test_file = fopen("parameters.txt", "r")) == NULL)
		{
			printf("file parameters.txt is missing or corrupted\n");
			exit(-1);
		}

		fscanf(test_file, "%u\n", &APP_PORT_NUM);
		fscanf(test_file, "%u\n", &APP_PORT_FORWARD);
		fscanf(test_file, "%u\n", &MAX_SEND_RATE);
		fscanf(test_file, "%u\n", &INITIAL_RATE);
		fscanf(test_file, "%u\n", &MIN_SEND_RATE);
		fscanf(test_file, "%u\n", &SND_BEYOND_WIN);
		fscanf(test_file, "%u\n", &NUM_PKT_BEYOND_WIN);
		fscanf(test_file, "%u\n", &BDP); // num of
		fscanf(test_file, "%u\n", &RTT_LIMIT); //us

		init_mem_pool();
	}

	void init_mem_pool()
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventConnStateAvailable, NULL );

		_size = 0;

		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			conn_table[i] = new conn_state(CIRCULAR_BUF_SIZE);
		}

		printf("CONN MEMORY ALLOCATED\n");

		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			tcb_table[i] = new TCB;
		}

		printf("TCB MEMORY ALLOCATED");

	}

	void inline add_tcb(u_int value)
	{
		ex_tcb.add(value);
	    pthread_cond_signal(&m_eventConnStateAvailable);
	}

	void inline flush()
	{
		ex_tcb.flush();
		_size = 0;
	}

	~mem_pool()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventConnStateAvailable);
		//delete[] conn_table;
		//delete[] tcb_table;
	}

}pool;

struct RateCtrlParam
{
	Forward* forward_it;
	u_int id;
};

u_int HashBernstein(const char *key, size_t len)
{
	u_int hash = 5381;
	for(u_int i = 0; i < len; ++i)
		hash = 33 * hash + key[i];
	return (hash ^ (hash >> 16)) % TOTAL_NUM_CONN;
}

struct conn_Htable
{
	u_int size;

	conn_Htable()
	{
		size = 0;
	}

	int Hash(const char *key, size_t len)
	{
		u_int i = HashBernstein(key, len);

		if (size == TOTAL_NUM_CONN)
			return -1;

		while(conn_table[i]->initial_time)
		{
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		size ++;

		return i;
	}

	int search(const char *key, size_t len, u_short cPort)
	{
		u_int i = HashBernstein(key, len);
		while (conn_table[i]->initial_time)
		{
			if (conn_table[i]->cPort == cPort)
				return i;
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		return -1;
	}

	void decrease()
	{
		if (size)
			size --;
	}

};
conn_Htable conn_hash;
struct tcb_Htable
{
	u_int size;

	tcb_Htable()
	{
		size = 0;
	}

	int Hash(const char *key, size_t len)
	{
		u_int i = HashBernstein(key, len);

		if (size == TOTAL_NUM_CONN)
			return -1;

		while(tcb_table[i]->initial_time)
		{
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		size ++;

		return i;
	}

	int search(const char *key, size_t len, ip_address *client_ip)
	{
		u_int i = HashBernstein(key, len);
		while (tcb_table[i]->initial_time)
		{
			if (memcmp(&tcb_table[i]->client_ip_address, client_ip, sizeof(ip_address)) == 0)
				return i;
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		return -1;
	}

	void decrease()
	{
		if (size)
			size --;
	}

};

tcb_Htable tcb_hash;

char *iptos(u_long_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  printf("%s\n",d->name); /* Name */
  if (d->description)
    printf("\tDescription: %s\n",d->description);  /* Description */

  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no"); /* Loopback Address*/
  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);

    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));

        break;

	  case AF_INET6:
		  printf("\tAddress Family Name: AF_INET6\n");
		  break;

	  default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}
void inline print_bw_info(u_short sport, u_int tcb_index)
{
#ifdef DEBUG
	printf("STATE %d BUFFER %u %u ACK %u INTERARRIVAL TIME %u RTT %u RTO %u RTT STD %u SENDING RATE %u AGGREGATE ESTIMATED RATE %u INDIVIDUAL APPROX ESTIMATED RATE %u INDIVIDUAL INSTAN ESTIMATED RATE %u CONNID %hu\n",
			tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd,
			tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size(), tcb_table[tcb_index]->conn[sport]->server_state.snd_una,
			tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->rto,
			tcb_table[tcb_index]->conn[sport]->rtt_std_dev, tcb_table[tcb_index]->send_rate, tcb_table[tcb_index]->rcv_thrughput_approx,
			tcb_table[tcb_index]->send_rate_upper, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, sport);
#endif
}
u_short inline CheckSum(u_short * buffer, u_int size)
{
    u_long_long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size)
    {
        cksum += *(u_char *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (u_short) (~cksum);
}
void inline init_retx_data_pkt(u_int tcb_index, u_short sport, u_int num_init)
{
	u_int index = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
	ForwardPkt *retx_pkt;

	for (u_int i = 0; i < num_init; i ++)
	{
		retx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(index);
		retx_pkt->snd_time = 0;
		index = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pktNext(index);
	}
}
BOOL inline check_buffer_empty(u_int tcb_index, u_short dport)
{
        BOOL empty = TRUE;
        u_short port;
        for (int i = 0; i < tcb_table[tcb_index]->states.num; i ++)
        {
            port = tcb_table[tcb_index]->states.state_id[i];
            if (tcb_table[tcb_index]->conn[port]->dataPktBuffer.pkts())
            {
                empty = FALSE;
                break;
            }            
        }
        
        return empty;
        
}
BOOL inline check_conn_state(u_int tcb_index)
{
    BOOL closed = TRUE;
    u_short port;
    
    for (int i = 0; i < tcb_table[tcb_index]->states.num; i ++)
    {
        port = tcb_table[tcb_index]->states.state_id[i];
        if (tcb_table[tcb_index]->conn[port]->server_state.state != CLOSED)
        {
            closed = FALSE;
            break;
        }            
    }

    return closed; 
}
void inline send_forward(DATA* data, struct pcap_pkthdr* header, u_char* pkt_data) //+ add const
{
	pthread_mutex_lock(&data->forward->mutex);
	while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
	ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
	data->forward->pktQueue.tailNext();
	data->forward->pktQueue.increase();
	pthread_cond_signal(&data->forward->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward->mutex);
}
void inline send_wait_forward(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data, u_short sport, u_short dport, u_int data_len, u_short ctrl_flag, u_int seq_num)
{
        pthread_mutex_lock(&data->forward->mutex);
        while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
                pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
        ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
        tmpForwardPkt->data = (void *)data;
        tmpForwardPkt->sPort = sport;
        tmpForwardPkt->dPort = dport;
        tmpForwardPkt->ctr_flag = ctrl_flag;
        tmpForwardPkt->data_len = data_len;
        tmpForwardPkt->seq_num = seq_num;
        memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
        memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
        data->forward->pktQueue.tailNext();
        data->forward->pktQueue.increase();
        pthread_cond_signal(&data->forward->m_eventElementAvailable);
        pthread_mutex_unlock(&data->forward->mutex);
}
void inline send_backward(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data)
{
	pthread_mutex_lock(&data->forward_back->mutex);
	while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);

	ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
	data->forward_back->pktQueue.tailNext();
	data->forward_back->pktQueue.increase();
	pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward_back->mutex);
}
void inline send_data_pkt(Forward* forward, ForwardPkt* tmpPkt)
{
	pthread_mutex_lock(&forward->mutex);
	while (forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&forward->m_eventSpaceAvailable, &forward->mutex);
	ForwardPkt *tmpForwardPkt = forward->pktQueue.tail();
	tmpForwardPkt->tcb = tmpPkt->tcb;
	tmpForwardPkt->index = tmpPkt->index;
	tmpForwardPkt->sPort = tmpPkt->sPort;
	tmpForwardPkt->dPort = tmpPkt->dPort;
	tmpForwardPkt->seq_num = tmpPkt->seq_num;
	tmpForwardPkt->data_len = tmpPkt->data_len;
        tmpForwardPkt->TSval = tmpPkt->TSval;
        tmpForwardPkt->ctr_flag = tmpPkt->ctr_flag;
	tmpForwardPkt->data = tmpPkt->data;
	memcpy(&(tmpForwardPkt->header), &(tmpPkt->header), sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, tmpPkt->pkt_data, tmpPkt->header.len);
	forward->pktQueue.tailNext();
	forward->pktQueue.increase();
	pthread_cond_signal(&forward->m_eventElementAvailable);
	pthread_mutex_unlock(&forward->mutex);

}
void inline send_ack_back(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, sack_header* sack)
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;
	struct pcap_pkthdr capHeader;


	if (sack->size())
	{
		tcp_sack tcpSackHeader;
		tcpSackHeader.pad_1 = 1;
		tcpSackHeader.pad_2 = 1;
		tcpSackHeader.kind = 5;
		tcpSackHeader.length = sack->size()*8+2;

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(tcp_sack)] = {0};
		u_short buffer_len;

		buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;

		for (int i = 0; i < sack->size(); i ++)
		{
			tcpSackHeader.sack_block[i].left_edge_block = htonl(sack->sack_list[i].left_edge_block);
			tcpSackHeader.sack_block[i].right_edge_block = htonl(sack->sack_list[i].right_edge_block);

		}

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;

		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);

		//tcpSackHeader.length = sack->size()*8+2 + (4-(sack->size()*8+2)%4);
		tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2) / 4 << 12 | ctr_bits);

		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);
		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header) + (u_short)tcpSackHeader.length + 2);

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		pthread_mutex_lock(&data->forward_back->mutex);
		while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);
		ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward_back->pktQueue.tailNext();
		data->forward_back->pktQueue.increase();
		pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward_back->mutex);


	}
	else
	{

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header)] = {0};
		u_short buffer_len;

		buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header);
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;

		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;

		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons(sizeof(tcp_header)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header));

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));

		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header));


		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));

		pthread_mutex_lock(&data->forward_back->mutex);
		while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);

		ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward_back->pktQueue.tailNext();
		data->forward_back->pktQueue.increase();
		pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward_back->mutex);

	}
}
void inline send_syn_ack_back(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, u_char* tcp_opt, u_short tcp_opt_len, u_char Buffer[])
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;

	struct pcap_pkthdr capHeader;

	u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len;

	//u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + 50] = {0};
	//u_char* Buffer = (u_char *)malloc(sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len); //
	memset(Buffer, 0, MTU);

	capHeader.ts.tv_sec = time(NULL);
	capHeader.ts.tv_usec = 0;
	capHeader.caplen = buffer_len;
	capHeader.len = buffer_len;

	memcpy(macHeader.mac_src, src_mac, 6);
	memcpy(macHeader.mac_dst, dst_mac, 6);
	macHeader.opt = htons(0x0800);

	ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
	ipHeader.tos = 0;
	ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len);
	ipHeader.identification = htons(data_id);
	ipHeader.flags_fo = 0x40;
	ipHeader.ttl = 128;
	ipHeader.proto = IPPROTO_TCP;
	ipHeader.crc = 0;
	ipHeader.saddr = src_address;
	ipHeader.daddr = dst_address;

	tcpHeader.sport = htons(src_port);
	tcpHeader.dport = htons(dst_port);
	tcpHeader.seq_num = htonl(seq);
	tcpHeader.ack_num = htonl(ack);
	tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + tcp_opt_len) / 4 << 12 | ctr_bits);
	tcpHeader.window = htons(awin);
	tcpHeader.crc = 0;
	tcpHeader.urg_pointer = 0;

	psdHeader.saddr = src_address;
	psdHeader.daddr = dst_address;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(sizeof(tcp_header) + tcp_opt_len);

	memcpy(Buffer, &psdHeader, sizeof(psd_header));
	memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
	memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), tcp_opt, tcp_opt_len);
	tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + tcp_opt_len + sizeof(psd_header));

	memset(Buffer, 0, MTU);
	memcpy(Buffer, &ipHeader, sizeof(ip_header));
	ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

	memset(Buffer, 0, MTU);
	memcpy(Buffer, &macHeader, sizeof(mac_header));
	memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
	memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
	memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), tcp_opt, tcp_opt_len);

	pthread_mutex_lock(&data->forward_back->mutex);
	while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);
	ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
        tmpForwardPkt->ctr_flag = ctr_bits;
        tmpForwardPkt->sPort = src_port;
        tmpForwardPkt->dPort = dst_port;
        tmpForwardPkt->seq_num = seq;
	memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
	data->forward_back->pktQueue.tailNext();
	data->forward_back->pktQueue.increase();
	pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward_back->mutex);

}
void inline send_win_update_forward(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, sack_header* sack)
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;

	struct pcap_pkthdr capHeader;


	if (sack->size())
	{
		tcp_sack tcpSackHeader;
		tcpSackHeader.pad_1 = 1;
		tcpSackHeader.pad_2 = 1;
		tcpSackHeader.kind = 5;
		tcpSackHeader.length = sack->size()*8 + 2;

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(tcp_sack)] = {0};
		u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2;
		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;
		for (int i = 0; i < sack->size(); i ++)
		{
			tcpSackHeader.sack_block[i].left_edge_block = htonl(sack->sack_list[i].left_edge_block);
			tcpSackHeader.sack_block[i].right_edge_block = htonl(sack->sack_list[i].right_edge_block);
		}
		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header) + (u_short)tcpSackHeader.length + 2);
		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		pthread_mutex_lock(&data->forward->mutex);
		while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
		ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward->pktQueue.tailNext();
		data->forward->pktQueue.increase();
		pthread_cond_signal(&data->forward->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward->mutex);

	}
	else
	{
		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header)] = {0};
		u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header);

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;
		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons(sizeof(tcp_header)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header));

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));

		pthread_mutex_lock(&data->forward->mutex);
		while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
		ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward->pktQueue.tailNext();
		data->forward->pktQueue.increase();
		pthread_cond_signal(&data->forward->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward->mutex);
	}
}
void inline frag_data_pkt(ForwardPkt *frag_pkt, u_int ack_num)
{
	u_char pkt_buffer[MTU];
	mac_header* mh = (mac_header *)frag_pkt->pkt_data;

	ip_header* ih = (ip_header *) (frag_pkt->pkt_data + 14);
	u_int ip_len = (ih->ver_ihl & 0xf) * 4;
	u_short total_len = ntohs(ih->tlen);
	u_short id = ntohs(ih->identification);

	tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
	u_short sport = ntohs(th->sport);
	u_short dport = ntohs(th->dport);
	u_int seq_num = ntohl(th->seq_num);
	//u_int ack_num = ntohl(th->ack_num);

	u_short window = ntohs(th->window);
	u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
	u_short ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
	u_short data_len = total_len - ip_len - tcp_len;


	assert(seq_num < ack_num);

	memcpy(ih + tcp_len, ih + tcp_len + (ack_num - seq_num), data_len - (ack_num - seq_num));
	frag_pkt->header.len = 14 + total_len - (ack_num - seq_num);
	ih->tlen = htons(total_len - (ack_num - seq_num));

	data_len = data_len - (ack_num - seq_num);

	th->seq_num = htonl(ack_num);
	th->crc = 0;

	memset(pkt_buffer, 0, MTU);
	psd_header psdHeader;

	psdHeader.saddr = ih->saddr;
	psdHeader.daddr = ih->daddr;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(tcp_len + data_len);

	memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
	memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);

	th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);

	ih->crc = 0;
	memset(pkt_buffer, 0, MTU);
	memcpy(pkt_buffer, ih, ip_len);

	ih->crc = CheckSum((u_short *)pkt_buffer, ip_len);

	frag_pkt->seq_num = ack_num;
	frag_pkt->data_len = data_len;
}






void inline data_size_in_flight(u_int tcb_index, u_int data_len)
{
        
    if (tcb_table[tcb_index]->pkts_transit >= data_len)
        tcb_table[tcb_index]->pkts_transit -= data_len; 
    else
        tcb_table[tcb_index]->pkts_transit = 0;
        
}

void inline bandwidth_probe(u_int tcb_index, u_int sport, u_long_long current_time, u_int cum_ack) {

    if (!tcb_table[tcb_index]->round_start) 
    {
        tcb_table[tcb_index]->last_snd_wnd = tcb_table[tcb_index]->snd_wnd;
        tcb_table[tcb_index]->snd_wnd_count = 0;
        tcb_table[tcb_index]->round_start = current_time;
        fprintf(stderr, "round start %lu\n", tcb_table[tcb_index]->round_start);
    } 
    
    
    if (tcb_table[tcb_index]->probe_state == 1) 
    {
        tcb_table[tcb_index]->snd_wnd += 1;    
        tcb_table[tcb_index]->snd_wnd_count += 1;
        
        if (current_time - tcb_table[tcb_index]->round_start > MIN_RTT / 4) 
        {
            tcb_table[tcb_index]->probe_state = 2;           
            tcb_table[tcb_index]->toggle = 0;
            tcb_table[tcb_index]->round_start = current_time;
           
            
        }
    }
    else if (tcb_table[tcb_index]->probe_state == 2) 
    {     
        tcb_table[tcb_index]->toggle += cum_ack;
        tcb_table[tcb_index]->snd_wnd_count += 1;    
    }
            
    if (tcb_table[tcb_index]->last_snd_wnd == tcb_table[tcb_index]->snd_wnd_count) 
    {
        tcb_table[tcb_index]->last_snd_wnd = tcb_table[tcb_index]->snd_wnd;
        
        if (tcb_table[tcb_index]->probe_state == 1) 
        {
            tcb_table[tcb_index]->round_start = 0;
            tcb_table[tcb_index]->snd_wnd_count = 0;
        }
        else if (tcb_table[tcb_index]->probe_state == 2) 
        {
            tcb_table[tcb_index]->snd_wnd ++;
            tcb_table[tcb_index]->snd_wnd_count = 0;
                
            if (current_time - tcb_table[tcb_index]->round_start > 10000) 
            {
                u_int rcv_bw = (u_long_long)tcb_table[tcb_index]->toggle *                          
                        (u_long_long)RESOLUTION / 
                        (u_long_long)(current_time - tcb_table[tcb_index]->round_start);

                tcb_table[tcb_index]->send_rate = 10000;
                                       
                tcb_table[tcb_index]->sliding_avg_window.interval = 250000;
                tcb_table[tcb_index]->sliding_avg_window.M = tcb_table[tcb_index]->sliding_avg_window.interval / tcb_table[tcb_index]->sliding_avg_window.delta;
                
                
                tcb_table[tcb_index]->increase_factor = 1.01;
                tcb_table[tcb_index]->delay_threshold = 11000;
                
                
                //tcb_table[tcb_index]->send_rate_upper = find_initial_rate_window(find_bw_level(rcv_bw), 10) * 1000;
                //tcb_table[tcb_index]->send_rate_lower = tcb_table[tcb_index]->send_rate_lower > tcb_table[tcb_index]->send_rate_upper / 10 ? 
                //    tcb_table[tcb_index]->send_rate_upper/10 : tcb_table[tcb_index]->send_rate_lower;

                tcb_table[tcb_index]->mean_throughput = rcv_bw;
                
                fprintf(stderr, "send_rate %u, rcv_bw: %u, count: %u interval: %lu", 
                        tcb_table[tcb_index]->send_rate, 
                        rcv_bw,
                        tcb_table[tcb_index]->toggle, 
                        tcb_table[tcb_index]->sliding_avg_window.interval     
                        );
                
                tcb_table[tcb_index]->probe_state = 0;
                
            }
            
            fprintf(stderr, "probe phase 2 snd_win: %u\n", tcb_table[tcb_index]->snd_wnd);
        
        }                
    }  
}




void inline log_data(u_short sport, u_int tcb_index)
{
    if (!tcb_table[tcb_index]->conn[sport]->rttFd)
    {
        char name[20];
        sprintf(name, "%u", sport);
        tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
    }

    
    /*fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n", 
        tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, 
        tcb_table[tcb_index]->conn[sport]->server_state.snd_una, 
        tcb_table[tcb_index]->conn[sport]->RTT, 
        tcb_table[tcb_index]->conn[sport]->RTT_IETF, 
        tcb_table[tcb_index]->conn[sport]->mdev, 
        tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev, 
        tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf, 
        tcb_table[tcb_index]->conn[sport]->rto, 
        tcb_table[tcb_index]->conn[sport]->rto_ietf, 
        tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, 
        tcb_table[tcb_index]->conn[sport]->cumul_ack, 
        tcb_table[tcb_index]->rcv_thrughput_approx, 
        tcb_table[tcb_index]->rcv_thrughput, 
        tcb_table[tcb_index]->send_rate, 
        tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytes(), 
        tcb_table[tcb_index]->conn[sport]->max_data_len);*/
    
    fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%u %hu %u %u %u\n",
        tcb_index,
        sport, 
        tcb_table[tcb_index]->conn[sport]->RTT, 
        tcb_table[tcb_index]->conn[sport]->downlink_queueing_length/tcb_table[tcb_index]->conn[sport]->max_data_len, 
        (tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay)
        //tcb_table[tcb_index]->conn[sport]->target_queue_len/tcb_table[tcb_index]->conn[sport]->max_data_len, 
        //tcb_table[tcb_index]->conn[sport]->send_rate/1000, 
        //tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput/1000, 
        //tcb_table[tcb_index]->conn[sport]->buffer_max/tcb_table[tcb_index]->conn[sport]->max_data_len
        );
}




void inline rcv_ack_downlink_queueing_len_w_rtt(u_int tcb_index, u_short sport, u_long_long rcv_time, u_int rtt, u_int min_rtt)
{
        
    if (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.size())
    {
        u_int i = tcb_table[tcb_index]->conn[sport]->sliding_avg_win.size() - 1;
        int size = tcb_table[tcb_index]->conn[sport]->sliding_avg_win.size();
        u_int downlink_queueing_length = 0;
        
        while (size && rtt - min_rtt > 
                rcv_time - tcb_table[tcb_index]->conn[sport]->sliding_avg_win.window[i].time) {
            downlink_queueing_length ++;
            i --;
            size --;
        }
                
        tcb_table[tcb_index]->downlink_queueing_length = downlink_queueing_length;
        
    }
}




void inline send_forward_with_params(DATA* data, struct pcap_pkthdr* header, u_char* pkt_data, 
                                    u_short sport, u_short dport, u_int data_len, 
                                    u_short ctrl_flag, u_int seq_num, u_int tcb_index)
{
    pthread_mutex_lock(&data->forward->mutex);
    while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
            pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
    ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
    tmpForwardPkt->data = (void *)data;
    tmpForwardPkt->sPort = sport;
    tmpForwardPkt->dPort = dport;
    tmpForwardPkt->ctr_flag = ctrl_flag;
    tmpForwardPkt->data_len = data_len;
    tmpForwardPkt->seq_num = seq_num;
    tmpForwardPkt->TSval = tcb_table[tcb_index]->cur_ack_TSval;
    tmpForwardPkt->tcb = tcb_index;
    memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
    memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
    data->forward->pktQueue.tailNext();
    data->forward->pktQueue.increase();
    pthread_cond_signal(&data->forward->m_eventElementAvailable);
    pthread_mutex_unlock(&data->forward->mutex);
    
}
/***********SoD queue length estimation***********/
void inline SoD_downlink_queue_length_est(u_int tcb_index, u_short sport)
{
    if (tcb_table[tcb_index]->sliding_tsval_window.size())
    {
        u_int i = tcb_table[tcb_index]->sliding_tsval_window.size() - 1;
        int size = tcb_table[tcb_index]->sliding_tsval_window.size();
        u_int downlink_queueing_length = 0;
                
        while (size && tcb_table[tcb_index]->downlink_queueing_delay >= (tcb_table[tcb_index]->cur_TSval - 
                tcb_table[tcb_index]->sliding_tsval_window.window[i].time) * tcb_table[tcb_index]->timestamp_granularity)
        {
            
            downlink_queueing_length ++; //tcb_table[tcb_index]->sliding_tsval_window.window[i].len;
            i --;
            size --;                         
        }
        
        if (downlink_queueing_length)    
            downlink_queueing_length --;            
            
        
        if (tcb_table[tcb_index]->downlink_queueing_length)
            tcb_table[tcb_index]->downlink_queueing_length = 0.875*tcb_table[tcb_index]->downlink_queueing_length + 
                    0.125*downlink_queueing_length;
        else
            tcb_table[tcb_index]->downlink_queueing_length = downlink_queueing_length;
            
        

    }
}
/***********TCP-RRE estimate queueing delay in the downlink************/
void inline downlink_queue_delay_estimator(u_int tcb_index, u_short sport, u_long_long send_time)
{
    if (tcb_table[tcb_index]->cur_TSecr && tcb_table[tcb_index]->cur_TSval)
    {
        tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay = (long long)tcb_table[tcb_index]->cur_TSval * 
                (long long)tcb_table[tcb_index]->timestamp_granularity - (long long)send_time;
        
        
        
        if (tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay > tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay)
        {
            /*
            printf("%lld %lld %lld %lld %u %u %u %lu\n", 
                tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay, 
                tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay, 
                    tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay - 
                tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput, 
                tcb_table[tcb_index]->conn[sport]->downlink_queueing_length, 
                    tcb_table[tcb_index]->cur_TSval, send_time);
            */
            
            tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay = tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay;          
            
            //exit(-1);
            
        }
        
        tcb_table[tcb_index]->conn[sport]->downlink_queueing_length = 
                (u_long_long)(tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay - 
                tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay) * 
                (u_long_long)tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput / 
                (u_long_long)RESOLUTION;
        
        
        /*
        printf("%lld %lld %lld %lld %u %u %u %lu\n", 
                tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay, 
                tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay, 
                tcb_table[tcb_index]->conn[sport]->downlink_one_way_delay - 
                tcb_table[tcb_index]->conn[sport]->min_downlink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput, 
                tcb_table[tcb_index]->conn[sport]->downlink_queueing_length, 
                    tcb_table[tcb_index]->cur_TSval, send_time);
         */
          
    }
}
/***********ATRC downlink queueing delay estimation for cumulative ACKs***********/
void inline rcv_ack_downlink_queueing_delay_est(u_int tcb_index, u_short sport, u_long_long send_time)
{
    if (tcb_table[tcb_index]->cur_TSecr && tcb_table[tcb_index]->cur_TSval)
    {
        tcb_table[tcb_index]->downlink_one_way_delay = (long long)tcb_table[tcb_index]->cur_TSval * 
                (long long)tcb_table[tcb_index]->timestamp_granularity - (long long)send_time;
                        
        if (tcb_table[tcb_index]->min_downlink_one_way_delay > tcb_table[tcb_index]->downlink_one_way_delay)
        {
            
            tcb_table[tcb_index]->min_downlink_one_way_delay = tcb_table[tcb_index]->downlink_one_way_delay;   
            
            /*
            printf("%lld %lld %lld %lld %u %u %u %lu\n", 
                tcb_table[tcb_index]->downlink_one_way_delay, 
                tcb_table[tcb_index]->min_downlink_one_way_delay, 
                    tcb_table[tcb_index]->downlink_one_way_delay - 
                tcb_table[tcb_index]->min_downlink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                tcb_table[tcb_index]->rcv_tsval_est_thruput, 
                tcb_table[tcb_index]->downlink_queueing_length, 
                    tcb_table[tcb_index]->cur_TSval, send_time);
            */                                                    
            
        }
                
        tcb_table[tcb_index]->downlink_queueing_delay = tcb_table[tcb_index]->downlink_one_way_delay - 
                tcb_table[tcb_index]->min_downlink_one_way_delay;
        
        if (tcb_table[tcb_index]->downlink_queueing_delay > 1000000) {
            fprintf(stderr, "%u %u %u %u %u\n", 
                    tcb_table[tcb_index]->downlink_queueing_delay, 
                    tcb_table[tcb_index]->min_downlink_one_way_delay, 
                    tcb_table[tcb_index]->cur_TSecr, 
                    tcb_table[tcb_index]->cur_TSval, 
                    send_time);
        }
            
        
        SoD_downlink_queue_length_est(tcb_index, sport);
        
        /*
        printf("%lld %lld %lld %lld %u %u %u %lu %u\n", 
                tcb_table[tcb_index]->downlink_one_way_delay, 
                tcb_table[tcb_index]->min_downlink_one_way_delay, 
                tcb_table[tcb_index]->downlink_one_way_delay - tcb_table[tcb_index]->min_downlink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                tcb_table[tcb_index]->rcv_tsval_est_thruput, 
                tcb_table[tcb_index]->downlink_queueing_length/MTU, 
                tcb_table[tcb_index]->cur_TSval, 
                send_time, 
                tcb_table[tcb_index]->minRTT);
        */
          
    }
}
/**********ATRC downloading queueing delay estimation for duplicated ACKs***********/
void inline rcv_dup_ack_downlink_queueing_delay_est(u_int tcb_index, u_short sport)
{
    if (tcb_table[tcb_index]->cur_TSval && tcb_table[tcb_index]->cur_TSecr) 
    {
        tcb_table[tcb_index]->downlink_one_way_delay = ((long long)tcb_table[tcb_index]->cur_TSval - (long long)tcb_table[tcb_index]->cur_TSecr) * 
                (long long)tcb_table[tcb_index]->timestamp_granularity;
        
        if (tcb_table[tcb_index]->min_downlink_one_way_delay > tcb_table[tcb_index]->downlink_one_way_delay)
        {
             tcb_table[tcb_index]->min_downlink_one_way_delay = tcb_table[tcb_index]->downlink_one_way_delay;  
        }
        
        tcb_table[tcb_index]->downlink_queueing_delay = tcb_table[tcb_index]->downlink_one_way_delay - 
                tcb_table[tcb_index]->min_downlink_one_way_delay;        
               
        SoD_downlink_queue_length_est(tcb_index, sport);
    }
}
/***********ATRC downloading queueing delay estimation for uploading data packets**********/
void inline rcv_data_downlink_queueing_delay_est(u_int tcb_index, u_short sport)
{
    if (tcb_table[tcb_index]->cur_TSval && tcb_table[tcb_index]->cur_TSecr)
    {
        tcb_table[tcb_index]->ack_downlink_one_way_delay = ((long long)tcb_table[tcb_index]->cur_TSval - (long long)tcb_table[tcb_index]->cur_TSecr) * 
                (long long)tcb_table[tcb_index]->timestamp_granularity;
        
        if (tcb_table[tcb_index]->min_ack_downlink_one_way_delay > tcb_table[tcb_index]->ack_downlink_one_way_delay)
        {
             tcb_table[tcb_index]->min_ack_downlink_one_way_delay = tcb_table[tcb_index]->ack_downlink_one_way_delay;  
        }
        
        tcb_table[tcb_index]->downlink_queueing_delay = tcb_table[tcb_index]->ack_downlink_one_way_delay - 
                tcb_table[tcb_index]->min_ack_downlink_one_way_delay;        
               
        SoD_downlink_queue_length_est(tcb_index, sport);
        
        /*
        printf("%lld %lld %lld %lld %u %u %u %u %u\n", 
                tcb_table[tcb_index]->ack_downlink_one_way_delay, 
                tcb_table[tcb_index]->min_ack_downlink_one_way_delay, 
                tcb_table[tcb_index]->ack_downlink_one_way_delay - 
                tcb_table[tcb_index]->min_ack_downlink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                tcb_table[tcb_index]->rcv_tsval_est_thruput, 
                tcb_table[tcb_index]->downlink_queueing_length, 
                tcb_table[tcb_index]->cur_TSval, 
                tcb_table[tcb_index]->cur_TSval, 
                tcb_table[tcb_index]->minRTT);
        */
    }
}
/***********RSFC data uplink queueing delay estimation***********/
void inline rcv_data_uplink_delay_var(u_int tcb_index, u_short sport, u_long_long rcv_time, u_int ack_num)
{
   
    if (tcb_table[tcb_index]->cur_TSecr && tcb_table[tcb_index]->cur_TSval)
    {
        tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay = (long long)rcv_time - (long long)tcb_table[tcb_index]->cur_TSval * 
                (long long)tcb_table[tcb_index]->timestamp_granularity;
        
        if (tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay > tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay)
        {
                                   
            tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay = tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay;          
            
            /*
            printf("%lld %lld %lld %lld %u %u %u %lu\n", 
                    tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay, 
                    tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay, 
                    tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                    (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                    tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                    tcb_table[tcb_index]->cur_TSval, 
                    tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                    rcv_time);
            */
            
            //exit(-1);
            
        }
        
        tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay = 
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay;
        
        /*
        printf("%lld %lld %lld %lld %u %u %u %lu\n",
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                (long long) tcb_table[tcb_index]->cur_TSval * (long long) tcb_table[tcb_index]->timestamp_granularity,
                tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                tcb_table[tcb_index]->cur_TSval,
                tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                rcv_time);
        */
    }
}






void inline RTT_estimator(ForwardPkt *unAckPkt, u_long_long snd_time, u_long_long rcv_time, u_int ack_num, u_short sport, u_int tcb_index)
{
#ifdef LINUX_RTT
    
	if (tcb_table[tcb_index]->RTT)
	{
            if (ack_num <= tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno)
            {
                    if (rcv_time - snd_time < tcb_table[tcb_index]->conn[sport]->RTT && abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) > tcb_table[tcb_index]->conn[sport]->mdev)
                            tcb_table[tcb_index]->conn[sport]->mdev = (tcb_table[tcb_index]->conn[sport]->mdev >= 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) ? tcb_table[tcb_index]->conn[sport]->mdev : 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))));
                    else
                            tcb_table[tcb_index]->conn[sport]->mdev = (tcb_table[tcb_index]->conn[sport]->mdev >= 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) ? tcb_table[tcb_index]->conn[sport]->mdev : 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))));

            }
            else if (ack_num > tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno && tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts())
            {
                    tcb_table[tcb_index]->conn[sport]->rtt_std_dev = tcb_table[tcb_index]->conn[sport]->mdev;
                    if (rcv_time - snd_time < tcb_table[tcb_index]->conn[sport]->RTT && abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) > tcb_table[tcb_index]->conn[sport]->mdev)
                            tcb_table[tcb_index]->conn[sport]->mdev = 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time)));
                    else
                            tcb_table[tcb_index]->conn[sport]->mdev = 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time)));

                    tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;
            }


            tcb_table[tcb_index]->conn[sport]->RTT = 0.875 * tcb_table[tcb_index]->conn[sport]->RTT + 0.125 * (rcv_time - snd_time);
            tcb_table[tcb_index]->RTT_INST = rcv_time - snd_time;
            tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;

            tcb_table[tcb_index]->RTT = 0.875 * tcb_table[tcb_index]->RTT + 0.125 * (rcv_time - snd_time);
            tcb_table[tcb_index]->conn[sport]->rto = (MAX_RTO >= tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev ? MAX_RTO : tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev);

	}
	else
	{
            tcb_table[tcb_index]->conn[sport]->RTT = rcv_time - snd_time;
            tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;
            tcb_table[tcb_index]->RTT_INST = rcv_time - snd_time;
            tcb_table[tcb_index]->RTT = rcv_time - snd_time;     
            tcb_table[tcb_index]->conn[sport]->rtt_std_dev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
            tcb_table[tcb_index]->conn[sport]->mdev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
            tcb_table[tcb_index]->conn[sport]->rto = (MAX_RTO >= tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev ? MAX_RTO : tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev);
            tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

	}
#endif

#ifdef STD_RTT
	if (tcb_table[tcb_index]->conn[sport]->RTT_IETF)
	{
		if (ack_num > tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf)
		{
			tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf = 0.75 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf + 0.25 * abs(((long)(rcv_time - snd_time) - tcb_table[tcb_index]->conn[sport]->RTT_IETF));
			tcb_table[tcb_index]->conn[sport]->RTT_IETF = 0.875 * tcb_table[tcb_index]->conn[sport]->RTT_IETF + 0.125 * (rcv_time - snd_time);
			tcb_table[tcb_index]->RTT = 0.875 * tcb_table[tcb_index]->RTT + 0.125 * (rcv_time - snd_time);
			tcb_table[tcb_index]->RTT_INST = rcv_time - snd_time;
                        tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;
			tcb_table[tcb_index]->conn[sport]->rto_ietf = (MAX_RTO_IETF >= tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf ? MAX_RTO_IETF : tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf);
			tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

		}

	}
	else
	{
		tcb_table[tcb_index]->conn[sport]->RTT_IETF = rcv_time - snd_time;
		tcb_table[tcb_index]->RTT = rcv_time - snd_time;
                tcb_table[tcb_index]->RTT_INST = rcv_time - snd_time;
		tcb_table[tcb_index]->conn[sport]->LAST_RTT = tcb_table[tcb_index]->conn[sport]->RTT_IETF;
		tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf = tcb_table[tcb_index]->conn[sport]->RTT_IETF / 2;
		tcb_table[tcb_index]->conn[sport]->rto_ietf = (MAX_RTO_IETF >= tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf ? MAX_RTO_IETF : tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf);
		tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

	}
#endif

	if (tcb_table[tcb_index]->minRTT > tcb_table[tcb_index]->RTT_INST)
	{
            tcb_table[tcb_index]->minRTT = tcb_table[tcb_index]->RTT_INST;
            tcb_table[tcb_index]->ref_rcv_time = rcv_time;
            tcb_table[tcb_index]->ref_TSval = tcb_table[tcb_index]->cur_TSval;
        }
        
        
#ifdef TCP-RRE        
            downlink_queue_delay_estimator(tcb_index, sport, snd_time);
#else
#ifdef DOWNLINK_QUEUE_LEN_EST
            rcv_ack_downlink_queueing_delay_est(tcb_index, sport, snd_time);
#else
            rcv_ack_downlink_queueing_len_w_rtt(tcb_index, sport, rcv_time, tcb_table[tcb_index]->RTT, tcb_table[tcb_index]->minRTT);
#endif       
            
#endif
   
}






void inline BW_adaptation(u_short sport, u_int tcb_index)
{
	if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL && tcb_table[tcb_index]->conn[sport]->RTT)
	{
	        /*
	        if (tcb_table[tcb_index]->conn[sport]->RTT >= 1000000)
	        {
	            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
                    {
                            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
                            print_bw_info(sport, tcb_index);
                    }
	            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
                    {
                            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
                            print_bw_info(sport, tcb_index);
                    }
	        }
                */
	        if (tcb_table[tcb_index]->conn[sport]->RTT > tcb_table[tcb_index]->conn[sport]->RTT_limit)
		{
			if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
			{
				tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
				print_bw_info(sport, tcb_index);
			}
		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT <= tcb_table[tcb_index]->conn[sport]->RTT_limit)
		{
			if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else
			{
                               //tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
                               //tcb_table[tcb_index]->send_rate = 0.675 * tcb_table[tcb_index]->send_rate + 0.375 * tcb_table[tcb_index]->send_rate_upper;    
                               //print_bw_info(sport, tcb_index);

			}
		}

	}
	else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX && tcb_table[tcb_index]->conn[sport]->RTT)
	{
             if (tcb_table[tcb_index]->conn[sport]->RTT > tcb_table[tcb_index]->conn[sport]->RTT_limit)
	    {    
                if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
		{
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
			print_bw_info(sport, tcb_index);
		}
		else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
		{
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
			print_bw_info(sport, tcb_index);
		}
		else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
		{
			tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
			print_bw_info(sport, tcb_index);
		}
            }
             /*
            else
            {
                if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
                {
                        tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
                        print_bw_info(sport, tcb_index);
                }
                else
                {
                        tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;                       

                        print_bw_info(sport, tcb_index);

                }
            }
             */
	}
}



#define BUFFER_UNDERFLOW SLIDE_TIME_INTERVAL/(1.5 * SLIDE_TIME_DELTA)

void inline update_unsent_bytes(u_int tcb_index, u_long_long current_time)
{
             
        if (tcb_table[tcb_index]->RTT > tcb_table[tcb_index]->RTT_limit && 
                tcb_table[tcb_index]->RTT <= tcb_table[tcb_index]->RTT_limit + DELAY_TOLERANCE)
        {
            
            if (current_time > tcb_table[tcb_index]->sliding_avg_window.reload_time &&                    
                    !tcb_table[tcb_index]->sliding_avg_window.lower_heuristic && 
                    tcb_table[tcb_index]->sliding_avg_window._stack_size &&
                    tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len > 0 && 
                    tcb_table[tcb_index]->sliding_avg_window.underflow_time >= BUFFER_UNDERFLOW &&
                    tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 2].sign
                    )
            {                                  
                u_long_long rcv_thrughput = tcb_table[tcb_index]->rcv_thrughput_approx;                
                    
                u_long_long bytes_should_sent = rcv_thrughput * (u_long_long)(current_time - tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k-1].time) / 
                        (u_long_long)RESOLUTION;

                long unsent_bytes_sent = tcb_table[tcb_index]->sent_bytes_counter - (long)bytes_should_sent;
                
                if (unsent_bytes_sent > 0)
                {
                    tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len = 
                            (tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len > 
                            unsent_bytes_sent ? tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len - 
                            unsent_bytes_sent : 0);
                    
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes = (tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes > 
                            unsent_bytes_sent ? tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes - unsent_bytes_sent : 0);                    
                    
                }
                
            }              
        }
}





#ifndef DOWNLINK_QUEUE_LEN_EST
void inline BandwidthAdaptation(u_int tcb_index, u_long_long current_time)
{
    if (tcb_table[tcb_index]->RTT)
    {        
        /*
        if (tcb_table[tcb_index]->RTT >= 1000000)
        {
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
            }
        }
        */        
                 
        if (tcb_table[tcb_index]->RTT > tcb_table[tcb_index]->RTT_limit + tcb_table[tcb_index]->delay_threshold) //if (tcb_table[tcb_index]->downlink_queueing_length > 80*MTU)
        {
            if (!tcb_table[tcb_index]->sliding_avg_window.upper_heuristic)            
            {
                tcb_table[tcb_index]->sliding_avg_window.upper_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_0;                                       
                tcb_table[tcb_index]->sliding_avg_window.buffer_drain_start_time = current_time;
            }
            
            tcb_table[tcb_index]->send_rate = (u_long_long)tcb_table[tcb_index]->rcv_thrughput_approx * (u_long_long)(MIN_RTT + QUEUE_DELAY_TARGET) / 
                    (u_long_long)tcb_table[tcb_index]->RTT;
            
            tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->send_rate > tcb_table[tcb_index]->send_rate_upper ? 
                tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->send_rate);
            
            tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->send_rate < tcb_table[tcb_index]->send_rate_lower ? 
                tcb_table[tcb_index]->send_rate_lower : tcb_table[tcb_index]->send_rate);
                                 
            fprintf(stderr, "buffer draining: RTT %u bw %u rate %u mean %u u_size %u uu %d h0 %ld h1 %ld h2 %ld min %u max %u "
                    "stack %u Q %u nb %u pos %u port %hu\n",
                    tcb_table[tcb_index]->RTT,
                    tcb_table[tcb_index]->rcv_thrughput_approx,
                    tcb_table[tcb_index]->send_rate,
                    tcb_table[tcb_index]->mean_throughput,
                    tcb_table[tcb_index]->sliding_avg_window._u_size,
                    tcb_table[tcb_index]->unsent_size,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_0,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_1,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_2,
                    tcb_table[tcb_index]->send_rate_lower,
                    tcb_table[tcb_index]->send_rate_upper,
                    tcb_table[tcb_index]->sliding_avg_window._stack_size,
                    tcb_table[tcb_index]->downlink_queueing_length,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes,//tcb_table[tcb_index]->sliding_avg_window.unsent_nb_pos(tcb_table[tcb_index]->rcv_thrughput_approx),                 
                    tcb_table[tcb_index]->sliding_avg_window.nb_unsent_pos,
                    tcb_table[tcb_index]->states.state_id[tcb_table[tcb_index]->states.num-1]
                    );
            
                                                  
        }
        else if (tcb_table[tcb_index]->RTT > tcb_table[tcb_index]->RTT_limit)
        {   
                              
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->increase_factor * (double)tcb_table[tcb_index]->rcv_thrughput_approx;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? 
                    tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);            
            }
                        
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->increase_factor * tcb_table[tcb_index]->rcv_thrughput_approx;
            
            if (tcb_table[tcb_index]->sliding_avg_window.upper_heuristic) 
            {                                 
                tcb_table[tcb_index]->sliding_avg_window.upper_heuristic = 0;  
                tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_2;
                                                
                tcb_table[tcb_index]->sliding_avg_window.put_stack(tcb_table[tcb_index]->sliding_avg_window.unsent_data, 0, 0, 0, 0);
                tcb_table[tcb_index]->sliding_avg_window.unsent_data = 0;
                               
                tcb_table[tcb_index]->sliding_avg_window.buffer_drain_interval = 
                        current_time - tcb_table[tcb_index]->sliding_avg_window.buffer_drain_start_time;
            }

#define UNDERFLOW_THRESHOLD 0
            
            if (tcb_table[tcb_index]->sliding_avg_window.lower_heuristic)
            {
                if (!tcb_table[tcb_index]->sliding_avg_window._u_size &&  
                        (tcb_table[tcb_index]->RTT < tcb_table[tcb_index]->RTT_limit + 0.0008 * RESOLUTION &&
                        tcb_table[tcb_index]->downlink_queueing_length <= UNDERFLOW_THRESHOLD))
                {
                    tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = 0;                     
                    tcb_table[tcb_index]->sliding_avg_window.reload_time = current_time + 
                            tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time);                   
                    tcb_table[tcb_index]->sliding_avg_window.underflow_time = 1;
                           
               
                    
                    tcb_table[tcb_index]->sliding_avg_window.make_up_bw = 
                            (tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes > 0 ? 
                                tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes:0);
                                        
                }                                                                                                                         
            }            


#define RATE_THRESHOLD 600000 
            
            if (!tcb_table[tcb_index]->sliding_avg_window.lower_heuristic && 
                    tcb_table[tcb_index]->sliding_avg_window._stack_size && 
                    tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len > 0)
            {                               
                                             
                if ((tcb_table[tcb_index]->RTT < tcb_table[tcb_index]->RTT_limit + 0.0008 * RESOLUTION && 
                         tcb_table[tcb_index]->downlink_queueing_length <= UNDERFLOW_THRESHOLD) || 
                        (tcb_table[tcb_index]->RTT < tcb_table[tcb_index]->RTT_limit + 0.0008 * RESOLUTION && 
                        tcb_table[tcb_index]->rcv_thrughput_approx < RATE_THRESHOLD))
                {
                    
                    if (current_time > tcb_table[tcb_index]->sliding_avg_window.reload_time)
                    {
                         if (tcb_table[tcb_index]->sliding_avg_window.underflow_time >= BUFFER_UNDERFLOW)
                         {
                                                
            
                             
                             if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_lower)
                                 tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->sliding_avg_window.make_up_bw / 
                                        (1.0 *tcb_table[tcb_index]->RTT_limit / tcb_table[tcb_index]->sliding_avg_window.delta), current_time, 0);
                             else
                                 tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->sliding_avg_window.make_up_bw / 
                                        (5.0 *tcb_table[tcb_index]->RTT_limit/tcb_table[tcb_index]->sliding_avg_window.delta), current_time, 0);
                            
                            tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) == 0 ? 
                                tcb_table[tcb_index]->send_rate_upper : (u_long_long)(tcb_table[tcb_index]->sliding_avg_window.bytes()) * 
                                    (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time)); 
                            
                            tcb_table[tcb_index]->send_rate = 
                                    (tcb_table[tcb_index]->send_rate > tcb_table[tcb_index]->send_rate_upper ? 
                                        tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->send_rate);

                            tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 1].sign = TRUE;


                            fprintf(stderr, "-----------monitor state: rate %u bw %u under_flow: %u----------\n",
                                    tcb_table[tcb_index]->send_rate,
                                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                                    tcb_table[tcb_index]->sliding_avg_window.underflow_time);
                         }
                         else
                         {
                            tcb_table[tcb_index]->sliding_avg_window.make_up_bw = 0;
                            tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_2; 
                         }
                    }
                    else
                    {
                        
                        tcb_table[tcb_index]->sliding_avg_window.underflow_time ++;                    
                    }
                }
               
            }
            else if (!tcb_table[tcb_index]->sliding_avg_window.lower_heuristic && 
                    tcb_table[tcb_index]->sliding_avg_window._stack_size &&
                    tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len <= 0)
            {                              
                                
                tcb_table[tcb_index]->sliding_avg_window._stack_size --;
                if (!tcb_table[tcb_index]->sliding_avg_window._stack_size)
                {
                    tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_2; 
                    tcb_table[tcb_index]->sliding_avg_window.make_up_bw = 0;
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes = 0;
                }
            }
                 
            
            
            fprintf(stderr, "rate adaptation: RTT %u bw %u rate %u mean %u u_size %u uu %d h0 %ld h1 %ld h2 %ld min %u max %u "
                    "stack %u Q %u nb %u pos %u port %hu\n", 
                    tcb_table[tcb_index]->RTT, 
                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                    tcb_table[tcb_index]->send_rate, 
                    tcb_table[tcb_index]->mean_throughput, 
                    tcb_table[tcb_index]->sliding_avg_window._u_size,
                    tcb_table[tcb_index]->unsent_size,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_0,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_1, 
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_2, 
                    tcb_table[tcb_index]->send_rate_lower,
                    tcb_table[tcb_index]->send_rate_upper,
                    tcb_table[tcb_index]->sliding_avg_window._stack_size, 
                    tcb_table[tcb_index]->downlink_queueing_length,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes,                  
                    tcb_table[tcb_index]->sliding_avg_window.nb_unsent_pos,
                    tcb_table[tcb_index]->states.state_id[tcb_table[tcb_index]->states.num-1]
                    );
            
        } 
        else
        {
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate;                
            
            
           
            fprintf(stderr, "buffer fillup: RTT: %u  bw: %u send rate: %u upper: %ld lower: %ld h: %ld h0: %ld h1: %ld h2: %ld unsent: %ld add_unsent: %ld burst_unsent: %ld\n", 
                    tcb_table[tcb_index]->RTT, 
                    tcb_table[tcb_index]->rcv_thrughput_approx,
                    tcb_table[tcb_index]->send_rate,
                    tcb_table[tcb_index]->sliding_avg_window.upper_heuristic, 
                    tcb_table[tcb_index]->sliding_avg_window.lower_heuristic,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_0,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_1, 
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_2, 
                    tcb_table[tcb_index]->sliding_avg_window.unsent_data,                    
                    tcb_table[tcb_index]->sliding_avg_window.unsent_data_due_schedule_delay,
                    tcb_table[tcb_index]->sliding_avg_window.init_burst_unsent_bytes
                    );
            
        }
                
    }
    
    
}

#else 
/*
void inline BandwidthAdaptation(u_int tcb_index)
{
    if (tcb_table[tcb_index]->RTT)
    {                
        if (tcb_table[tcb_index]->downlink_queueing_length > BW_DELAY_PRO/5)
        {
                                                          
            tcb_table[tcb_index]->send_rate = (u_long_long)tcb_table[tcb_index]->rcv_thrughput_approx > 
                    (u_long_long)(tcb_table[tcb_index]->downlink_queueing_length - BW_DELAY_PRO/6) * (u_long_long)RESOLUTION /
                    (u_long_long)(tcb_table[tcb_index]->downlink_queueing_delay + tcb_table[tcb_index]->delay_var + tcb_table[tcb_index]->minRTT) ? (u_long_long)tcb_table[tcb_index]->rcv_thrughput_approx -
                    (u_long_long)(tcb_table[tcb_index]->downlink_queueing_length - BW_DELAY_PRO/6) * (u_long_long)RESOLUTION /
                    (u_long_long)(tcb_table[tcb_index]->downlink_queueing_delay + tcb_table[tcb_index]->delay_var + tcb_table[tcb_index]->minRTT) : tcb_table[tcb_index]->rcv_thrughput_approx;
            
            
            //downlink_queueing_delay + tcb_table[tcb_index]->delay_var + tcb_table[tcb_index]->minRTT);
            
            tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->send_rate <= tcb_table[tcb_index]->send_rate_upper ? 
                    tcb_table[tcb_index]->send_rate : tcb_table[tcb_index]->send_rate_upper);
            
            if (tcb_table[tcb_index]->RTT > tcb_table[tcb_index]->RTT_limit - 10000)
            {                
                //tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
            }
            
        }
        else if (tcb_table[tcb_index]->downlink_queueing_length <= BW_DELAY_PRO/5 && 
                tcb_table[tcb_index]->downlink_queueing_length > BW_DELAY_PRO/8)
        {
            
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower) 
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
            } 
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate) 
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
            } 
            else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate) 
            {
                tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? 
                    tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
            }
            
            if (tcb_table[tcb_index]->RTT > tcb_table[tcb_index]->RTT_limit - 10000)
            {
                
                //tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
            }
            
        }
        else
        {                        
            if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
            }
            else
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;                
            }

            tcb_table[tcb_index]->unsent_data_bytes = 0;            
        }
    }
}
*/

void inline BandwidthAdaptation(u_int tcb_index, u_long_long current_time)
{
    if (tcb_table[tcb_index]->RTT)
    {                
        if (tcb_table[tcb_index]->downlink_queueing_delay > tcb_table[tcb_index]->delay_threshold)
        {
            if (!tcb_table[tcb_index]->sliding_avg_window.upper_heuristic)            
            {
                tcb_table[tcb_index]->sliding_avg_window.upper_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_0;                                       
                tcb_table[tcb_index]->sliding_avg_window.buffer_drain_start_time = current_time;
            }
            
            tcb_table[tcb_index]->send_rate = (u_long_long)tcb_table[tcb_index]->rcv_thrughput_approx * (u_long_long)(MIN_RTT) 
                    / (u_long_long)(tcb_table[tcb_index]->downlink_queueing_delay + MIN_RTT);
            
            tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->send_rate < tcb_table[tcb_index]->send_rate_lower ? 
                tcb_table[tcb_index]->send_rate_lower : tcb_table[tcb_index]->send_rate);
                                 
            fprintf(stderr, "buffer draining: RTT %u dd %u bw %u rate %u ud %d uq %u tsbw %u us %d c %d unsent %u u_rr %u "
                    "stack %u dq %u nb %u pos %u port %hu\n",
                    tcb_table[tcb_index]->RTT,
                    tcb_table[tcb_index]->downlink_queueing_delay,
                    tcb_table[tcb_index]->rcv_thrughput_approx,
                    tcb_table[tcb_index]->send_rate,
                    tcb_table[tcb_index]->delay_var,
                    tcb_table[tcb_index]->delay_size,
                    tcb_table[tcb_index]->rcv_tsval_est_thruput,
                    tcb_table[tcb_index]->sliding_avg_window._u_size,
                    tcb_table[tcb_index]->sliding_avg_window.size(),
                    (tcb_table[tcb_index]->sliding_avg_window._stack_size ? 
                        tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size - 1].len : 0),
                    tcb_table[tcb_index]->sliding_avg_window.unsent_bytes_rr,
                    tcb_table[tcb_index]->sliding_avg_window._stack_size,
                    tcb_table[tcb_index]->downlink_queueing_length,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes,//tcb_table[tcb_index]->sliding_avg_window.unsent_nb_pos(tcb_table[tcb_index]->rcv_thrughput_approx),                 
                    tcb_table[tcb_index]->sliding_avg_window.nb_unsent_pos,
                    tcb_table[tcb_index]->states.state_id[tcb_table[tcb_index]->states.num-1]
                    );
            
        }
        else if (tcb_table[tcb_index]->downlink_queueing_delay > 5)
        {   
                                   
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->increase_factor * tcb_table[tcb_index]->rcv_thrughput_approx;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? 
                    tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);            
            }
           
            if (tcb_table[tcb_index]->sliding_avg_window.upper_heuristic) 
            {                                 
                tcb_table[tcb_index]->sliding_avg_window.upper_heuristic = 0;  
                tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = tcb_table[tcb_index]->sliding_avg_window.heuristic_2;
                                                
                tcb_table[tcb_index]->sliding_avg_window.put_stack(tcb_table[tcb_index]->sliding_avg_window.unsent_data, 0, 0, 0, 0);
                
                tcb_table[tcb_index]->sliding_avg_window.unsent_data = 0;
                               
                tcb_table[tcb_index]->sliding_avg_window.buffer_drain_interval = 
                        current_time - tcb_table[tcb_index]->sliding_avg_window.buffer_drain_start_time;
            }

            if (tcb_table[tcb_index]->sliding_avg_window.lower_heuristic)
            {
                tcb_table[tcb_index]->sliding_avg_window.lower_heuristic = 0;                                                                                                                                                              
            }            
                  
            fprintf(stderr, "rate adaptation: RTT %u dd %u bw %u rate %u ud %d uq %u tsbw %u us %d c %d unsent %u u_rr %u "
                    "stack %u dq %u nb %u pos %u port %hu\n", 
                    tcb_table[tcb_index]->RTT,
                    tcb_table[tcb_index]->downlink_queueing_delay,
                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                    tcb_table[tcb_index]->send_rate, 
                    tcb_table[tcb_index]->delay_var,
                    tcb_table[tcb_index]->delay_size,
                    tcb_table[tcb_index]->rcv_tsval_est_thruput, 
                    tcb_table[tcb_index]->sliding_avg_window._u_size,
                    tcb_table[tcb_index]->sliding_avg_window.size(),                    
                    (tcb_table[tcb_index]->sliding_avg_window._stack_size ? 
                        tcb_table[tcb_index]->sliding_avg_window.unsent_stack[tcb_table[tcb_index]->sliding_avg_window._stack_size-1].len : 0),                    
                    tcb_table[tcb_index]->sliding_avg_window.unsent_bytes_rr,
                    tcb_table[tcb_index]->sliding_avg_window._stack_size, 
                    tcb_table[tcb_index]->downlink_queueing_length,
                    tcb_table[tcb_index]->sliding_avg_window.heuristic_bytes, //tcb_table[tcb_index]->sliding_avg_window.unsent_nb_pos(tcb_table[tcb_index]->rcv_thrughput_approx),                    
                    tcb_table[tcb_index]->sliding_avg_window.nb_unsent_pos,
                    tcb_table[tcb_index]->states.state_id[tcb_table[tcb_index]->states.num-1]
                    );
            
        }                 
    }       
}

#endif






/***********ATRC estimates the delayed data size***********/
void inline tcb_est_delay_size(u_int tcb_index)
{
    u_int current_delay_size = (u_long_long)tcb_table[tcb_index]->rcv_tsval_est_thruput * (u_long_long)tcb_table[tcb_index]->delay_var / (u_long_long)RESOLUTION;                        
    tcb_table[tcb_index]->unsent_size = tcb_table[tcb_index]->unsent_size + (int)(current_delay_size - tcb_table[tcb_index]->delay_size);
    tcb_table[tcb_index]->delay_size = current_delay_size;
    
}





/**********ATRC forecast the throughput of the next propagation delay*****************/
void inline atrc_thrughput_prediction(u_int tcb_index, u_long_long current_time)
{
    
    tcb_table[tcb_index]->thrughput_gradient = (tcb_table[tcb_index]->sliding_gradient_window.estmateInterval(current_time) == 0 ? 
        0 : ((long long)tcb_table[tcb_index]->sliding_gradient_window.tail() - (long long)tcb_table[tcb_index]->sliding_gradient_window.head()) * (long long)RESOLUTION / 
            (long long)tcb_table[tcb_index]->sliding_gradient_window.estmateInterval(current_time));

    tcb_table[tcb_index]->thrughput_prediction = (long long)tcb_table[tcb_index]->thrughput_gradient * (long long)MIN_RTT / (long long)RESOLUTION + (long long)tcb_table[tcb_index]->rcv_thrughput_approx < 0 ? 
        0 : (long long)tcb_table[tcb_index]->thrughput_gradient * (long long)MIN_RTT / (long long)RESOLUTION + tcb_table[tcb_index]->rcv_thrughput_approx;
    
}





/**********ATRC estimates the uplink bandwidth***********/
void inline tcb_uplink_bw_est(u_int tcb_index, u_long_long current_time)
{
    if (tcb_table[tcb_index]->sliding_uplink_window.sample_time)
    {
        if (tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time) >= tcb_table[tcb_index]->sliding_uplink_window.interval)
        {
            tcb_table[tcb_index]->rcv_uplink_thruput = (tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time) == 0 ? 
		    MAX_UPLINK_BW : (u_long_long)tcb_table[tcb_index]->sliding_uplink_window.bytes() * 
		    (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time));
            
            tcb_table[tcb_index]->rcv_uplink_thruput_approx = 0 * tcb_table[tcb_index]->rcv_uplink_thruput_approx + 
                    1 * tcb_table[tcb_index]->rcv_uplink_thruput;        
            
            tcb_table[tcb_index]->sliding_uplink_window.nextEstmateSampleTime(current_time);
            tcb_table[tcb_index]->sliding_uplink_window.another_shift();         
            
            if (tcb_table[tcb_index]->sliding_uplink_window.k < tcb_table[tcb_index]->sliding_uplink_window.interval / tcb_table[tcb_index]->sliding_uplink_window.delta)         
                  tcb_table[tcb_index]->sliding_uplink_window.k = tcb_table[tcb_index]->sliding_uplink_window.interval / tcb_table[tcb_index]->sliding_uplink_window.delta;
                  
            if (tcb_table[tcb_index]->sliding_uplink_window.size() < 5)
            {
                tcb_table[tcb_index]->sliding_uplink_window.flush();                
            }
        }
        else
        {            
           
            if (tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time) >= 
                tcb_table[tcb_index]->sliding_uplink_window.k * tcb_table[tcb_index]->sliding_uplink_window.delta)
            {   
                tcb_table[tcb_index]->rcv_uplink_thruput = (tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time) == 0 ? 
                    MAX_UPLINK_BW : (u_long_long)tcb_table[tcb_index]->sliding_uplink_window.bytes() * 
                        (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_uplink_window.estmateInterval(current_time));
                               
                
                tcb_table[tcb_index]->rcv_uplink_thruput_approx = (1 - double(tcb_table[tcb_index]->sliding_uplink_window.k * tcb_table[tcb_index]->sliding_uplink_window.delta)/ 
                        double(tcb_table[tcb_index]->sliding_uplink_window.interval)) * MAX_UPLINK_BW + (double(tcb_table[tcb_index]->sliding_uplink_window.k * tcb_table[tcb_index]->sliding_uplink_window.delta)/ 
                        double(tcb_table[tcb_index]->sliding_uplink_window.interval)) * tcb_table[tcb_index]->rcv_uplink_thruput;
  
                
                if (tcb_table[tcb_index]->sliding_uplink_window.k < tcb_table[tcb_index]->sliding_uplink_window.interval / tcb_table[tcb_index]->sliding_uplink_window.delta)         
                    tcb_table[tcb_index]->sliding_uplink_window.k ++;
                
            }         
        }
    }
}






void print_conn_stats(u_int tcb_index, u_long_long current_time)
{
      fprintf(stderr, "rtt %u dd %u bw %u rate %u ud %d uq %u dq %u ts_bw %u usize %d ubyte %d u_rr %u port %hu\n",
            tcb_table[tcb_index]->RTT,
            tcb_table[tcb_index]->downlink_queueing_delay,
            tcb_table[tcb_index]->rcv_thrughput_approx,
            tcb_table[tcb_index]->send_rate,
            tcb_table[tcb_index]->delay_var,
            tcb_table[tcb_index]->delay_size,
            tcb_table[tcb_index]->downlink_queueing_length,
            tcb_table[tcb_index]->rcv_tsval_est_thruput,
            tcb_table[tcb_index]->sliding_avg_window._u_size,
            tcb_table[tcb_index]->sliding_avg_window.counted_unsent_bytes,
            tcb_table[tcb_index]->sliding_avg_window.unsent_bytes_rr,                    
            tcb_table[tcb_index]->states.state_id[tcb_table[tcb_index]->states.num-1]
            );
}
/***********ATRC rate control**********/
void inline tcb_bw_burst_ctrl(u_int tcb_index, u_long_long current_time, u_int sport)
{

#ifdef FIX_TIME_INTERVAL_EST

    
    if (tcb_table[tcb_index]->sliding_avg_window.sample_time)
    {        
        
#ifdef USE_TIMESTAMP         
        current_time = (current_time > (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity ? 
            current_time - tcb_table[tcb_index]->time_diff : current_time + tcb_table[tcb_index]->time_diff);
#endif
        
	if (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) >= tcb_table[tcb_index]->sliding_avg_window.interval)
	{           
            u_int bytes, rcv_thruput, max_bytes;
            int unsent = tcb_table[tcb_index]->unsent_size + tcb_table[tcb_index]->sliding_avg_window.unsent_delay_bytes;
            tcb_table[tcb_index]->sliding_avg_window.unsent_delay_bytes = 0;            
            
#ifndef DOWNLINK_QUEUE_LEN_EST
            unsent = 0;
#endif        
   
            if (unsent > 0)
            {
                u_int interval = tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time);
                bytes = tcb_table[tcb_index]->sliding_avg_window.bytes();
                rcv_thruput = ((u_long_long)bytes + (u_long_long)unsent) * (u_long_long)RESOLUTION / (u_long_long)interval;
                
                if (rcv_thruput > tcb_table[tcb_index]->send_rate_upper)
                {
                    max_bytes = (u_long_long)tcb_table[tcb_index]->send_rate_upper * (u_long_long)interval / (u_long_long)RESOLUTION;                                                            
                    if (max_bytes > bytes)
                    {                        
                        tcb_table[tcb_index]->sliding_avg_window.another_put(max_bytes - bytes, current_time, 15);
                        tcb_table[tcb_index]->unsent_size -= (int)(max_bytes - bytes);                           
                    }                                                            
                }
                else
                {                                     
                    tcb_table[tcb_index]->sliding_avg_window.another_put(unsent, current_time, 15);
                    tcb_table[tcb_index]->unsent_size -= unsent;
                }
            }
            
            //update_unsent_bytes(tcb_index, current_time);
            tcb_table[tcb_index]->sliding_avg_window.phase_2_sent_bytes += tcb_table[tcb_index]->sent_bytes_counter;                        
            tcb_table[tcb_index]->sliding_avg_window.threshold(tcb_table[tcb_index]->send_rate_upper);                        
                        
            
#ifdef DOWNLINK_QUEUE_LEN_EST
            
            tcb_table[tcb_index]->sliding_avg_window.threshold_1(current_time, 
                    current_time - tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 1].time, 
                    tcb_table[tcb_index]->sent_bytes_counter, 
                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                    tcb_table[tcb_index]->send_rate_lower,
                    tcb_table[tcb_index]->downlink_queueing_delay, 
                    0);            
#else
            tcb_table[tcb_index]->sliding_avg_window.threshold_1(current_time, 
                    current_time - tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 1].time, 
                    tcb_table[tcb_index]->sent_bytes_counter, 
                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                    tcb_table[tcb_index]->send_rate_lower,
                    tcb_table[tcb_index]->RTT, 
                    tcb_table[tcb_index]->RTT_limit);            
            
#endif
            
            tcb_table[tcb_index]->sliding_avg_window.threshold_2();
              
            tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) == 0 ? 
		    tcb_table[tcb_index]->send_rate : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * 
		    (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time));

            tcb_table[tcb_index]->rcv_thrughput_approx = 0 * tcb_table[tcb_index]->rcv_thrughput_approx + 1 * tcb_table[tcb_index]->rcv_thrughput;            
            
            //tcb_table[tcb_index]->sliding_gradient_window.put(tcb_table[tcb_index]->rcv_thrughput_approx, current_time, 0);                        
            //atrc_thrughput_prediction(tcb_index, current_time);
            
                       
#ifdef DYNAMIC_RATE_FIT            
            BandwidthAdaptation(tcb_index, current_time);                        
#endif
            
            tcb_table[tcb_index]->sliding_avg_window.nextEstmateSampleTime(current_time);
            tcb_table[tcb_index]->sliding_avg_window.another_shift();
                        
            
            tcb_table[tcb_index]->sent_bytes_counter = 0;

            if (tcb_table[tcb_index]->sliding_avg_window.k < tcb_table[tcb_index]->sliding_avg_window.interval / tcb_table[tcb_index]->sliding_avg_window.delta)         
            {
                tcb_table[tcb_index]->sliding_avg_window.k ++;
                tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k-1].time = current_time;
                
            }
            else  
                tcb_table[tcb_index]->sliding_avg_window.bw_window_shift(current_time);                          
            
            
            if (tcb_table[tcb_index]->sliding_avg_window.size() < 2)
            {
                tcb_table[tcb_index]->sliding_avg_window.flush();
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
            }                                                  
            
            
	}
	else if (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) < tcb_table[tcb_index]->sliding_avg_window.interval)
	{
            
                       
            if (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) >= tcb_table[tcb_index]->sliding_avg_window.k * 
                    tcb_table[tcb_index]->sliding_avg_window.delta)
            {
                            
                u_int bytes, rcv_thruput, max_bytes;
                int unsent = tcb_table[tcb_index]->unsent_size;
                
#ifndef DOWNLINK_QUEUE_LEN_EST
                unsent = 0;
#endif 
                if (unsent > 0)
                {
                    bytes = tcb_table[tcb_index]->sliding_avg_window.bytes();
                    u_int interval = tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time);
                    rcv_thruput = ((u_long_long)bytes + (u_long_long)unsent) * (u_long_long)RESOLUTION / 
                            (u_long_long)interval;
                                
                    if (rcv_thruput > tcb_table[tcb_index]->send_rate_upper)
                    {
                        max_bytes = (u_long_long)tcb_table[tcb_index]->send_rate_upper * (u_long_long)interval / (u_long_long)RESOLUTION;
                       
                        if (max_bytes > bytes)
                        {  
                            tcb_table[tcb_index]->sliding_avg_window.another_put(max_bytes - bytes, current_time, 15);
                            tcb_table[tcb_index]->unsent_size -= (int)(max_bytes - bytes);                                                       
                        }                                                                        
                    }
                    else
                    {                     
                        tcb_table[tcb_index]->sliding_avg_window.another_put(unsent, current_time, 15);
                        tcb_table[tcb_index]->unsent_size -= unsent;
                        
                    }
                }
            
                //update_unsent_bytes(tcb_index, current_time);
                tcb_table[tcb_index]->sliding_avg_window.phase_1_sent_bytes += tcb_table[tcb_index]->sent_bytes_counter;
                tcb_table[tcb_index]->sliding_avg_window.phase_2_sent_bytes = tcb_table[tcb_index]->sliding_avg_window.phase_1_sent_bytes;
                
                tcb_table[tcb_index]->sliding_avg_window.threshold(tcb_table[tcb_index]->send_rate_upper);

                
#ifdef DOWNLINK_QUEUE_LEN_EST    
                tcb_table[tcb_index]->sliding_avg_window.threshold_1(current_time, 
                        current_time - tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 1].time, 
                        tcb_table[tcb_index]->sent_bytes_counter, 
                        tcb_table[tcb_index]->rcv_thrughput_approx, 
                        tcb_table[tcb_index]->send_rate_lower,
                        tcb_table[tcb_index]->downlink_queueing_delay, 
                    0);     

#else                
                tcb_table[tcb_index]->sliding_avg_window.threshold_1(current_time, 
                    current_time - tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k - 1].time, 
                    tcb_table[tcb_index]->sent_bytes_counter, 
                    tcb_table[tcb_index]->rcv_thrughput_approx, 
                    tcb_table[tcb_index]->send_rate_lower,
                    tcb_table[tcb_index]->RTT, 
                    tcb_table[tcb_index]->RTT_limit);            

#endif       
            
                tcb_table[tcb_index]->sliding_avg_window.threshold_2();
                
               
                
                
		tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) == 0 ? 
                    tcb_table[tcb_index]->send_rate : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / 
                        (u_long_long)tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time));
                
		tcb_table[tcb_index]->rcv_thrughput_approx =  (1 - double(tcb_table[tcb_index]->sliding_avg_window.k * tcb_table[tcb_index]->sliding_avg_window.delta)/ double(tcb_table[tcb_index]->sliding_avg_window.interval)) * 
                        tcb_table[tcb_index]->send_rate + (double(tcb_table[tcb_index]->sliding_avg_window.k * tcb_table[tcb_index]->sliding_avg_window.delta)/ double(tcb_table[tcb_index]->sliding_avg_window.interval)) * 
                        tcb_table[tcb_index]->rcv_thrughput;

                //tcb_table[tcb_index]->sliding_gradient_window.put(tcb_table[tcb_index]->rcv_thrughput, current_time, 0);       
                
                
#ifdef DYNAMIC_RATE_FIT                
		BandwidthAdaptation(tcb_index, current_time);                
#endif
                
                tcb_table[tcb_index]->sent_bytes_counter = 0;
                
                if (tcb_table[tcb_index]->sliding_avg_window.k < tcb_table[tcb_index]->sliding_avg_window.interval/tcb_table[tcb_index]->sliding_avg_window.delta)
                {
                    tcb_table[tcb_index]->sliding_avg_window.k ++;
                    tcb_table[tcb_index]->sliding_avg_window.bw_window[tcb_table[tcb_index]->sliding_avg_window.k-1].time = current_time;
                }
                else  
                    tcb_table[tcb_index]->sliding_avg_window.bw_window_shift(current_time);
                
                                
                                                                                  
            }
	}
    }
   
#endif


}






void inline log_debug_tcb_info(u_int tcb_index, u_long_long current_time)
{
    if (!tcb_table[tcb_index]->out_file)               
    {
        char name[20];
        sprintf(name, "%u.%u.%u.%u", tcb_table[tcb_index]->client_ip_address.byte1, tcb_table[tcb_index]->client_ip_address.byte2, tcb_table[tcb_index]->client_ip_address.byte3, tcb_table[tcb_index]->client_ip_address.byte4);
        tcb_table[tcb_index]->out_file = fopen(strcat(name, ".txt"), "w");
    }

    fprintf(tcb_table[tcb_index]->out_file, "%u %u %u %u %u %u %u %u %u %u %llu %llu %llu %llu\n", 
    tcb_table[tcb_index]->RTT, 
    tcb_table[tcb_index]->send_rate/1000, 
    tcb_table[tcb_index]->rcv_thrughput_approx/1000, 
    tcb_table[tcb_index]->rcv_thrughput/1000, 
    tcb_table[tcb_index]->pkts_transit, 
    tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time), 
    tcb_table[tcb_index]->sliding_avg_window.bytes(), 
    tcb_table[tcb_index]->BusyPeriod.head()->started, 
    tcb_table[tcb_index]->BusyPeriod._size, 
    check_buffer_empty(tcb_index, 0), 
    current_time, 
    tcb_table[tcb_index]->sliding_avg_window.sample_time, 
    tcb_table[tcb_index]->sliding_avg_window.tailTime(),
    tcb_table[tcb_index]->sliding_avg_window.shift_time);
                
}
void inline log_debug_conn_info(u_int tcb_index, u_short sport, u_long_long current_time)
{
    if (!tcb_table[tcb_index]->out_file)               
    {
        char name[20];
        sprintf(name, "%u.%u.%u.%u", tcb_table[tcb_index]->client_ip_address.byte1, tcb_table[tcb_index]->client_ip_address.byte2, tcb_table[tcb_index]->client_ip_address.byte3, tcb_table[tcb_index]->client_ip_address.byte4);
        tcb_table[tcb_index]->out_file = fopen(strcat(name, ".txt"), "w");
    }

    fprintf(tcb_table[tcb_index]->out_file, "%hu %u %u %u %u %u %u %u %u %u %u %u %llu %llu %llu %llu %u %u %u %u\n", sport, tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->RTT, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->rcv_thrughput/1000, tcb_table[tcb_index]->pkts_transit, tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time), tcb_table[tcb_index]->sliding_avg_window.bytes(), tcb_table[tcb_index]->BusyPeriod.head()->started, tcb_table[tcb_index]->BusyPeriod._size, check_buffer_empty(tcb_index, 0), current_time, tcb_table[tcb_index]->sliding_avg_window.sample_time, tcb_table[tcb_index]->sliding_avg_window.tailTime(), tcb_table[tcb_index]->sliding_avg_window.shift_time, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, tcb_table[tcb_index]->unsent_data_bytes);
    
}
u_int inline aggre_bw_estimate_approx(u_short this_port, u_int tcb_index)
{
	u_long_long current_time = timer.Start();

	u_int sport;
	tcb_table[tcb_index]->aggre_bw_estimate = 0;

	for (u_int i = 0; i < tcb_table[tcb_index]->states.num; i ++)
	{
		if (tcb_table[tcb_index]->states.state_id[i] != this_port)
		{
			sport = tcb_table[tcb_index]->states.state_id[i];
			tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? 0 :
				tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * RESOLUTION / tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));
			tcb_table[tcb_index]->aggre_bw_estimate += tcb_table[tcb_index]->conn[sport]->rcv_thrughput;
		}
	}

	tcb_table[tcb_index]->aggre_bw_estimate += tcb_table[tcb_index]->conn[this_port]->rcv_thrughput_approx;
	return tcb_table[tcb_index]->aggre_bw_estimate;
}
void inline ack_sack_option(u_char* tcp_opt, u_int tcp_opt_len, u_short sport, u_int ack_num, u_int tcb_index, u_int awin)
{
        for (u_int i = 0; i < tcp_opt_len; )
        {
            switch ((u_short)*(tcp_opt + i))
            {
            case 0: //end of option
                    *(tcp_opt + i) = 1;
                    //printf("END OF OPTION\n");
                    break;
            case 1: //NOP
                    //printf("NO OF OPERATION\n");
                    break;
	    case 8: //TCP Timestamp
		    tcb_table[tcb_index]->cur_TSval = ntohl(*(u_int *)(tcp_opt + i + 2));
		    tcb_table[tcb_index]->cur_TSecr = ntohl(*(u_int *)(tcp_opt + i + 2 + 4));
		    
		    break;
            case 5: //SACK

                    u_short sack_block_num = ((u_short)*(tcp_opt + i + 1) - 2) / sizeof(tcp_sack_block);
                    //tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;

                    if (sack_block_num == 1) // init sack_block_num
                    	tcb_table[tcb_index]->conn[sport]->sack_block_num = sack_block_num;
                    
                    u_int last_right_sack = 0;
                    if (sack_block_num > tcb_table[tcb_index]->conn[sport]->sack_block_num && sack_block_num >= 2)
                    {
                    	last_right_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + 1*8 + 4));

                    	if (MY_SEQ_LT(ack_num, last_right_sack) && tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX) // DSACK
                    	{
                            ForwardPkt* out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                            if (MY_SEQ_GT(out_awin_pkt->seq_num, ack_num + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                            {
                                while (MY_SEQ_GT(out_awin_pkt->seq_num, ack_num + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale) + last_right_sack - ack_num))
                                {
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                                    out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                                    
                                }
                            }
                    	}
                    }
                                            
                    tcb_table[tcb_index]->conn[sport]->sack_block_num = sack_block_num;
                    u_int left_sack, right_sack;
                    u_int rtx = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;

                    ForwardPkt* is_rtx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(rtx);

                    for (int j = sack_block_num - 1; j >= 0; j --) {
                    	left_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + j*8));
                        right_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + j*8 + 4));

                        if (MY_SEQ_GT(right_sack, ack_num + awin * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)) || 
                                MY_SEQ_GT(left_sack, ack_num + awin * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale))) {
                            //fprintf(stderr)
                        }

                        if (MY_SEQ_GEQ(ack_num, right_sack)) { //DSACK
                            tcb_table[tcb_index]->conn[sport]->sack_diff += (int)(right_sack - left_sack);
                            continue;
                        }
                                                
                        
                        while (is_rtx_pkt->occupy && 
                                MY_SEQ_LT(is_rtx_pkt->seq_num, right_sack) && 
                                MY_SEQ_LT(is_rtx_pkt->seq_num, ack_num + 
                                awin * pow((float) 2, (int) tcb_table[tcb_index]->conn[sport]->server_state.win_scale))) {
                             if (MY_SEQ_GEQ(is_rtx_pkt->seq_num, left_sack) && 
                                     MY_SEQ_LEQ(is_rtx_pkt->seq_num + is_rtx_pkt->data_len, right_sack) && 
                                     is_rtx_pkt->is_rtx) {
                                is_rtx_pkt->is_rtx = false;
                                tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
                                tcb_table[tcb_index]->conn[sport]->sack_diff += is_rtx_pkt->data_len;
                                tcb_table[tcb_index]->conn[sport]->undup_sack_diff += is_rtx_pkt->data_len;
                             }

                             rtx = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pktNext(rtx);
                             is_rtx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(rtx);
                        }

                        if (MY_SEQ_GT(right_sack, tcb_table[tcb_index]->conn[sport]->max_sack_edge)) {
                            tcb_table[tcb_index]->conn[sport]->max_sack_edge = right_sack;
                        }                                               
                    }

                    break;
            }

            if ((u_short)*(tcp_opt + i) > 1)
               i += (u_short)*(tcp_opt + i + 1);
            else
               i ++;
        }


}
void inline rcv_ack_bw_estimate(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();

	//if (tcb_table[tcb_index]->conn[sport]->reset_timer == TRUE)
	//	tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == 0)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		//Right version of TCPW bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.065 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput :
			0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time));
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}

#endif

		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
}
void inline rcv_dup_ack_bw_estimate(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.065 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput :
			0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time));
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);
#endif
		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}

}
void inline rcv_ack_stat_count(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	/*
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	*/
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	//if (tcb_table[tcb_index]->conn[sport]->reset_timer == TRUE)
	//	tcb_table[tcb_index]->conn[sport]->init_state();

	if (!tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		//Wrong version of TCPW bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time;

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}
#endif

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		assert(tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time);
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
	}

}
void inline rcv_dup_ack_stat_count(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		// Wrong version of TCPW of bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx +
			0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time;

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
                    tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
                    tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT
		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->thruput_actual, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}
}
void inline rcv_ack_dft_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	

	if (!tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = 0.2 * tcb_table[tcb_index]->conn[sport]->ack_interarrival_time + 0.8 * (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time);
		tcb_table[tcb_index]->conn[sport]->dft_cumul_ack = 0.2 * tcb_table[tcb_index]->conn[sport]->dft_cumul_ack + 0.8 * tcb_table[tcb_index]->conn[sport]->cumul_ack;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->dft_cumul_ack * RESOLUTION / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.9 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.1 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%u %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}

#endif

		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}

}
void inline rcv_dup_ack_dft_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();


	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = 0.2 * tcb_table[tcb_index]->conn[sport]->ack_interarrival_time + 0.8 * (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time);
		tcb_table[tcb_index]->conn[sport]->dft_cumul_ack = 0.2 * tcb_table[tcb_index]->conn[sport]->dft_cumul_ack + 0.8 * tcb_table[tcb_index]->conn[sport]->cumul_ack;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->dft_cumul_ack * RESOLUTION / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.9 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.1 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT
		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif
		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}

}




/***********ATRC and RSFC estimate uplink receiving throughput according to data receiving rate*********/
void inline rcv_data_uplink_slide_win_avg_bw(u_int tcb_index, u_short sport, u_int ack_num, u_short data_len, u_long_long current_time)
{
   
    if (!tcb_table[tcb_index]->sliding_uplink_window.sample_time)
    {          
        tcb_table[tcb_index]->sliding_uplink_window.sample_time = current_time;
    }

    tcb_table[tcb_index]->sliding_uplink_window.another_put(data_len, current_time, ack_num);
  
    tcb_table[tcb_index]->conn[sport]->sliding_uplink_window.put(data_len, current_time, ack_num);
    tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput = (tcb_table[tcb_index]->conn[sport]->sliding_uplink_window.timeInterval(current_time) == 0 ? 
		    MAX_UPLINK_BW : (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_uplink_window.bytes() * 
		    (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_uplink_window.timeInterval(current_time));
    
    
}






void inline rcv_ack_slide_win_avg_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{

	tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time > 0 ? tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time : 0);
	tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;

	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->last_ack_seqno = (tcb_table[tcb_index]->conn[sport]->last_ack_seqno == 0 ? ack_num : tcb_table[tcb_index]->conn[sport]->last_ack_seqno);

	tcb_table[tcb_index]->conn[sport]->cumul_ack = (int)(tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno);

	if (tcb_table[tcb_index]->conn[sport]->cumul_ack > tcb_table[tcb_index]->conn[sport]->max_data_len)
	{
            if (tcb_table[tcb_index]->conn[sport]->accounted_for >= tcb_table[tcb_index]->conn[sport]->cumul_ack)
            {
                tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for - tcb_table[tcb_index]->conn[sport]->cumul_ack;
                tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->max_data_len;
            }
            else
            {
                tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cumul_ack - tcb_table[tcb_index]->conn[sport]->accounted_for;
                tcb_table[tcb_index]->conn[sport]->accounted_for = 0;
            }
	}

	tcb_table[tcb_index]->conn[sport]->sliding_avg_win.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, ack_num);
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput = 
		(tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : 
			(u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * 
                (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));

	tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;
                
        tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->cur_TSval, ack_num);
        tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput = 0.0 * tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput + 
                1.0 * (tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) == 0 ? 
                    0 : (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.bytes() * (u_long_long)RESOLUTION / 
                ((u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) * 
                (u_long_long)tcb_table[tcb_index]->timestamp_granularity));
        
        
#ifdef FIX_TIME_INTERVAL_EST

	tcb_table[tcb_index]->sliding_tsval_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->cur_TSval, ack_num);
        tcb_table[tcb_index]->rcv_tsval_est_thruput = 0.0 * tcb_table[tcb_index]->rcv_tsval_est_thruput + 1.0 * (tcb_table[tcb_index]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) == 0 ? 
            0 : (u_long_long)tcb_table[tcb_index]->sliding_tsval_window.bytes() * (u_long_long)RESOLUTION / 
                ((u_long_long)tcb_table[tcb_index]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) * (u_long_long)tcb_table[tcb_index]->timestamp_granularity));
        
        
        
        if(!tcb_table[tcb_index]->sliding_avg_window.sample_time && tcb_table[tcb_index]->conn[sport]->cumul_ack)
	{            
            
        
#ifdef USE_TIMESTAMP
            tcb_table[tcb_index]->time_diff = current_time > (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity ? 
                current_time - (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity : 
                (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity - current_time;
            tcb_table[tcb_index]->sliding_avg_window.sample_time = (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity;
#else
            
            tcb_table[tcb_index]->sliding_avg_window.sample_time = current_time;                
            tcb_table[tcb_index]->sliding_avg_window.init_burst = tcb_table[tcb_index]->pkts_transit;
            tcb_table[tcb_index]->sliding_avg_window.init_burst = tcb_table[tcb_index]->sent_bytes_counter;
            tcb_table[tcb_index]->sliding_avg_window.init_burst_unsent_bytes = (long long)tcb_table[tcb_index]->send_rate_upper * (long long)tcb_table[tcb_index]->RTT / (long long)RESOLUTION - 
                    tcb_table[tcb_index]->sliding_avg_window.init_burst;
            tcb_table[tcb_index]->sliding_avg_window.bw_window[0].time = current_time;
            tcb_table[tcb_index]->sent_bytes_counter = 0;
             
            
#endif 
            
	}
        
                                       
        if (tcb_table[tcb_index]->sliding_avg_window.sample_time && tcb_table[tcb_index]->conn[sport]->cumul_ack)
        {
            
#ifdef USE_TIMESTAMP
            tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack, 
                    (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity, ack_num);
#else
            tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack , current_time, ack_num);         
                        
#endif 
        }

	
#else

	tcb_table[tcb_index]->sliding_avg_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, ack_num);
	tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
	tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT
	BW_adaptation(sport, tcb_index);
#endif
	
#ifndef DEBUG
	printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\t\t\r", 
	tcb_table[tcb_index]->conn[sport]->server_state.phase, 
	tcb_table[tcb_index]->conn[sport]->server_state.snd_una, 
	tcb_table[tcb_index]->conn[sport]->ack_interarrival_time/1000, 
	tcb_table[tcb_index]->conn[sport]->RTT/1000, 
	tcb_table[tcb_index]->conn[sport]->RTT_limit/1000, 
	tcb_table[tcb_index]->send_rate/1000, 
	tcb_table[tcb_index]->rcv_thrughput_approx/1000, 
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, 
	sport);
#endif
	
#endif

#ifdef LOG_STAT
	log_data(sport, tcb_index);
#endif
	
        
        if (current_time > tcb_table[tcb_index]->conn[sport]->initial_time + 2 * RESOLUTION /*&& tcb_table[tcb_index]->mean_throughput == MAX_SEND_RATE*/) {
            tcb_table[tcb_index]->mean_throughput = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;        
            
        }
        
        
#ifdef DOWNLINK_QUEUE_LEN_EST
        /*
        tcb_table[tcb_index]->sliding_avg_window.window_update(tcb_table[tcb_index]->cur_TSecr, 
            tcb_table[tcb_index]->downlink_queueing_delay, 
            0, 
            tcb_table[tcb_index]->downlink_queueing_length, 
            tcb_table[tcb_index]->mean_throughput, 
            current_time);
        */       
#else
        tcb_table[tcb_index]->sliding_avg_window.window_update(tcb_table[tcb_index]->cur_TSecr, 
            tcb_table[tcb_index]->RTT, 
            tcb_table[tcb_index]->RTT_limit, 
            tcb_table[tcb_index]->downlink_queueing_length, 
            tcb_table[tcb_index]->mean_throughput, 
            current_time);

#endif
        
        tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
	tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;
                
}
void inline rcv_dup_ack_slide_win_avg_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
	tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time > 0 ? tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time : 0);
	tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;

	if (tcb_table[tcb_index]->conn[sport]->sack_diff)
	{
            tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
            tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for + tcb_table[tcb_index]->conn[sport]->cumul_ack;

	}
	else
	{
            tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->max_data_len;
            tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for + tcb_table[tcb_index]->conn[sport]->cumul_ack;

	}

	tcb_table[tcb_index]->conn[sport]->sliding_avg_win.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : 
            (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * (u_long_long)RESOLUTION / 
                (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

        tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->cur_TSval, ack_num);
        tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput = 0.0 * tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput + 
                1.0 * (tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) == 0 ? 0 : 
                    (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.bytes() * (u_long_long)RESOLUTION / 
                ((u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) * (u_long_long)tcb_table[tcb_index]->timestamp_granularity));
        
#ifdef FIX_TIME_INTERVAL_EST

        tcb_table[tcb_index]->sliding_tsval_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->cur_TSval, ack_num);
        tcb_table[tcb_index]->rcv_tsval_est_thruput = 0.0 * tcb_table[tcb_index]->rcv_tsval_est_thruput + 1.0 * (tcb_table[tcb_index]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) == 0 ? 
            0 : (u_long_long)tcb_table[tcb_index]->sliding_tsval_window.bytes() * (u_long_long)RESOLUTION / 
                (u_long_long)(tcb_table[tcb_index]->sliding_tsval_window.timeInterval(tcb_table[tcb_index]->cur_TSval) * tcb_table[tcb_index]->timestamp_granularity));
        
#ifdef USE_TIMESTAMP
        tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack, 
            (u_long_long)tcb_table[tcb_index]->cur_TSval * (u_long_long)tcb_table[tcb_index]->timestamp_granularity, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
#else
        
        tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
#endif
        
#else
	tcb_table[tcb_index]->sliding_avg_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
	tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? (u_long_long)tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
	tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT

	if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
	{
		tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		print_bw_info(sport, tcb_index);
	}
	else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
	{
		tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
		print_bw_info(sport, tcb_index);
	}
	else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
	{
		tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
		print_bw_info(sport, tcb_index);
	}

#endif


#ifndef DEBUG
    printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time/1000, tcb_table[tcb_index]->conn[sport]->RTT/1000, tcb_table[tcb_index]->conn[sport]->RTT_limit/1000, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, sport);
#endif

#endif

#ifdef LOG_STAT
	log_data(sport, tcb_index);
#endif

        
#ifdef DOWNLINK_QUEUE_LEN_EST
        /*
        tcb_table[tcb_index]->sliding_avg_window.window_update(tcb_table[tcb_index]->cur_TSecr, 
            tcb_table[tcb_index]->downlink_queueing_delay, 
            0, 
            tcb_table[tcb_index]->downlink_queueing_length, 
            tcb_table[tcb_index]->conn[sport]->rcv_thrughput, 
            current_time);
        */
#else
            
        tcb_table[tcb_index]->sliding_avg_window.window_update(tcb_table[tcb_index]->cur_TSecr, 
            tcb_table[tcb_index]->RTT, 
            tcb_table[tcb_index]->RTT_limit, 
            tcb_table[tcb_index]->downlink_queueing_length, 
            tcb_table[tcb_index]->mean_throughput, 
            current_time);
#endif           
        
	tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
	tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;

}





/**********TCP-RRE adapt to the sending rate according to buffering**********/
void inline rcv_ack_buffer_manage_mode(u_int tcb_index, u_short sport, u_int ack_num, u_long_long current_time)
{
    if (tcb_table[tcb_index]->conn[sport]->RTT)
    {
        if (tcb_table[tcb_index]->conn[sport]->downlink_queueing_length < tcb_table[tcb_index]->conn[sport]->target_queue_len)
        {
            tcb_table[tcb_index]->conn[sport]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput + 
                    (u_long_long)(tcb_table[tcb_index]->conn[sport]->buffer_max - tcb_table[tcb_index]->conn[sport]->target_queue_len) * (u_long_long)RESOLUTION / 
                    (u_long_long)tcb_table[tcb_index]->conn[sport]->RTT;
            
            
            printf("TCP-RRE Buffer Fill %u %hu %u %lu %u %u %u %u %u %u \n", 
                    tcb_index, 
                    sport, 
                    ack_num, 
                    current_time, 
                    tcb_table[tcb_index]->conn[sport]->RTT/1000, 
                    tcb_table[tcb_index]->conn[sport]->downlink_queueing_length/tcb_table[tcb_index]->conn[sport]->max_data_len, 
                    tcb_table[tcb_index]->conn[sport]->target_queue_len/tcb_table[tcb_index]->conn[sport]->max_data_len, 
                    tcb_table[tcb_index]->conn[sport]->send_rate/1000, 
                    tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput/1000, 
                    tcb_table[tcb_index]->conn[sport]->buffer_max/tcb_table[tcb_index]->conn[sport]->max_data_len);
            
        }
        else
        {
            tcb_table[tcb_index]->conn[sport]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput - 
                    (u_long_long)(tcb_table[tcb_index]->conn[sport]->target_queue_len - tcb_table[tcb_index]->conn[sport]->buffer_min) * (u_long_long)RESOLUTION / 
                    (u_long_long)tcb_table[tcb_index]->conn[sport]->RTT;
          
            
            printf("TCP-RRE Buffer Drain %u %hu %u %lu %u %u %u %u %u %u \n", 
                    tcb_index, 
                    sport, 
                    ack_num, 
                    current_time, 
                    tcb_table[tcb_index]->conn[sport]->RTT/1000, 
                    tcb_table[tcb_index]->conn[sport]->downlink_queueing_length/tcb_table[tcb_index]->conn[sport]->max_data_len, 
                    tcb_table[tcb_index]->conn[sport]->target_queue_len/tcb_table[tcb_index]->conn[sport]->max_data_len, 
                    tcb_table[tcb_index]->conn[sport]->send_rate/1000, 
                    tcb_table[tcb_index]->conn[sport]->rcv_tsval_thruput/1000, 
                    tcb_table[tcb_index]->conn[sport]->buffer_max/tcb_table[tcb_index]->conn[sport]->max_data_len);
            
        }
        
            
        //log_data(sport, tcb_index);
        
                
    }
}
/**********RSFC window adaptation***********/
void inline rcv_data_flow_ctrl(u_int tcb_index, u_short sport, u_int ack_num, u_long_long current_time)
{
    if (tcb_table[tcb_index]->conn[sport]->local_adv_window)
    {
        if (tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay > MIN_RTT)
        {
            tcb_table[tcb_index]->conn[sport]->local_adv_window = min(tcb_table[tcb_index]->conn[sport]->local_adv_window, 
                    (u_int)((u_long_long)tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput*(u_long_long)MIN_RTT/(u_long_long)RESOLUTION));
            
            printf("Fast State %lld %lld %lld %lld %u %u %u %lu %u %u\n",
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity,
                tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                tcb_table[tcb_index]->cur_TSval,
                tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                current_time,
                tcb_table[tcb_index]->conn[sport]->local_adv_window, 
                tcb_table[tcb_index]->conn[sport]->client_state.sender_win_scale);
        }
        else
        {
            tcb_table[tcb_index]->conn[sport]->local_adv_window += tcb_table[tcb_index]->conn[sport]->MSS;
            printf("Slow State %lld %lld %lld %lld %u %u %u %lu %u %u\n",
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity,
                tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                tcb_table[tcb_index]->cur_TSval,
                tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                current_time,
                tcb_table[tcb_index]->conn[sport]->local_adv_window, 
                tcb_table[tcb_index]->conn[sport]->client_state.sender_win_scale);
        }

       
    }
}






void inline update_max_sack_edge(u_int tcb_index, u_short sport, u_int ack_num)
{
    if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
        tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;
        
}
void inline rcv_rst_handler(u_short sport, u_int tcb_index, u_long_long current_time, u_short ctr_flag)
{
        ForwardPkt *unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
    
        while (unAckPkt->occupy)
        {           
             unAckPkt->rcv_time = current_time;             
             if (unAckPkt->is_rtx)
             {                 
                data_size_in_flight(tcb_index, unAckPkt->data_len);                                                    
             }
             
             unAckPkt->initPkt();
             tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAckNext();
             tcb_table[tcb_index]->conn[sport]->dataPktBuffer.decrease();
             unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
        }
        
        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.flush();        
        
}





/***********ATRC cross connection uplink queueing delay estimation (not used now)***********/
void inline rcv_ack_delay_variation(u_int tcb_index, u_short sport, u_long_long current_time, u_int ack_num)
{
  
    if (!tcb_table[tcb_index]->first_rcv_time)
    {
        tcb_table[tcb_index]->first_rcv_time = current_time;
        tcb_table[tcb_index]->first_TSval = tcb_table[tcb_index]->cur_TSval;
    }
    else
    {
        /*        
        tcb_table[tcb_index]->timestamp_granularity = (tcb_table[tcb_index]->cur_TSval == tcb_table[tcb_index]->first_TSval ? 
            1 : (current_time -  tcb_table[tcb_index]->first_rcv_time)/(tcb_table[tcb_index]->cur_TSval - tcb_table[tcb_index]->first_TSval));
        
        tcb_table[tcb_index]->timestamp_granularity = tcb_table[tcb_index]->timestamp_granularity > 0 ? 
            tcb_table[tcb_index]->timestamp_granularity : 1;
        */
        
        
	if (tcb_table[tcb_index]->cur_TSecr > 0 && tcb_table[tcb_index]->ref_TSval > 0)
	{                        
            //tcb_table[tcb_index]->delay_var 
                    
            u_int tmp_delay_var = (current_time - tcb_table[tcb_index]->ref_rcv_time) > 
                    (tcb_table[tcb_index]->cur_TSval - tcb_table[tcb_index]->ref_TSval) * tcb_table[tcb_index]->timestamp_granularity ? 
                    (current_time - tcb_table[tcb_index]->ref_rcv_time) - (tcb_table[tcb_index]->cur_TSval - tcb_table[tcb_index]->ref_TSval) * 
                    tcb_table[tcb_index]->timestamp_granularity : 0;
                                 
            tcb_table[tcb_index]->delay_var = 0.0*tcb_table[tcb_index]->delay_var + 1.0*tmp_delay_var;                        
            
            /*
            printf("%u %d %d %u %u %u %u %d %u\n", 
                    ack_num,
                    tcb_table[tcb_index]->delay_var, 
                    tcb_table[tcb_index]->last_delay_var,
                    current_time - tcb_table[tcb_index]->ref_rcv_time, 
                    tcb_table[tcb_index]->cur_TSval - tcb_table[tcb_index]->ref_TSval, 
                    tcb_table[tcb_index]->timestamp_granularity, 
                    tcb_table[tcb_index]->delay_size, 
                    tcb_table[tcb_index]->unsent_size, 
                    tcb_table[tcb_index]->minRTT);
            */
            
            if (tcb_table[tcb_index]->last_delay_var)
            {
                
                if (tcb_table[tcb_index]->last_delay_var - tcb_table[tcb_index]->delay_var > 10000)
                {                    
                    //tcb_table[tcb_index]->delay_var = (tcb_table[tcb_index]->last_delay_var + tcb_table[tcb_index]->delay_var)/3;
                    /*
                    printf("%u %d %d %u %u %u %u %d %u\n", 
                    ack_num,
                    tcb_table[tcb_index]->delay_var, 
                    tcb_table[tcb_index]->last_delay_var,
                    current_time - tcb_table[tcb_index]->ref_rcv_time, 
                    tcb_table[tcb_index]->cur_TSval - tcb_table[tcb_index]->ref_TSval, 
                    tcb_table[tcb_index]->timestamp_granularity, 
                    tcb_table[tcb_index]->delay_size, 
                    tcb_table[tcb_index]->unsent_size, 
                    tcb_table[tcb_index]->minRTT);*/
                }
                
                tcb_table[tcb_index]->last_delay_var = tcb_table[tcb_index]->delay_var;
                 
            }
            else
                tcb_table[tcb_index]->last_delay_var = tcb_table[tcb_index]->delay_var;
            
            tcb_est_delay_size(tcb_index);
	}
    }
}
/***********ATRC predicts uplink queueing delay using uploading TCP packets***********/
void inline rcv_ack_uplink_queueing_delay_est(u_int tcb_index, u_short sport, u_long_long rcv_time, u_int ack_num) 
{
    if (tcb_table[tcb_index]->cur_TSecr && tcb_table[tcb_index]->cur_TSval)
    {
        tcb_table[tcb_index]->uplink_one_way_delay = (long long)rcv_time - (long long)tcb_table[tcb_index]->cur_TSval * 
                (long long)tcb_table[tcb_index]->timestamp_granularity;
        
        if (tcb_table[tcb_index]->min_uplink_one_way_delay > tcb_table[tcb_index]->uplink_one_way_delay)
        {
                                   
            tcb_table[tcb_index]->min_uplink_one_way_delay = tcb_table[tcb_index]->uplink_one_way_delay;          
            
            /*
            printf("%lld %lld %lld %lld %u %u %u %lu\n", 
                    tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay, 
                    tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay, 
                    tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                    (long long)tcb_table[tcb_index]->cur_TSval * (long long)tcb_table[tcb_index]->timestamp_granularity, 
                    tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                    tcb_table[tcb_index]->cur_TSval, 
                    tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                    rcv_time);
            */
                                 
        }
        
        tcb_table[tcb_index]->delay_var = 
                tcb_table[tcb_index]->uplink_one_way_delay - tcb_table[tcb_index]->min_uplink_one_way_delay;
        tcb_est_delay_size(tcb_index);
        /*
        printf("%lld %lld %lld %lld %u %u %u %lu\n",
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                tcb_table[tcb_index]->conn[sport]->uplink_one_way_delay - tcb_table[tcb_index]->conn[sport]->min_uplink_one_way_delay,
                (long long) tcb_table[tcb_index]->cur_TSval * (long long) tcb_table[tcb_index]->timestamp_granularity,
                tcb_table[tcb_index]->conn[sport]->rcv_uplink_thruput,
                tcb_table[tcb_index]->cur_TSval,
                tcb_table[tcb_index]->conn[sport]->uplink_queueing_delay,
                rcv_time);
        */
    }
                    
}







void inline rcv_ack_handler(u_char* th, u_int tcp_len, u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
	// ACK sent but unAck packet
	ForwardPkt *unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
	tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
	tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

        if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
            tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;

	if (tcp_len > 20) // TCP Options Check SACK lists
	{
            u_int tcp_opt_len = tcp_len - 20;
            u_char *tcp_opt = (u_char *)th + 20;
            ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index, window);
	}
        
        while (unAckPkt->occupy && MY_SEQ_GEQ(ack_num, unAckPkt->seq_num + unAckPkt->data_len))
        {                       
            unAckPkt->rcv_time = current_time;
            if (unAckPkt->is_rtx)
            {                               
                data_size_in_flight(tcb_index, unAckPkt->data_len);
                if (tcb_table[tcb_index]->conn[sport]->server_state.state == ESTABLISHED)
                {                    
                    if (tcb_table[tcb_index]->probe_state && unAckPkt->data_len)
                        bandwidth_probe(tcb_index, sport, current_time, unAckPkt->data_len);
                                        
                    if (tcb_table[tcb_index]->conn[sport]->server_state.phase != FAST_RTX)
                    {
                        if (unAckPkt->snd_time && unAckPkt->snd_time < unAckPkt->rcv_time)
                        {                                                        
                            //if (tcb_table[tcb_index]->cur_TSecr == unAckPkt->TSval) {
                            if (ack_num == unAckPkt->seq_num + unAckPkt->data_len)  {                            
                                RTT_estimator(unAckPkt, unAckPkt->snd_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);                                 
                            }               
                        }
                        else if (unAckPkt->rtx_time && unAckPkt->rtx_time < unAckPkt->rcv_time)
                        {                            
                            if (tcb_table[tcb_index]->cur_TSecr == unAckPkt->TSval) {
                                RTT_estimator(unAckPkt, unAckPkt->rtx_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);                              
                            }
                            
                            /*
                            if (tcb_table[tcb_index]->cur_TSecr == unAckPkt->TSval)                
                                rcv_ack_downlink_queueing_len_w_rtt(tcb_index, sport, unAckPkt->rtx_time, unAckPkt->rcv_time);                                
                            */
                        }
                    }
                    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
                    {
                        if (unAckPkt->snd_time && unAckPkt->snd_time < unAckPkt->rcv_time)
                        {
                            if (tcb_table[tcb_index]->cur_TSecr == unAckPkt->TSval)
                                RTT_estimator(unAckPkt, unAckPkt->snd_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);                              
                        }
                        else if (unAckPkt->rtx_time && unAckPkt->rtx_time < unAckPkt->rcv_time)
                        {
                            if (tcb_table[tcb_index]->cur_TSecr == unAckPkt->TSval)
                                RTT_estimator(unAckPkt, unAckPkt->rtx_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);                            
                        }
                    }
                }                
            }
                   
             
            unAckPkt->initPkt();
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAckNext();
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.decrease();
            unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

        }
         
  
	if ((tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX || 
                tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT))
        {
            if (MY_SEQ_GEQ(ack_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
            {

                if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
                {
                 
                    if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && 
                            MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge))
                    {
                        tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge;
                    }
                    else
                    {
                        tcb_table[tcb_index]->conn[sport]->sack_block_num = 0;

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;

                        if (!tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                            tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = TRUE;

                        tcb_table[tcb_index]->conn[sport]->opp_rtx_space = 0; 
                        tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;                       
                          
                    }
                }
                else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                {
                    tcb_table[tcb_index]->conn[sport]->FRTO_ack_count ++;
                    if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)
                    {
                                           
                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;

                        if (!unAckPkt->snd_time)
                        {
                          tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                          tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                          tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                        }
                        else
                        {
                            tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                            if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts)
                            {
                                if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len)
                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
                                else //FIN packet
                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + 1;

                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                            }
                            else if (!tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts)
                            {
                                if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len)
                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
                                else //FIN packet
                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + 1;

                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                            }

                        }

                    }
                    else if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 2)
                    {
                        tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                        tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                        tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                     
                    }
                }
            }	  
        }
        
    
	if (tcb_table[tcb_index]->conn[sport]->server_state.state == ESTABLISHED)         
        {
            if (!tcb_table[tcb_index]->probe_state) 
            {
                rcv_ack_slide_win_avg_bw(ack_num, window, sport, tcb_index, current_time);	
                //rcv_ack_delay_variation(tcb_index, sport, current_time, ack_num);     

                rcv_ack_uplink_queueing_delay_est(tcb_index, sport, current_time, ack_num);        

#ifdef RSFC
                rcv_data_uplink_delay_var(tcb_index, sport, current_time, ack_num);
                rcv_data_flow_ctrl(tcb_index, sport, ack_num, current_time);
#endif

#ifdef TCP-RRE        
                rcv_ack_buffer_manage_mode(tcb_index, sport, ack_num, current_time);
#endif
            }
        }
        
	if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts > tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size)
	{
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck()->seq_num;

            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
            {
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;

            }
	}

	// Adv window is zero, prepare to retransmit,
	if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && 
                tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd <= tcb_table[tcb_index]->conn[sport]->server_state.win_limit)
	{
            tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = FALSE;
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
	}

}
void inline rcv_dup_ack_handler(u_char* th, u_int tcp_len, u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
    
	ForwardPkt* retransmitPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
	tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
        
        if (!retransmitPkt->num_dup && tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
            tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;
                
	if (window)
	{   
            if (window != tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd)
            {
                //window update
            }
            
            if (tcb_table[tcb_index]->conn[sport]->undup_sack_diff) // send within AWnd
	    {
	    	retransmitPkt->num_dup ++;
                
                if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++; // check state bug
                
                data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->undup_sack_diff);
               
	    }
	    else if (tcb_table[tcb_index]->conn[sport]->sack_diff) // send before AWnd
	    {
                if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                        tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++; // check state bug
                
                data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->sack_diff);
	    }
	    else if (!tcb_table[tcb_index]->conn[sport]->undup_sack_diff && !tcb_table[tcb_index]->conn[sport]->sack_diff) // send beyond AWnd
	    {
                retransmitPkt->num_dup ++;
                
                if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++;
                
                data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->max_data_len);
                
	    }
	}
	else if (!window) // AWnd zero
	{
            retransmitPkt->num_dup ++;
            
            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++;
            
            data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->max_data_len);
            
	}
        
        
        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
        
	if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd <= tcb_table[tcb_index]->conn[sport]->server_state.win_limit)
	{
            tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = FALSE;
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
	}
	
        if (tcb_table[tcb_index]->conn[sport]->server_state.state == ESTABLISHED)                 
        {
            if (!tcb_table[tcb_index]->probe_state) 
            {
                rcv_dup_ack_slide_win_avg_bw(ack_num, window, sport, tcb_index, current_time);        
                rcv_ack_uplink_queueing_delay_est(tcb_index, sport, current_time, ack_num);
                //rcv_dup_ack_downlink_queueing_delay_est(tcb_index, sport);
        
    #ifdef RSFC
                rcv_data_uplink_delay_var(tcb_index, sport, current_time, ack_num);                        
                rcv_data_flow_ctrl(tcb_index, sport, ack_num, current_time);
    #endif
            }
        }
        
	if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts > tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size)
	{
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
           
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck()->seq_num;

            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
            {
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                
            }

	}

	if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
	{
            
            if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 0)//&& tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count == 2)
            {
                /*
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;

                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                */
            }
            else if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1 && tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count >= 2)
            {
                                
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = retransmitPkt->seq_num;
                retransmitPkt->rtx_time = retransmitPkt->snd_time;
                retransmitPkt->snd_time = 0;
                retransmitPkt->num_dup = 0;
                
                
#ifdef DEBUG
                printf("%u %u %u %u %u\n",  tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts, ack_num);
#endif
                
            }

	}
        else if (retransmitPkt->num_dup == NUM_DUP_ACK)
	{

	    if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
            {
	        if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, retransmitPkt->seq_num + retransmitPkt->data_len))
	        {
	           //tcb_table[tcb_index]->conn[sport]->max_sack_edge = retransmitPkt->seq_num + retransmitPkt->data_len;
	           tcb_table[tcb_index]->conn[sport]->max_sack_edge = retransmitPkt->seq_num +  tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

	        }
                
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;

                
                if (!tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts)
                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                                                
                ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

                if (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 
                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                {
                    tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

                    while (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                    {
                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                        out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();                        
                    }
                }
                else
                {
                    tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = out_awin_pkt->seq_num;                                        
                    tcb_table[tcb_index]->conn[sport]->opp_rtx_space = 
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 
                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * 
                            pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale) - 
                            out_awin_pkt->seq_num;
                     
                }
                
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = retransmitPkt->seq_num;
                retransmitPkt->rtx_time = retransmitPkt->snd_time;
                retransmitPkt->snd_time = 0;

                tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;

#ifdef DEBUG
                printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO DUP ACKS ON ESTIMATED RATE %u\n", retransmitPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx);
#endif

            }
	    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
	    {

	        if (MY_SEQ_GT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge)) // out-of-AWnd tx successful
                {

	           tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->max_sack_edge;
                   
	           /*
                   ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                   while (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                   {
                       tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                       out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                   }
                   */

	           tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	           tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

                   return;
                }
	        else // out-of-AWnd tx are all failed
	        {
                    tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	            tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

	            return;
	        }
                
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = retransmitPkt->seq_num;
                retransmitPkt->rtx_time = retransmitPkt->snd_time;
                retransmitPkt->snd_time = 0;
                
                tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;
            
#ifdef DEBUG
                printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO DUP ACKS ON ESTIMATED RATE %u\n", retransmitPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx);
#endif

            }
            else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
            {
                // NORMAL_TIMEOUT
            }
            
	}
	else if (retransmitPkt->num_dup > NUM_DUP_ACK)
	{
            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX || tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
            {
                if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && tcb_table[tcb_index]->conn[sport]->sack_block_num && !tcb_table[tcb_index]->conn[sport]->undup_sack_diff && !tcb_table[tcb_index]->conn[sport]->sack_diff)
                {
                    /*
                    if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                        tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                    */
                }

                tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = (tcb_table[tcb_index]->conn[sport]->max_sack_edge > tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge ? tcb_table[tcb_index]->conn[sport]->max_sack_edge : tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge);
            }
	}

	tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

}




void inline rcv_data_pkt(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data, u_short sport, u_short dport, u_int seq_num, u_short data_len, u_short ctr_flag, u_int tcb_index)
{
    ForwardPkt *tmpForwardPkt = tcb_table[tcb_index]->conn[dport]->dataPktBuffer.tail();
    tmpForwardPkt->index = (tcb_table[tcb_index]->conn[dport]->dataPktBuffer._tail % tcb_table[tcb_index]->conn[dport]->dataPktBuffer.capacity);
    tmpForwardPkt->data = (void *)data;
    memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
    memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
    tmpForwardPkt->tcb = tcb_index;
    tmpForwardPkt->sPort = sport;
    tmpForwardPkt->dPort = dport;
#ifdef COMPLETE_SPLITTING_TCP
    tmpForwardPkt->seq_num = tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt + seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
#else
    tmpForwardPkt->seq_num = seq_num;
#endif
    tmpForwardPkt->data_len = data_len;
    tcb_table[tcb_index]->conn[dport]->max_data_len = max(tcb_table[tcb_index]->conn[dport]->max_data_len, (u_int)data_len);
    tmpForwardPkt->ctr_flag = ctr_flag;
    tmpForwardPkt->snd_time = 0;
    tmpForwardPkt->rcv_time = 0;
    tmpForwardPkt->num_dup = 0;
    tmpForwardPkt->is_rtx = true;
    tmpForwardPkt->occupy = true;
    tmpForwardPkt->TSval = tcb_table[tcb_index]->cur_ack_TSval;
    
    tcb_table[tcb_index]->conn[dport]->dataPktBuffer.tailNext();
    tcb_table[tcb_index]->conn[dport]->dataPktBuffer.increase();
    tcb_table[tcb_index]->conn[dport]->dataPktBuffer._last_pkts ++;
    
}
void inline accclient_rcv_data_pkt(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data, u_short sport, u_short dport, u_int seq_num, u_short data_len, u_short ctr_flag, u_int tcb_index)
{
    ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.tail();
    tmpForwardPkt->data = (void *)data;
    memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
    memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
    tmpForwardPkt->sPort = sport;
    tmpForwardPkt->dPort = dport;
    tmpForwardPkt->seq_num = seq_num;
    tmpForwardPkt->data_len = data_len;
    tmpForwardPkt->ctr_flag = ctr_flag;
    tmpForwardPkt->snd_time = 0;
    tmpForwardPkt->rcv_time = 0;
    tmpForwardPkt->num_dup = 0;
    tmpForwardPkt->is_rtx = true;
    tmpForwardPkt->occupy = true;
    tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.tailNext();
    tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.increase();
    
}
void inline clean_sack(u_short sport, u_int ack_num, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->sack_block_num = 0;
	tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;
	for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
	{
		if (tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block && tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block)
		{

			tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block = tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block = 0;
		}
	}
}
void inline create_sack_list(u_int tcb_index, u_short dport, u_int seq_num, u_short data_len)
{

	if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == 0)
	{
		tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
		tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[0].left_edge_block = seq_num;
		tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[0].right_edge_block = seq_num + data_len;

		return;
	}
	else
	{
		for (int i = 0; i < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); i ++)
		{
			if (seq_num < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
			{
				if (seq_num + data_len < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == CLIENT_SACK_SIZE)
					{
						return;
					}
					else
					{

						tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
						for (int j = i + 1; j < tcb_table[tcb_index]->conn[dport]->client_state.sack._size; j ++)
						{
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].left_edge_block;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].right_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].right_edge_block;

						}

						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = seq_num;
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = seq_num + data_len;

						return;
					}
				}
				else if (seq_num + data_len >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = seq_num;

					return;
				}
			}
			else if (seq_num >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
			{
				if (seq_num == tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
				{
					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = seq_num + data_len;

					return;
				}
				else if (seq_num > tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
				{
					if (i == tcb_table[tcb_index]->conn[dport]->client_state.sack.size() - 1)
					{
						if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == CLIENT_SACK_SIZE)
						{
							return;
						}
						else
						{
							tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i+1].left_edge_block = seq_num;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i+1].right_edge_block = seq_num + data_len;

							return;
						}
					}

					continue;
				}
			}
		}
	}

}
u_int inline check_sack_list(u_int tcb_index, u_short dport, u_int seq_num, u_int data_len)
{
	if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() > 0)
	{
		for (int i = 0; i < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); i ++)
		{
			if (seq_num < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
			{
				if (seq_num + data_len >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					u_int snd_nxt = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block;

					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = 0;

					for (int j = i + 1; j < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); j ++)
					{
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].left_edge_block;
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].right_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].right_edge_block;
					}

					tcb_table[tcb_index]->conn[dport]->client_state.sack._size --;

					return snd_nxt;
				}
			}

		}

	}

	return seq_num + data_len;
}
void inline syn_sack_option(u_char* tcp_opt, u_int tcp_opt_len, u_short dport, BOOL mobile, u_int tcb_index)
{
	for (u_int i = 0; i < tcp_opt_len; )
	{
		switch ((u_short)*(tcp_opt + i))
		{
		case 0: //end of option
			*(tcp_opt + i) = 1;
			//printf("END OF OPTION\n");
			break;
		case 1: // NOP
			//printf("NO OPERATION\n");
			break;
		case 4: // SACK permitted
			tcb_table[tcb_index]->conn[dport]->server_state.SACK_permitted = TRUE;
#ifdef DEBUG
			printf("SACK_PERMITTED\n");
#endif
			break;
		case 2:
			tcb_table[tcb_index]->conn[dport]->MSS = min(ntohs(*(u_short *)(tcp_opt + i + 2)), tcb_table[tcb_index]->conn[dport]->MSS);
#ifdef DEBUG
			printf("MSS: %u\n", tcb_table[tcb_index]->conn[dport]->MSS);
#endif
			break;
                case 8: 
                        if (mobile) //from mobile client
                        {  
                            tcb_table[tcb_index]->cur_TSval = ntohl(*(u_int *)(tcp_opt + i + 2));
                            tcb_table[tcb_index]->cur_TSecr = ntohl(*(u_int *)(tcp_opt + i + 2 + 4));
                        }
                        
                        break;                    
		case 3:
			if (mobile) //from mobile client
			{
                            tcb_table[tcb_index]->conn[dport]->server_state.win_scale = (u_short)*(tcp_opt + i + 2);
                            *(tcp_opt + i + 2) = tcb_table[tcb_index]->conn[dport]->server_state.win_scale > WIN_SCALE ? 
                                tcb_table[tcb_index]->conn[dport]->server_state.win_scale : WIN_SCALE; // can be 1, 2, 3, 4, 0
                            tcb_table[tcb_index]->conn[dport]->client_state.win_scale = 
                                    max((u_short)*(tcp_opt + i + 2), tcb_table[tcb_index]->conn[dport]->server_state.win_scale);

#ifdef DEBUG
                            printf("WIN_SCALE: %hu\n", tcb_table[tcb_index]->conn[dport]->server_state.win_scale);
#endif
			}
			else //from Internet server
			{
			    //tcb_table[tcb_index]->conn[dport]->client_state.win_scale = max((u_short)*(tcp_opt + i + 2), tcb_table[tcb_index]->conn[dport]->server_state.win_scale);
			    //*(tcp_opt + i + 2) = 15;
			    
                            /*the window scale option from Internet server*/
                            tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale = (u_short)*(tcp_opt + i + 2);
#ifdef DEBUG
			    printf("WIN_SCALE: %hu\n", tcb_table[tcb_index]->conn[dport]->client_state.win_scale);
#endif
			}

			break;
                       
               case 9: 
                        *(tcp_opt + i) = 25;
                        for (int j = 2; j < (u_short)*(tcp_opt + i + 1); j ++)
                        {
                             *(tcp_opt + i + j) = 1; 
                        }

                        break;
                       
		}

		if ((u_short)*(tcp_opt + i) > 1)
			i += (u_short)*(tcp_opt + i + 1);
		else
			i ++;
	}
       
}
void inline rcv_header_update(ip_header* ih, tcp_header* th, u_short tcp_len, u_short data_len)
{
	u_char Buffer[MTU] = {0};
	th->window = htons(LOCAL_WINDOW);
	th->crc = 0;

	psd_header psdHeader;
	psdHeader.saddr = ih->saddr;
	psdHeader.daddr = ih->daddr;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(tcp_len + data_len);

	memcpy(Buffer, &psdHeader, sizeof(psd_header));
	memcpy(Buffer + sizeof(psd_header), th, tcp_len + data_len);

	th->crc = CheckSum((u_short *)Buffer, tcp_len + sizeof(psd_header) + data_len);
}
void inline rcv_header_update(ip_header* ih, tcp_header* th, u_short tcp_len, u_short data_len, u_char Buffer[])
{
    //u_char Buffer[MTU] = {0};
    //memset(Buffer, 0, PKT_SIZE)
    //th->window = htons(LOCAL_WINDOW);
    th->crc = 0;

    psd_header psdHeader;
    psdHeader.saddr = ih->saddr;
    psdHeader.daddr = ih->daddr;
    psdHeader.mbz = 0;
    psdHeader.ptoto = IPPROTO_TCP;
    psdHeader.tcp_len = htons(tcp_len + data_len);

    memcpy(Buffer, &psdHeader, sizeof(psd_header));
    memcpy(Buffer + sizeof(psd_header), th, tcp_len + data_len);

    th->crc = CheckSum((u_short *)Buffer, tcp_len + sizeof(psd_header) + data_len);
}






int inline nxt_schedule_tcb()
{
	int tcb_it = -1;
	u_int tcb_index;

	u_long_long timeUsed;
	double timeInterval;
	double timeSleep;
	u_long_long current_time;

	while (!pool.ex_tcb.isEmpty())
	{
            tcb_it = pool.ex_tcb.iterator();
            tcb_index = pool.ex_tcb.state_id[tcb_it];
            current_time = timer.Start();
            //timeUsed = current_time - tcb_table[tcb_index]->startTime;

            tcb_bw_burst_ctrl(tcb_index, current_time, 0);
            //tcb_uplink_bw_est(tcb_index, current_time);

            timeUsed = tcb_table[tcb_index]->sliding_snd_window.timeInterval(current_time);
            if (tcb_table[tcb_index]->send_rate == 0 /*|| tcb_table[tcb_index]->totalByteSent < MTU*/)
            {
                pool.ex_tcb.next();
                return tcb_it;
            }                         
            else
            {
                //timeInterval = (double)tcb_table[tcb_index]->totalByteSent * (double)RESOLUTION / (double)tcb_table[tcb_index]->send_rate;

                timeInterval = 
                        (double)tcb_table[tcb_index]->sliding_snd_window.bytes() * 
                        (double)RESOLUTION / 
                        (double)tcb_table[tcb_index]->send_rate;
                
                timeSleep = timeInterval - (double)timeUsed;

                if (timeSleep >= 1)
                {
                    pool.ex_tcb.next();
                    continue;
                }
                else
                {
                    tcb_table[tcb_index]->startTime = timer.Start();
                    tcb_table[tcb_index]->totalByteSent = 0;

                    pool.ex_tcb.next();
                    return tcb_it;
                }
            }
	}

	return -1;
}




#ifdef TCP-RRE
int inline nxt_schedule_conn(u_int tcb_index)
{
    u_int it = -1;
    
    u_long_long timeUsed;
    double timeInterval;
    double timeSleep;
    u_long_long current_time;    
    
    while (!tcb_table[tcb_index]->states.isEmpty())
    {
        it = tcb_table[tcb_index]->states.iterator();
        u_short sport = tcb_table[tcb_index]->states.state_id[it];
        current_time = timer.Start();
        
        timeUsed = tcb_table[tcb_index]->conn[sport]->sliding_snd_window.timeInterval(current_time);
        if (tcb_table[tcb_index]->conn[sport]->send_rate == 0 || tcb_table[tcb_index]->conn[sport]->totalByteSent < MTU)
        {            
            tcb_table[tcb_index]->states.next();
            
            //printf("%lu %u %u\n", timeUsed, tcb_table[tcb_index]->conn[sport]->send_rate, tcb_table[tcb_index]->conn[sport]->totalByteSent);
            
            return it;
        }
        else
        {
            //timeInterval = (double)tcb_table[tcb_index]->conn[sport]->totalByteSent * (double)RESOLUTION / (double)tcb_table[tcb_index]->conn[sport]->send_rate;
            timeInterval = (double)tcb_table[tcb_index]->conn[sport]->sliding_snd_window.bytes() * (double)RESOLUTION / (double)tcb_table[tcb_index]->conn[sport]->send_rate;
            timeSleep = timeInterval - (double)timeUsed;
            
            if (timeSleep >= 1)
            {
                tcb_table[tcb_index]->states.next();
                
                //printf("%lf %lf\n", timeSleep, timeInterval);
                
                continue;
            }
            else
            {
                tcb_table[tcb_index]->conn[sport]->startTime = timer.Start();
                tcb_table[tcb_index]->conn[sport]->totalByteSent = 0;
                    
                tcb_table[tcb_index]->states.next();
                
                //printf("%lf\n", timeSleep, tcb);
                return it;
            }
        }
                        
    }
    
    return -1;
}
#endif




#ifndef TCP-RRE
int inline nxt_schedule_conn(u_int tcb_index)
{
    u_int it;

    if (!tcb_table[tcb_index]->states.isEmpty())
    {
        it = tcb_table[tcb_index]->states.iterator();
        tcb_table[tcb_index]->states.next();
        return it;
    }
    return -1;
}
#endif



void inline rm_tcb_conn(u_int tcb_index, u_short sport, int tcb_it, int conn_it)
{
	tcb_table[tcb_index]->states.del(conn_it);
	tcb_table[tcb_index]->conn[sport]->flush();
	tcb_table[tcb_index]->conn[sport] = NULL;

	pool._size --;

	conn_hash.decrease();

	if (tcb_table[tcb_index]->states.isEmpty())
	{
		pool.ex_tcb.del(tcb_it);
		tcb_table[tcb_index]->flush();

		tcb_hash.decrease();
	}
}
void inline accclient_snd_data_pkt(DATA* data, u_int tcb_index, u_short sport, u_short dport, u_short adv_win)
{            
    ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.head();
    ip_header* ih = (ip_header *)((u_char *)tmpForwardPkt->pkt_data + 14);
    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
    u_short total_len = ntohs(ih->tlen);
    tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
    u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
    u_short data_len = total_len - ip_len - tcp_len;
    th->ack_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);
    //th->window = htons(adv_win);
    rcv_header_update(ih, th, tcp_len, data_len);

    send_backward(data, &tmpForwardPkt->header, tmpForwardPkt->pkt_data);
    tmpForwardPkt->initPkt();
    tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.headNext();
    tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.decrease();
                                                     
}
u_int urand()
{
    return (double(rand()%176));
}
u_int genuniform(u_int min, u_int max)
{
    double random_no = double(rand()%(TOTAL_NO_PKT + 1));
    double uniform_no = random_no / double(TOTAL_NO_PKT);
    
    return min + (max - min)*uniform_no; 
}
u_int genexp(double mean)
{
    double uniform_no = double(urand())/double(175);
    return -mean*log(uniform_no);
}
time_t get_current_time(u_int8_t force_now) {
  if(force_now
     /*|| readOnlyGlobals.reforgeTimestamps
     || (readWriteGlobals == NULL)*/)
    return(time(NULL));
  /*else
    return(readWriteGlobals->now);*/
}
void traceEvent(const int eventTraceLevel, const char* file,
		const int line, const char * format, ...) {
  va_list va_ap;

  //if(eventTraceLevel <= readOnlyGlobals.traceLevel) 
  {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = get_current_time(1);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf)-1, "%s [%s:%d] %s%s", theDate,
#ifdef WIN32
	     strrchr(file, '\\')+1,
#else
	     file,
#endif
	     line, extra_msg, buf);

#ifndef WIN32
    /*
    if(readOnlyGlobals.useSyslog) {
      if(!readWriteGlobals->syslog_opened) {
	openlog(readOnlyGlobals.nprobeId, LOG_PID, LOG_DAEMON);
	readWriteGlobals->syslog_opened = 1;
      }

      syslog(LOG_INFO, "%s", out_buf);
    } else*/
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}
static void deEndianRecord(struct generic_netflow_record *record) {
  record->last = ntohl(record->last), record->first = ntohl(record->first);

  if(record->srcaddr.ipVersion == 4) {
    record->srcaddr.ipType.ipv4 = ntohl(record->srcaddr.ipType.ipv4);
    record->dstaddr.ipType.ipv4 = ntohl(record->dstaddr.ipType.ipv4);
    record->nexthop.ipType.ipv4 = ntohl(record->nexthop.ipType.ipv4);
  }

  record->sentPkts = ntohl(record->sentPkts), record->rcvdPkts = ntohl(record->rcvdPkts);
  record->srcport = ntohs(record->srcport), record->dstport = ntohs(record->dstport);
  record->sentOctets = ntohl(record->sentOctets), record->rcvdOctets = ntohl(record->rcvdOctets);
  record->input = ntohs(record->input), record->output = ntohs(record->output);
  record->src_as = htonl(record->src_as), record->dst_as = htonl(record->dst_as);
  record->icmpType = ntohs(record->icmpType);
}










void* scheduler(void* _arg)
{
	struct pcap_pkthdr *header;

	DATA* data = (DATA *)_arg;
	Forward* forward = data->forward;

	ForwardPkt *tmpPkt, *timeoutPkt;
	u_short sport, tcb_index;
	u_long_long current_time;
	int tcb_it, conn_it;

	BOOL retransmit;
	BOOL newTransmit;

	u_int snd_win;
	int space;
	printf("State Ack iTime(ms) RTT(ms) SendRate(KB/s) TotalEstRate(KB/s) EstRate(KB/s) Conn\n");

	u_int seq_nxt = 0;

	while (TRUE)
	{
            pthread_mutex_lock(&pool.mutex);
            while (pool.ex_tcb.isEmpty())
                pthread_cond_wait(&pool.m_eventConnStateAvailable, &pool.mutex);

            pthread_mutex_unlock(&pool.mutex);

            tcb_it = nxt_schedule_tcb();

            if (tcb_it == -1)
                continue;
            tcb_index = pool.ex_tcb.state_id[tcb_it];
            conn_it = nxt_schedule_conn(tcb_index);

            if (conn_it == -1)
                continue;

            sport = tcb_table[tcb_index]->states.state_id[conn_it];

            if (sport == 0)
                continue;
            
            pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);                        
            if(tcb_table[tcb_index]->conn[sport]->server_state.state != CLOSED)
            {
                current_time = timer.Start();

#ifdef LOG_STAT
                log_data(sport, tcb_index);
#endif

                retransmit = TRUE;                
                //print_conn_stats(tcb_index, sport, current_time);

                if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts() > 0)
                {                    

                    if (tcb_table[tcb_index]->conn[sport]->close_time)
                        tcb_table[tcb_index]->conn[sport]->close_time = 0;

                    if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
                    {
                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                        if (!tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                        {
                            snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                            space = snd_win - (int)(tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);

                            if ((int)tmpPkt->data_len > space + NUM_PKT_BEYOND_WIN * tcb_table[tcb_index]->conn[sport]->max_data_len)
                            {
                                retransmit = FALSE;
                                goto normal_timeout_check;
                            }

                        }
                        else if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                        {
#ifdef CTRL_FLIGHT
                            
                            if (tcb_table[tcb_index]->probe_state) 
                            {
                                snd_win =tcb_table[tcb_index]->snd_wnd * tcb_table[tcb_index]->conn[sport]->max_data_len;
                                space = snd_win - (int)tcb_table[tcb_index]->pkts_transit;

                                if ((int)tmpPkt->data_len > space)
                                {
                                    retransmit = FALSE;
                                    goto normal_timeout_check;
                                }
                            }
                            else if (tcb_table[tcb_index]->send_rate < 2 * tcb_table[tcb_index]->conn[sport]->max_data_len * RESOLUTION / MIN_RTT)
                            {
                                space = 3 * MTU - (int) tcb_table[tcb_index]->pkts_transit;

                                if ((int)tmpPkt->data_len > space) {
                                    retransmit = FALSE;
                                    goto normal_timeout_check;
                                }
                            }
#endif
                        }

                        if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                            tmpPkt->rtx_time = tmpPkt->snd_time;
                        tmpPkt->snd_time = 0;

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();

                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD || tcb_table[tcb_index]->conn[sport]->server_state.state == CLOSED)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                            }
                            else
                                tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;
                            
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                            if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;
                        }
                        else
                        {
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len;
                                if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;
                        }

normal_timeout_check: 

                        timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                        if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto*2)
                        {
                                tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;

                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;

                                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;

                                if (!tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts)
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                if (!timeoutPkt->rtx_time)
                                    timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;

                        }


                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                    }
                    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                    {
                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                        if (MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge)) // Cannot retransmit beyong the largest right edge of SACK lists
                        {
                            retransmit = FALSE;
                            goto timeout_timer_check;
                        }

                        if (retransmit)
                        {
                            if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                    tmpPkt->rtx_time = tmpPkt->snd_time;
                            tmpPkt->snd_time = 0;
                        }

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();


                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                            }
                            else
                                tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                        }
                        else
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                        if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;

                        
timeout_timer_check:
                   
                        if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 0)
                        {
                            timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

                            /*
                            if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time  + TIME_TO_LIVE)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;                                    

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                if (!timeoutPkt->rtx_time)
                                    timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;

                                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                data_size_in_flight(tcb_index, timeoutPkt->data_len);
                            }
                            */

                            if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time  + tcb_table[tcb_index]->conn[sport]->rto)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                if (!timeoutPkt->rtx_time)
                                     timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;
                               
                            }
                        }
                        else if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)// I modified the timeout handler 29/11/2012
                        {
                            timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head);
                            if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                            {
                                if (tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count >= 2)
                                {
                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;                                    

                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                    if (!timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;

                                    tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                    data_size_in_flight(tcb_index, timeoutPkt->data_len);

                                }   
                                else
                                {
                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;

                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

                                    if (!timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;

                                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++;
                                    data_size_in_flight(tcb_index, timeoutPkt->data_len);
                                }
                            }
                        }

                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);


                    }
                    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
                    {

                        newTransmit = FALSE;
                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();
                        if (MY_SEQ_LT(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
                        {

                            /*
                            if (tcb_table[tcb_index]->conn[sport]->sack_block_num > 0)
                            {
                                    for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
                                    {
                                            if (tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block && tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block && MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block) && MY_SEQ_LEQ(tmpPkt->seq_num + tmpPkt->data_len, tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block))
                                            {
                                                    retransmit = FALSE;
                                                    break;
                                            }
                                    }
                            }
                            */

                            if (!tmpPkt->is_rtx)
                            {
                                retransmit = FALSE;
                            }
                            else if (tmpPkt->is_rtx)
                            {                                
                                data_size_in_flight(tcb_index, tmpPkt->data_len);
                            }

                            tcb_table[tcb_index]->conn[sport]->opp_rtx_space += tmpPkt->data_len;


                        }
                        else if (MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                            {
                                retransmit = FALSE;
                                //tcb_table[tcb_index]->conn[sport]->opp_rtx_space += tmpPkt->data_len;

                                if (!enable_opp_rtx)
                                {
                                    snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                                    space = snd_win -(int)(tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->seq_num - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);
                                    if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                        newTransmit = TRUE;

                                }                             
                                else if (enable_opp_rtx)
                                {
#ifdef CTRL_FLIGHT 
                                    snd_win = tcb_table[tcb_index]->conn[sport]->opp_rtx_space;
                                    space = snd_win;

                                    if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                    {
                                        newTransmit = TRUE;
                                    }

                                    //newTransmit = TRUE;

#else

                                    snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

                                    space = snd_win - (int)tcb_table[tcb_index]->pkts_transit;
                                    if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                    {
                                        newTransmit = TRUE;
                                    }

                                    //newTransmit = TRUE;
#endif
                                }

                                goto fast_rtx_timer_check;

                            }
                            else
                            {
                                retransmit = FALSE;

                                snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                                space = snd_win - (int)(tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);

                                if ((int)tmpPkt->data_len <= space)
                                {
                                    newTransmit = TRUE;

                                }

                                /*
                                snd_win = tcb_table[tcb_index]->conn[sport]->max_data_len * BDP;
                                space = snd_win - (int)tcb_table[tcb_index]->pkts_transit*(int)tcb_table[tcb_index]->conn[sport]->max_data_len;
                                space = snd_win - (int)tcb_table[tcb_index]->pkts_transit;
                                if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                {
                                    newTransmit = TRUE;
                                }
                                */

                                goto fast_rtx_timer_check;
                            }
                        }


                        if (retransmit)
                        {
                            if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                tmpPkt->rtx_time = tmpPkt->snd_time;
                            tmpPkt->snd_time = 0;
                        }

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();

                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                            }
                            else
                                tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                        }
                        else
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                        if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;

fast_rtx_timer_check:

                        timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

                        if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                        {

                            tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;
                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;
                            if (!timeoutPkt->rtx_time)
                                timeoutPkt->rtx_time = timeoutPkt->snd_time;
                            timeoutPkt->snd_time = 0;

                        }

                        if (newTransmit)
                        {

                            if (!tcb_table[tcb_index]->conn[sport]->send_out_awin && 
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts > 0)
                            {
                                tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

                                if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                    tmpPkt->rtx_time = tmpPkt->snd_time;
                                tmpPkt->snd_time = 0;

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadNext();

                                if ((tmpPkt->ctr_flag & 0x01) == 1)
                                {
                                    if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                                    {
                                        tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                        tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                                    }
                                    else
                                        tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                                }
                                else
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                                if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;

                                retransmit = TRUE;
                                tcb_table[tcb_index]->conn[sport]->opp_rtx_space -= tmpPkt->data_len;
                            }
                        }

                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                    }


                    if (retransmit)
                    {

                        send_data_pkt(forward, tmpPkt);
                        tcb_table[tcb_index]->totalByteSent += tmpPkt->data_len;                        
                        tcb_table[tcb_index]->conn[sport]->totalByteSent += tmpPkt->data_len;

                        tcb_table[tcb_index]->sliding_snd_window.put(tmpPkt->data_len, current_time, tmpPkt->seq_num);                                                
                        tcb_table[tcb_index]->conn[sport]->sliding_snd_window.put(tmpPkt->data_len, current_time, tmpPkt->seq_num);                        
                        tcb_table[tcb_index]->pkts_transit += tmpPkt->data_len;

                        tcb_table[tcb_index]->sent_bytes_counter += tmpPkt->data_len;
                                                
                        //log_debug_conn_info(tcb_index, sport, current_time);

                    }
                    

                }
                else
                {

                    if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size > 0)
                    {
                        timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                        if (tcb_table[tcb_index]->conn[sport]->client_state.state == CLOSED && 
                                timeoutPkt->snd_time && 
                                current_time > timeoutPkt->snd_time + TIME_TO_LIVE)
                        {
                            tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                            tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                            data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size * (int)tcb_table[tcb_index]->conn[sport]->max_data_len);

                        }
                        else
                        {                            
                            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)// I modified the timeout handler 29/11/2012
                            {

                                timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                                if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto*2)
                                {
                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;

                                    tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;

                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;

                                    if (!tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts)
                                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();                                    

                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                    if (!timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;
                                }


                            }
                            else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)// I modified the timeout handler 29/11/2012
                            {

                                timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                                if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                                {

                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                    if (timeoutPkt->snd_time && !timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;

                                }
                            }
                            else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)// I modified the timeout handler 29/11/2012
                            {

                                if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)
                                {

                                    timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head);
                                    if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                                    {
                                        if (tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count >= 2)
                                        {
                                            tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;                                    

                                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;

                                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                            if (!timeoutPkt->rtx_time)
                                                timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                            timeoutPkt->snd_time = 0;

                                            tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                            tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                            data_size_in_flight(tcb_index, timeoutPkt->data_len);

                                        }   
                                        else
                                        {
                                           tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;

                                           tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                                           tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;
                                           tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

                                           if (!timeoutPkt->rtx_time)
                                              timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                           timeoutPkt->snd_time = 0;

                                           tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++;
                                           data_size_in_flight(tcb_index, timeoutPkt->data_len);
                                        } 
                                    }
                                }                                                              
                            }
                        }
                    }

                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                }
            }
            else if (tcb_table[tcb_index]->conn[sport]->server_state.state == CLOSED && 
                    tcb_table[tcb_index]->conn[sport]->client_state.state == CLOSED)
            {
                pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                if (!tcb_table[tcb_index]->conn[sport]->close_time)
                     tcb_table[tcb_index]->conn[sport]->close_time = timer.Start();


                if (check_buffer_empty(tcb_index, sport))
                {
                    tcb_table[tcb_index]->flush_tcb_partially();
                } 


                if (timer.Start() > tcb_table[tcb_index]->conn[sport]->close_time + TIME_TO_LIVE)
                {
                    rm_tcb_conn(tcb_index, sport, tcb_it, conn_it);
                }

            }
            else
            {
                pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
            }
        }                   
}
void* forwarder(void* arg)
{
	Forward* forward = (Forward* )arg;
	struct pcap_pkthdr header;
	u_char pkt_data[PKT_SIZE];

	u_short dport, sport, ctrl_flag;
	u_int index, tcb_index, seq_num, TSval;
	u_short data_len;
        
        BOOL drop = FALSE;
       
#ifdef PKT_DROP_EMULATOR       
        
        u_long_long initial_time = 0;
              
        u_int num_pkt_drop = 0; 
        u_int num_pkt_tx = 0;
        u_int loss_rate = NUM_PKT_DROP;
                                
        u_int pkt_counter = 0;
        u_int current_seq_no = 0;        
        
        srand(time(NULL));
        bitset<TOTAL_NO_PKT> total_pkt;
        enable_opp_rtx = TRUE;
        
        if (forward->mode == SERVER_TO_CLIENT)
        {
            
            u_int lost_no_pkt = NUM_PKT_DROP;
            u_int *loss_event = new u_int[lost_no_pkt];
                       
            u_int no_event = 0;
            u_int event_lost_pkt;
            
            printf("Lost Events: ");
            
            while (TRUE)
            {
                event_lost_pkt = max(1, (int)min((u_int)genexp(2), lost_no_pkt));
                loss_event[no_event] = event_lost_pkt;
                lost_no_pkt = lost_no_pkt - event_lost_pkt; 
                
                printf("%u ", event_lost_pkt);
                   
                if (event_lost_pkt)
                   no_event ++;
                
                if (!lost_no_pkt)
                    break;
               
            }
            
            printf("\n");
            
            u_int pkt_index;
            BOOL flag;
            for (u_int i = 0; i < no_event; )
            {
                pkt_index = genuniform(1, TOTAL_NO_PKT);

                flag = TRUE;
                for (u_int j = 0; j < loss_event[i]; j ++)
                {
                    if (pkt_index + j >= TOTAL_NO_PKT || total_pkt[pkt_index + j])
                    {
                        flag = FALSE;
                        break; 
                    }
                    
                }
                
                if (flag)
                {
                    for (u_int j = 0; j < loss_event[i]; j ++)
                        total_pkt[pkt_index + j] = 1;
                    
                    i ++;
                    printf("%d ", pkt_index);
                
                }
            }
            
            printf("\n");
            
        }
        
        printf("Finish Initialization\n");
#endif       
        
	while(1)
	{
            pthread_mutex_lock(&forward->mutex);
            while (forward->pktQueue.size() == 0)
                pthread_cond_wait(&forward->m_eventElementAvailable, &forward->mutex);
            ForwardPkt* tmpForwardPkt = forward->pktQueue.head();
            dport = tmpForwardPkt->dPort;
            index = tmpForwardPkt->index;
            sport = tmpForwardPkt->sPort;
            data_len = tmpForwardPkt->data_len;
            ctrl_flag = tmpForwardPkt->ctr_flag;
            tcb_index = tmpForwardPkt->tcb;
            seq_num = tmpForwardPkt->seq_num;
            TSval = tmpForwardPkt->TSval;
            memcpy(&header, &(tmpForwardPkt->header), sizeof(struct pcap_pkthdr));
            memcpy(pkt_data, tmpForwardPkt->pkt_data, header.len);
            tmpForwardPkt->initPkt();
            forward->pktQueue.headNext();
            forward->pktQueue.decrease();
            pthread_cond_signal(&forward->m_eventSpaceAvailable);
            pthread_mutex_unlock(&forward->mutex);

#ifdef PKT_DROP_EMULATOR
            
            if (sport == APP_PORT_NUM || sport == APP_PORT_FORWARD || sport == APP_PORT_NUM + 1)
            {
                /*
                if (!initial_time)
                    initial_time = timer.Start();
                
                if (timer.Start() >= initial_time + DROP_PERIOD)
                {
                    
                    mac_header* mh = (mac_header *)pkt_data; 
                    ip_header* ih = (ip_header *) (pkt_data + 14); 
                    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
	            u_short total_len = ntohs(ih->tlen);
                    tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
                    u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                    u_short data_len = total_len - ip_len - tcp_len;
                    th->seq_num = htonl(num_pkt_drop);
                    rcv_header_update(ih, th, tcp_len, data_len);
                    
                    
                    if (num_pkt_drop)
                    {
                        if (header.len > 100)
                        {
                            num_pkt_drop --;
                            drop = TRUE;
                        }
                        else
                            drop = FALSE;
                    }
                    else
                    {
                        num_pkt_drop = NUM_PKT_DROP;
                        initial_time = timer.Start();
                    }
                                      
                }*/
                
                
                if (ctrl_flag == 18)
                {
                    pkt_counter = 0;
                    current_seq_no = seq_num;
                    printf("Start to emulate packet dorp enable opp rtx %u\n", enable_opp_rtx);                   
                }
                else if (data_len > 0 && seq_num > current_seq_no)
                {
                    current_seq_no = seq_num;
                                                            
                    if (pkt_counter >= TOTAL_NO_PKT)
                    {
                        pkt_counter = 0;
                    }
                    else if (total_pkt[pkt_counter] == 1)
                    {
                        
                        if (num_pkt_tx > 100)
                        {
                            drop = TRUE;                        
                            //printf("pkt %d is dropped\n", pkt_counter);
                            num_pkt_drop ++;
                        }
                        //printf("%u %u %u\n", num_pkt_drop, num_pkt_tx, num_pkt_drop*100/num_pkt_tx);
                        
                    }
                    else if (total_pkt[pkt_counter] != 1)
                    {   
                        
                        
                        if (num_pkt_tx > 100 && num_pkt_drop*100/num_pkt_tx < loss_rate)
                        {
                            drop = TRUE;
                            num_pkt_drop ++;
                            
                            //printf("%u %u %u\n", num_pkt_drop, num_pkt_tx, num_pkt_drop*100/num_pkt_tx);
                        }
                    }
                    
                    pkt_counter ++;                    
                    num_pkt_tx ++;
                }
                else if (data_len > 0 && seq_num <= current_seq_no)
                {
                   num_pkt_tx ++;    
                   
                   
                   //current_seq_no = seq_num;
                    
                }
                
                
                                                
            }
#else
           

#endif
            
            if (!drop)
            {                
                if (pcap_sendpacket(forward->dev, pkt_data, header.len) != 0)
                {
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(forward->dev));
                    exit(-1);
                }                
            }
            else
                drop = FALSE;
            
            if(sport == APP_PORT_NUM || sport == APP_PORT_FORWARD)
            {

                if (tcb_table[tcb_index]->conn[dport] && tcb_table[tcb_index]->conn[dport]->server_state.state != CLOSED)
                {
                    ForwardPkt* sendPkt = tcb_table[tcb_index]->conn[dport]->dataPktBuffer.pkt(index);
                    sendPkt->snd_time = timer.Start();                
                    tcb_table[tcb_index]->sliding_avg_window.sent_timestamp_rep = TSval;
                }                  
            }
	}
}






/**********for programming convenience, it is temprorately  for interpret the tcp option of tcp packets from real server*************/
void inline intepret_ack_sack_option_server(u_char* tcp_opt, u_int tcp_opt_len, u_short sport, u_int ack_num, u_int tcb_index, u_int awin)
{
    for (u_int i = 0; i < tcp_opt_len; )
    {
        switch ((u_short)*(tcp_opt + i))
        {

        case 0: //end of option
                *(tcp_opt + i) = 1;
                //printf("END OF OPTION\n");
                break;
        case 1: //NOP
                //printf("NO OF OPERATION\n");
                break;
        case 8: //TCP Timestamp                            
                if (!tcb_table[tcb_index]->cur_ack_TSval) 
                    tcb_table[tcb_index]->cur_ack_TSval = ntohl(*(u_int *)(tcp_opt + i + 2));
                
                tcb_table[tcb_index]->cur_ack_TSval ++;
                *(u_int *)(tcp_opt + i + 2) = htonl(tcb_table[tcb_index]->cur_ack_TSval);
                        
                tcb_table[tcb_index]->cur_ack_TSval = ntohl(*(u_int *)(tcp_opt + i + 2));
                tcb_table[tcb_index]->cur_ack_TSecr = ntohl(*(u_int *)(tcp_opt + i + 2 + 4));
                
                break;

        }        

        if ((u_short)*(tcp_opt + i) > 1)
           i += (u_short)*(tcp_opt + i + 1);
        else
           i ++;
    }
}







void* capturer(void* _data)
{
	struct pcap_pkthdr *header_ptr;
	const u_char *pkt_data_ptr;
	DATA* data = (DATA *)_data;
	int res;
	u_char pkt_data[PKT_SIZE];
	u_char pkt_buffer[PKT_SIZE];
	struct pcap_pkthdr header;
	srand(time(NULL));

	u_long_long current_time;
	char key[sizeof(ip_address)+sizeof(u_short)];
	
	FILE *form = fopen("toDataBase", "w");
	
	while((res = pcap_next_ex(data->dev_this, &header_ptr, &pkt_data_ptr)) >= 0)
	{
		if (res == 0)
                        continue; // Timeout elapsed

		current_time = timer.Start();
                
		memcpy(&header, header_ptr, sizeof(struct pcap_pkthdr));
		if (header.len <= PKT_SIZE)
		{
                    memcpy(pkt_data, pkt_data_ptr, header.len);
		}
		else
			continue; //Jumbo Frame

		if (pkt_data[14] == '\0')
                    send_forward(data, &header, pkt_data);
		else if (pkt_data[14] != '\0')
		{
                    mac_header* mh = (mac_header *)pkt_data; // mac header
                    ip_header* ih = (ip_header *) (pkt_data + 14); //length of ethernet header
                    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
                    u_short total_len = ntohs(ih->tlen);
                    u_short id = ntohs(ih->identification);
                    u_short off = ntohs(ih->flags_fo) & 0x3fff;
                    
                    
                    if ((u_int)ih->proto != 6)
                    {
                        if (likely((u_int)ih->proto == 17))
                        {
                            udp_header* uh = (udp_header *)((u_char *)ih + ip_len);
                            u_short sport = ntohs(uh->sport);
                            u_short dport = ntohs(uh->dport);
                            u_short udp_len = ntohs(uh->len);
                            u_int data_len = udp_len - sizeof(struct udp_header);
                            u_short payload_shift = sizeof(struct udp_header);
                            
                            //printf("UDP packets %u %u %u %hu %hu\n", total_len, ip_len, udp_len, sport, dport);
                            if ((data_len > 0) && ((dport == 2055) || (dport == 2057) || (dport == 6343) || (sport == 6343) || (dport == 9999) 
                                    || (dport == 3000) || (dport == 6000) || (dport == 9996) || (dport == 15003) || (sport == 35467) 
				    || (dport == 9500) || (sport == 55298) || (dport == 9000))) 
                            {                            
                                NetFlow5Record the5Record;
                                u_short flowVersion;
                                u_int recordActTime = 0, recordSysUpTime = 0;                                
                                struct generic_netflow_record record;
                                
                                /*
                                flow_ver5_hdr* myRecord = (flow_ver5_hdr *)((u_char *)uh + payload_shift);
                                u_short version = ntohs(myRecord->version);
                                printf("version %u\n", version);
                                */
                                
                                memcpy(&the5Record, (NetFlow5Record *)((u_char *)uh + payload_shift), data_len > sizeof(NetFlow5Record) ? sizeof(NetFlow5Record) : data_len);
                                flowVersion = ntohs(the5Record.flowHeader.version);                                               
                                u_short numFlows = ntohs(the5Record.flowHeader.count);
                                
                                //traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(version=%hu, len=%u)\n", flowVersion, data_len);
                                                                                                
                                if (flowVersion == 6)
                                {                                    
                                    u_short i, numFlows = ntohs(the5Record.flowHeader.count);
                                    recordActTime = ntohl(the5Record.flowHeader.unix_secs);
                                    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);
                                                                        
                                    //traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(%d flows)\n", numFlows);                                    				    
				    
                                    memset(&record, 0, sizeof(record));
                                    record.vlanId = (u_int16_t)-1;
                                    record.ntop.nw_latency_sec = record.ntop.nw_latency_usec = htonl(0);
                                    /*
				    fprintf(form, "%hu %hu %u %u %u %u %hu %hu %hu ", the5Record.flowHeader.version, the5Record.flowHeader.count, 
					    the5Record.flowHeader.sysUptime, the5Record.flowHeader.unix_secs, the5Record.flowHeader.unix_nsecs, 
					    the5Record.flowHeader.flow_sequence, the5Record.flowHeader.engine_type, the5Record.flowHeader.engine_id, 
					    the5Record.flowHeader.sampleRate);
				    */
                                    for(i=0; i<numFlows; i++) 
                                    {
                                        record.srcaddr.ipType.ipv4 = the5Record.flowRecord[i].srcaddr, record.srcaddr.ipVersion = 4;
                                        record.dstaddr.ipType.ipv4 = the5Record.flowRecord[i].dstaddr, record.dstaddr.ipVersion = 4;
                                        record.nexthop.ipType.ipv4  = the5Record.flowRecord[i].nexthop, record.nexthop.ipVersion = 4;
                                        record.input       = the5Record.flowRecord[i].input;
                                        record.output      = the5Record.flowRecord[i].output;
                                        record.sentPkts    = the5Record.flowRecord[i].dPkts;
                                        record.sentOctets  = the5Record.flowRecord[i].dOctets;
                                        record.first       = the5Record.flowRecord[i].first;
                                        record.last        = the5Record.flowRecord[i].last;
                                        record.tos         = the5Record.flowRecord[i].tos;
                                        record.srcport     = the5Record.flowRecord[i].srcport;
                                        record.dstport     = the5Record.flowRecord[i].dstport;
                                        record.tcp_flags   = the5Record.flowRecord[i].tcp_flags;
                                        record.proto       = the5Record.flowRecord[i].proto;
                                        record.dst_as      = htonl(ntohs(the5Record.flowRecord[i].dst_as));
                                        record.src_as      = htonl(ntohs(the5Record.flowRecord[i].src_as));
                                        record.dst_mask    = the5Record.flowRecord[i].dst_mask;
                                        record.src_mask    = the5Record.flowRecord[i].src_mask;
                                        record.engine_type = the5Record.flowHeader.engine_type;
                                        record.engine_id   = the5Record.flowHeader.engine_id;

                                        deEndianRecord(&record);
                                        //record.sentPkts   *= readOnlyGlobals.flowCollection.sampleRate;
                                        //record.sentOctets *= readOnlyGlobals.flowCollection.sampleRate;

                                        //handleGenericFlow(0 /* fake threadId */,
                                        //                 netflow_device_ip, recordActTime,
                                        //                  recordSysUpTime, &record);
                                        
                                        //traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(src %s:%hu dst %s:%hu)", iptos(record.srcaddr.ipType.ipv4), 
					//	record.srcport, iptos(record.dstaddr.ipType.ipv4), record.dstport);
					/*
					fprintf(form, "%hu %hu %u %u %u %u %hu %hu %hu ", the5Record.flowHeader.version, the5Record.flowHeader.count, 
					    the5Record.flowHeader.sysUptime, the5Record.flowHeader.unix_secs, the5Record.flowHeader.unix_nsecs, 
					    the5Record.flowHeader.flow_sequence, the5Record.flowHeader.engine_type, the5Record.flowHeader.engine_id, 
					    the5Record.flowHeader.sampleRate);
					
					fprintf(form, "{%s %s %s %hu %hu %u %u %u %u %hu %hu %hu %hu %hu %hu %hu %hu %hu %hu %hu}\n", 
						iptos(record.srcaddr.ipType.ipv4), iptos(record.dstaddr.ipType.ipv4), iptos(record.nexthop.ipType.ipv4), 
						record.input, record.output, record.sentPkts, record.sentOctets, record.first, record.last, 
						record.srcport, record.dstport, the5Record.flowRecord[i].pad1, record.tcp_flags, record.proto, 
						the5Record.flowRecord[i].tos, record.src_as, record.dst_as, record.src_mask, record.dst_mask,
						the5Record.flowRecord[i].pad2);
					
					fflush(form);
					*/
                                    }                                
                                }
				else if (flowVersion == 9)
				{
					printf("Netflow Version Number: %hu\n", flowVersion);
				}
                            }                                                        
                        }
			
			
                        send_forward(data, &header, pkt_data);
                    }
                    else if ((u_int)ih->proto == 6) //TCP
                    {
                        tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
                        u_short sport = ntohs(th->sport);
                        u_short dport = ntohs(th->dport);
                        u_int seq_num = ntohl(th->seq_num);
                        u_int ack_num = ntohl(th->ack_num);
                        u_short window = ntohs(th->window);
                        u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                        u_short ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
                        u_short data_len = total_len - ip_len - tcp_len;

                        if (sport == APP_PORT_NUM || sport == APP_PORT_FORWARD) //coming from server and we have already allocated a connection table
                        {
                            int tcb_index = tcb_hash.search((char *)&ih->daddr, sizeof(ip_address), &ih->daddr);
                            if (tcb_index == -1)
                            {
#ifdef DEBUG
                                printf("CANNOT FIND A TCB FOR USER %d.%d.%d.%d PORT %hu\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);

#endif                                          
                                send_forward(data, &header, pkt_data);
                                continue;
                            }

                            if (!tcb_table[tcb_index]->conn[dport])
                            {
#ifdef DEBUG
                                    printf("CAN FIND A TCB FOR USER %c.%c.%c.%c BUT NO CONNECTION FOR PORT %hu\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);

#endif                                          
                                send_forward(data, &header, pkt_data);
                                continue;
                            }
                            else if (tcb_table[tcb_index]->conn[dport] != NULL)
                            {
                                tcb_table[tcb_index]->conn[dport]->client_state.snd_nxt = ack_num;                                                                
                                
                                                                
                                
                                switch(tcb_table[tcb_index]->conn[dport]->client_state.state)
                                {
                                    case SYN_SENT:
                                    if (ctr_flag == 18) //SYN+ACK pkt
                                    {

                                        u_short flag = 0;
                                        if (tcp_len > 20) // TCP Options
                                        {
                                            u_int tcp_opt_len = tcp_len - 20;
                                            u_char *tcp_opt = (u_char *)th + 20;
                                            syn_sack_option(tcp_opt, tcp_opt_len, dport, FALSE, tcb_index);
                                            rcv_header_update(ih, th, tcp_len, data_len);

                                            /* for reference please don't uncomment it
                                            th->window = htons(LOCAL_WINDOW);
                                            th->crc = 0;

                                            memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                            psd_header psdHeader;

                                            psdHeader.saddr = ih->saddr;
                                            psdHeader.daddr = ih->daddr;
                                            psdHeader.mbz = 0;
                                            psdHeader.ptoto = IPPROTO_TCP;
                                            psdHeader.tcp_len = htons(tcp_len);

                                            memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                            memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
                                            th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
                                            */
                                        }

                                        tcb_table[tcb_index]->conn[dport]->client_state.state = ESTABLISHED; 
                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = seq_num + 1;
                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;
                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;


#ifdef COMPLETE_SPLITTING_TCP
                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                        u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                        send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                        /*
                                        ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[dport]->client_state.httpRequest;
                                        if (tmpForwardPkt->occupy)
                                        {
                                            ip_header* ih = (ip_header *)((u_char *)tmpForwardPkt->pkt_data + 14);
                                            u_int ip_len = (ih->ver_ihl & 0xf) * 4;
                                            u_short total_len = ntohs(ih->tlen);
                                            tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
                                            u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                                            u_short data_len = total_len - ip_len - tcp_len;
                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);
                                            th->window = htons(adv_win);
                                            rcv_header_update(ih, th, tcp_len, data_len);

                                            send_backward(data, &tmpForwardPkt->header, tmpForwardPkt->pkt_data);
                                            tmpForwardPkt->initPkt();
                                        }
                                        */


                                        while (tcb_table[tcb_index]->conn[dport]->client_state.httpRequest.size())
                                            accclient_snd_data_pkt(data, tcb_index, sport, dport, adv_win);


#else
                                        tcb_table[tcb_index]->conn[dport]->server_state.state = SYN_REVD;
                                        tcb_table[tcb_index]->conn[dport]->server_state.snd_una = seq_num;
                                        tcb_table[tcb_index]->conn[dport]->server_state.seq_nxt = seq_num + 1;
                                        tcb_table[tcb_index]->conn[dport]->server_state.snd_nxt = seq_num + 1;
                                        tcb_table[tcb_index]->conn[dport]->server_state.snd_max = seq_num + 1;
                                        send_forward(data, &header, pkt_data);
                                        //send_forward_with_params(data, &header, pkt_data, sport, dport, data_len, ctr_flag, seq_num, tcb_index);
                                         
#endif

                                    }
                                    else
                                    {
#ifdef DEBUG
                                            printf("SYN+ACK PACKET IS REQUIRED TO INIT CONNECTION %hu\n", dport);
#endif
                                    }
                                    break;

                                    case ESTABLISHED:
                                        
                                    if (tcp_len > 20) // TCP Options
                                    {
                                        u_int tcp_opt_len = tcp_len - 20;
                                        u_char *tcp_opt = (u_char *)th + 20;
                                        intepret_ack_sack_option_server(tcp_opt, tcp_opt_len, dport, ack_num, tcb_index, window);
                                        rcv_header_update(ih, th, tcp_len, data_len);

                                    }    
                                        
                                    if (!tcb_table[tcb_index]->conn[dport]->local_adv_window)
                                            tcb_table[tcb_index]->conn[dport]->local_adv_window = window * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale);
                                   
                                    if ((ctr_flag & 0x10) == 16 && seq_num < tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                    {
                                        if (data_len > 0 || (ctr_flag & 0x01) == 1)
                                        {

                                            u_short flag = 0;

#ifdef DEBUG
                                            printf("RECEIVING OLD PACKET %u WAITING PACKET %u ON CONNECTION %hu\n", seq_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, dport);
#endif

                                            //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);

                                            tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;
                                            //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                            //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                            u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                            if (adv_win && adv_win != LOCAL_WINDOW)
                                                    adv_win ++;

                                            if (adv_win)
                                            {
                                                send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                            }
                                            else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                            {
                                                send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                            }

                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                    tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                        }
                                        else 
                                        {
#ifndef COMPLETE_SPLITTING_TCP
#ifdef RSFC
                                            u_short adv_win = tcb_table[tcb_index]->conn[dport]->local_adv_window / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale);
                                            if (adv_win != window) 
                                            {
                                                th->window = htons(adv_win);
                                                rcv_header_update(ih, th, tcp_len, data_len, pkt_buffer);
                                            }
#endif                                     
                                          //  send_forward_with_params(data, &header, pkt_data, sport, dport, data_len, ctr_flag, seq_num, tcb_index);
                                         
#endif 
                                        }

                                    }
                                    else if ((ctr_flag & 0x10) == 16 && seq_num >= tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt) 
                                    {
                                        if (data_len > 0 || (ctr_flag & 0x01) == 1)
                                        {

                                            u_short flag = 0;
                                            u_short adv = 0;

                                            if (seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt < 
                                                    (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * 
                                                    tcb_table[tcb_index]->conn[dport]->MSS)
                                            {
                                                if (seq_num == tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                {
#ifdef COMPLETE_SPLITTING_TCP
                                                        th->seq_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt);
                                                        rcv_header_update(ih, th, tcp_len, data_len);

                                                        /*
                                                        th->crc = 0;
                                                        memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                        psd_header psdHeader;
                                                        psdHeader.saddr = ih->saddr;
                                                        psdHeader.daddr = ih->daddr;
                                                        psdHeader.mbz = 0;
                                                        psdHeader.ptoto = IPPROTO_TCP;
                                                        psdHeader.tcp_len = htons(tcp_len + data_len);

                                                        memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                        memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);
                                                        th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);
                                                        */
#endif
                                                    if ((ctr_flag & 0x01) == 1)
                                                    {

                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                        rcv_data_pkt(data, &header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);

                                                        u_int rcv_nxt_seq = check_sack_list(tcb_index, dport, seq_num, data_len);

                                                        tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt += (rcv_nxt_seq -tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + 1);                                                                                               												
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = (rcv_nxt_seq + 1);
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;

                                                        //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv5_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);

                                                        u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                        if (adv_win && adv_win != LOCAL_WINDOW)
                                                            adv_win ++;

                                                        send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                        //tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSE_WAIT;
                                                        //send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16|1, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                        //tcb_table[tcb_index]->conn[dport]->client_state.state = LAST_ACK;

                                                    }
                                                    else if (data_len > 0)
                                                    {

                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                        rcv_data_pkt(data, &header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);

                                                        u_int rcv_nxt_seq = check_sack_list(tcb_index, dport, seq_num, data_len);

                                                        tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt += (rcv_nxt_seq -tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt) ;
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = rcv_nxt_seq;
                                                        //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;
                                                        adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd - (tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);

                                                        //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 1) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                        u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                        if (adv_win && adv_win != LOCAL_WINDOW)
                                                                adv_win ++;
                                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;

                                                        BOOL acking = TRUE;
                                                        tcb_table[tcb_index]->conn[dport]->client_state.ack_count = tcb_table[tcb_index]->conn[dport]->client_state.ack_count + 1;
                                                        if ((tcb_table[tcb_index]->conn[dport]->client_state.ack_count = tcb_table[tcb_index]->conn[dport]->client_state.ack_count % 2) == 0)
                                                                acking = TRUE;

                                                        if (acking == TRUE || (ctr_flag & 0x08) == 8)
                                                        {
                                                            //if (adv_win || (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt))
                                                            {
                                                                send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                                if (!adv_win)
                                                                   tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                            }


                                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                                tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                                            else
                                                                tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 0;
                                                        }
                                                    }

                                                }
                                                else // out of order packets
                                                {
#ifdef DEBUG
                                                        printf("DISCARD OUT OF ORDER PACKET %u WAITTING ON PACKET %u ON CONNECTION %hu---\n", seq_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, dport);

#endif

#ifdef COMPLETE_SPLITTING_TCP
                                                        th->seq_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt + seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);
                                                        rcv_header_update(ih, th, tcp_len, data_len);

                                                        /*
                                                        th->crc = 0;
                                                        memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                        psd_header psdHeader;
                                                        psdHeader.saddr = ih->saddr;
                                                        psdHeader.daddr = ih->daddr;
                                                        psdHeader.mbz = 0;
                                                        psdHeader.ptoto = IPPROTO_TCP;
                                                        psdHeader.tcp_len = htons(tcp_len + data_len);

                                                        memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                        memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);
                                                        th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);
                                                        */
#endif

                                                    pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                    rcv_data_pkt(data, &header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
                                                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);

                                                    create_sack_list(tcb_index, dport, seq_num, data_len);

                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;

                                                    //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                    //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 1) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                    //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                    //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                    u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                    if (adv_win && adv_win != LOCAL_WINDOW)
                                                            adv_win ++;

                                                    if (adv_win)
                                                    {
                                                        send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                    }
                                                    else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                    {
                                                        send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                        tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                    }

                                                    if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                            tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                                }
                                            }
                                            else if (/*(ctr_flag & 0x10) == 16 && (data_len > 0 || (ctr_flag & 0x01) == 1) &&*/seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt >= (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS) // Outbound packets
                                            {
                                                //u_short flag = 0;
                                                tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;

#ifdef DEBUG
                                                printf("DISCARD OUT OF WINDOW PACKET %u WINDOW SIZE %u WAITTING ON PACKET %u %u ON CONNECTION %hu\n", seq_num, tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size(), tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, tcb_table[tcb_index]->conn[dport]->MSS, dport);
#endif
                                                //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                if (adv_win && adv_win != LOCAL_WINDOW)
                                                                adv_win ++;

                                                if (adv_win)
                                                {
                                                    send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);       
                                                }
                                                else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                {
                                                    send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                    tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                }

                                                if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                                tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                            }
                                        }
                                        else
                                        {

#ifdef COMPLETE_SPLITTING_TCP
                                            th->seq_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt);
                                            rcv_header_update(ih, th, tcp_len, data_len, pkt_buffer);

#else

#ifdef RSFC
                                            u_short adv_win = tcb_table[tcb_index]->conn[dport]->local_adv_window /
                                                    pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale);
                                            if (adv_win != window) 
                                            {
                                                th->window = htons(adv_win);
                                                rcv_header_update(ih, th, tcp_len, data_len, pkt_buffer);
                                            }

#endif 

                                            //send_forward(data, &header, pkt_data);
                                            //send_forward_with_params(data, &header, pkt_data, sport, dport, data_len, ctr_flag, seq_num, tcb_index);
                                         

#endif

                                        }

                                    }
                                    else 
                                    {

#ifdef RSFC
                                        u_short adv_win = tcb_table[tcb_index]->conn[dport]->local_adv_window / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale);
                                        if (adv_win != window) 
                                        {
                                            th->window = htons(adv_win);
                                            rcv_header_update(ih, th, tcp_len, data_len, pkt_buffer);
                                        }

#endif

                                        //send_forward(data, &header, pkt_data);
                                        //send_forward_with_params(data, &header, pkt_data, sport, dport, data_len, ctr_flag, seq_num, tcb_index);
                                     
                                    }
                                    
                                    break;					

                                case LAST_ACK:
                                    if ((ctr_flag & 0x10) == 16 /*&& seq_num == tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt*/)
                                    {
                                        tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSED;
#ifdef DEBUG
                                        printf("CLOSED GATEWAY-SERVER CONNECTION %hu\n", dport);
#endif
                                    }
                                    
                                    break;

                                case CLOSED:
                                    if ((ctr_flag & 0x01) == 1)
                                    {
                                        u_short flag = 0;
                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;

                                        u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                        if (adv_win && adv_win != LOCAL_WINDOW)
                                                adv_win ++;

                                        tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = check_sack_list(tcb_index, dport, seq_num, data_len) + 1;
                                        send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                        tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSED;
                                    }
                                    else if ((ctr_flag & 0x02) == 2)
                                    {
                                        send_forward(data, &header, pkt_data);
                                    }

                                    break;
                                }
                            }
                        }
                        else if (dport == APP_PORT_NUM || dport == APP_PORT_FORWARD) //coming from client
                        {
                                int tcb_index = tcb_hash.search((char *)&ih->saddr, sizeof(ip_address), &ih->saddr);

                                if (tcb_index != -1 && tcb_table[tcb_index]->conn[sport] != NULL)
                                {

                                        if ((ctr_flag & 0x04) == 4)//RST
                                        {
                                            /*
                                            pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                            delete tcb_table[tcb_index]->conn[sport];
                                            tcb_table[tcb_index]->conn[sport] = NULL;
                                            pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                            */

#ifdef COMPLETE_SPLITTING_TCP

                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                            rcv_header_update(ih, th, tcp_len, data_len);

                                            /*
                                            th->window = htons(LOCAL_WINDOW);
                                            th->crc = 0;

                                            memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                            psd_header psdHeader;

                                            psdHeader.saddr = ih->saddr;
                                            psdHeader.daddr = ih->daddr;
                                            psdHeader.mbz = 0;
                                            psdHeader.ptoto = IPPROTO_TCP;
                                            psdHeader.tcp_len = htons(tcp_len + data_len);

                                            memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                            memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);
                                            th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);
                                            */

#endif
                                            send_forward(data, &header, pkt_data);
                                            //data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size * tcb_table[tcb_index]->conn[sport]->max_data_len);

                                            pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                            rcv_rst_handler(sport, tcb_index, current_time, ctr_flag);
                                            pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                            if (tcb_table[tcb_index]->conn[sport] != NULL)
                                            {
                                                tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                                                tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                            }

                                            continue;
                                        }

                                        switch(tcb_table[tcb_index]->conn[sport]->server_state.state)
                                        {
                                                case SYN_REVD:
                                                if ((ctr_flag & 0x10) == 16 && ack_num > tcb_table[tcb_index]->conn[sport]->server_state.snd_una && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max) //ACK
                                                {

                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = ESTABLISHED;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

#ifdef COMPLETE_SPLITTING_TCP
                                                    /*
                                                    tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;
                                                    if (data_len > 0) //http request
                                                    {
                                                            ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest;
                                                            tmpForwardPkt->data = (void *)data;
                                                            memcpy(&(tmpForwardPkt->header), &header, sizeof(struct pcap_pkthdr));
                                                            memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                            memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);
                                                            tmpForwardPkt->sPort = sport;
                                                            tmpForwardPkt->dPort = dport;
                                                            tmpForwardPkt->seq_num = seq_num;
                                                            tmpForwardPkt->data_len = data_len;
                                                            tmpForwardPkt->ctr_flag = ctr_flag;
                                                            tmpForwardPkt->snd_time = 0;
                                                            tmpForwardPkt->rcv_time = 0;
                                                            tmpForwardPkt->num_dup = 0;
                                                            tmpForwardPkt->is_rtx = true;
                                                            tmpForwardPkt->occupy = true;
                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.state == ESTABLISHED)
                                                            {
                                                                    th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                                    th->window = htons(LOCAL_WINDOW);
                                                                    rcv_header_update(ih, th, tcp_len, data_len, pkt_buffer);
                                                                    tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
                                                                    memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                                    memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);
                                                                    send_forward(data, &header, pkt_data);
                                                                    tmpForwardPkt->initPkt();
                                                            }
                                                    }
                                                    */

                                                    if (data_len > 0)
                                                    {
                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.size() < tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.capacity)
                                                        {

                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                         
                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.state != SYN_SENT)
                                                            {
                                                                tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                                th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                                                            
                                                                //th->window = htons(LOCAL_WINDOW);
                                                                rcv_header_update(ih, th, tcp_len, data_len);              
                                                                send_forward(data, &header, pkt_data);                                                                

                                                            }
                                                            else
                                                                accclient_rcv_data_pkt(data, &header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);

                                                            u_short flag = 0;
                                                            send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        }
                                                        else 
                                                        {
                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                         
                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.state != SYN_SENT)
                                                            {
                                                                tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                                th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                                                            
                                                                //th->window = htons(LOCAL_WINDOW);
                                                                rcv_header_update(ih, th, tcp_len, data_len);              
                                                                send_forward(data, &header, pkt_data);             
                                                            }

                                                            u_short flag = 0;
                                                            send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, 0, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        }
                                                    }
                                                    else
                                                    {
                                                            /*
                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                                       

                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                                                           
                                                            rcv_header_update(ih, th, tcp_len, data_len);              
                                                            send_forward(data, &header, pkt_data);                
                                                            */ 

                                                    }   

#else
                                                    if (data_len > 0)
                                                    {
                                                        u_short flag = 0;
                                                        send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                    }

                                                    tcb_table[tcb_index]->conn[sport]->client_state.state = ESTABLISHED;
                                                    send_forward(data, &header, pkt_data);


                                                    //send_wait_forward(data, &header, pkt_data); // test with wifi
#endif


                                                }
                                                else if (ctr_flag == 2) //SYN pkt retransmission
                                                {

                                                    u_short flag = 0;

                                                    u_int tcp_opt_len = tcp_len - 20;
                                                    u_char *tcp_opt = (u_char *)th + 20;
                                                    syn_sack_option(tcp_opt, tcp_opt_len, sport, TRUE, tcb_index);

                                                    rcv_header_update(ih, th, tcp_len, data_len);
                                                    /*
                                                    th->window = htons(LOCAL_WINDOW);
                                                    th->crc = 0;

                                                    memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                    psd_header psdHeader;

                                                    psdHeader.saddr = ih->saddr;
                                                    psdHeader.daddr = ih->daddr;
                                                    psdHeader.mbz = 0;
                                                    psdHeader.ptoto = IPPROTO_TCP;
                                                    psdHeader.tcp_len = htons(tcp_len);

                                                    memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                    memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
                                                    th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
                                                    */
                                                    tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = CIRCULAR_BUF_SIZE * tcb_table[tcb_index]->conn[sport]->MSS; // can be increased

#ifdef COMPLETE_SPLITTING_TCP
                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_una = tcb_table[tcb_index]->conn[sport]->server_state.snd_una;
                                                    tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
#else
                                                    tcb_table[tcb_index]->conn[sport]->client_state.state = SYN_SENT;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
#endif
                                                    send_forward(data, &header, pkt_data);
#ifdef COMPLETE_SPLITTING_TCP
                                                    send_syn_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, seq_num + data_len + 1, flag|18, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, tcp_opt,  tcp_opt_len, pkt_buffer);
#endif
                                                }
                                                else
                                                {
#ifdef DEBUG
                                                    printf("FLAG %hu UNACK PACKET DUMPED IN SYN_REV STATE snd_max: %u snd_una: %u, ack: %u\n", ctr_flag, tcb_table[tcb_index]->conn[sport]->server_state.snd_max, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, ack_num);
#endif
                                                }
                                                break;

                                                case ESTABLISHED:
                                                if ((ctr_flag & 0x10) == 16) // have ACK flag
                                                {
                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = ESTABLISHED;

                                                    if ((ctr_flag & 0x01) == 1) //FIN Received
                                                    {
                                                        u_short flag = 0;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;

                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);


                                                        send_ack_back(sport, data, 
                                                                tcb_table[tcb_index]->conn[sport]->server_ip_address, 
                                                                tcb_table[tcb_index]->conn[sport]->client_ip_address, 
                                                                tcb_table[tcb_index]->conn[sport]->server_mac_address, 
                                                                tcb_table[tcb_index]->conn[sport]->client_mac_address, 
                                                                dport, sport, ack_num, seq_num + data_len + 1, flag|16, 
                                                                LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, 
                                                                &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        send_ack_back(sport, data, 
                                                                tcb_table[tcb_index]->conn[sport]->server_ip_address, 
                                                                tcb_table[tcb_index]->conn[sport]->client_ip_address, 
                                                                tcb_table[tcb_index]->conn[sport]->server_mac_address, 
                                                                tcb_table[tcb_index]->conn[sport]->client_mac_address, 
                                                                dport, sport, ack_num, seq_num + data_len + 1, flag|16|1, 
                                                                LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, 
                                                                &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt ++;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_max ++;

                                                        
                                                        //send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16|1, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1);                                                        

                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.state != CLOSED)
                                                        {
#ifdef COMPLETE_SPLITTING_TCP
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                            rcv_header_update(ih, th, tcp_len, data_len);
#endif
                                                            //tcb_table[tcb_index]->conn[sport]->client_state.state = FIN_WAIT_1;
                                                            tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                                                            send_forward(data, &header, pkt_data);
                                                        }

                                                        data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size * tcb_table[tcb_index]->conn[sport]->max_data_len);
                                                        tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
#ifdef DEBUG
                                                        printf("CLOSED GATEWAY-CLIENT CONNECTION %hu\n", sport);
#endif
                                                    }
                                                    else if (data_len > 0 /*&& MY_SEQ_GEQ(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max*/) // data packet needs be acked
                                                    {

#ifdef COMPLETE_SPLITTING_TCP
                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.size() 
                                                                    < tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.capacity)
                                                            {

                                                                tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                       
                                                                if (tcb_table[tcb_index]->conn[sport]->client_state.state != SYN_SENT)
                                                                {
                                                                   tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = 
                                                                           (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                                   th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);        
                                                                   //th->window = htons(LOCAL_WINDOW);
                                                                   rcv_header_update(ih, th, tcp_len, data_len);    
                                                                   send_forward(data, &header, pkt_data);                                                                
                                                                }
                                                                else
                                                                {

                                                                    accclient_rcv_data_pkt(data, &header, pkt_data, sport, dport, seq_num, data_len, 
                                                                            ctr_flag, tcb_index);
                                                                }

                                                                u_short flag = 0;
                                                                send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->client_ip_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->server_mac_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->client_mac_address, 
                                                                        dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, 
                                                                        tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, 
                                                                        &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                            }
                                                            else 
                                                            {
                                                                tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                                                               if (tcb_table[tcb_index]->conn[sport]->client_state.state != SYN_SENT)
                                                                 {
                                                                    tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - 
                                                                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * 
                                                                            tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                                    th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                 
                                                                    rcv_header_update(ih, th, tcp_len, data_len);              
                                                                    send_forward(data, &header, pkt_data);             
                                                                 }

                                                                u_short flag = 0;
                                                                send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->client_ip_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->server_mac_address, 
                                                                        tcb_table[tcb_index]->conn[sport]->client_mac_address, 
                                                                        dport, sport, ack_num, seq_num + data_len, flag|16, 0, 
                                                                        tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, 
                                                                        &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                            }

                                                            /*
                                                            ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest;
                                                            tmpForwardPkt->data = (void *)data;
                                                            memcpy(&(tmpForwardPkt->header), &header, sizeof(struct pcap_pkthdr));
                                                            memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                            memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);
                                                            tmpForwardPkt->sPort = sport;
                                                            tmpForwardPkt->dPort = dport;
                                                            tmpForwardPkt->seq_num = seq_num;
                                                            tmpForwardPkt->data_len = data_len;
                                                            tmpForwardPkt->ctr_flag = ctr_flag;
                                                            tmpForwardPkt->snd_time = 0;
                                                            tmpForwardPkt->rcv_time = 0;
                                                            tmpForwardPkt->num_dup = 0;
                                                            tmpForwardPkt->is_rtx = true;
                                                            tmpForwardPkt->occupy = true;
                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;
                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.state == ESTABLISHED)
                                                            {
                                                                    th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                                    th->window = htons(LOCAL_WINDOW);
                                                                    rcv_header_update(ih, th, tcp_len, data_len);
                                                                    tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
                                                                    memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                                    memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);
                                                                    send_forward(data, &header, pkt_data);
                                                                    tmpForwardPkt->initPkt();
                                                            }
                                                            */
#else
                                                            send_forward(data, &header, pkt_data);
                                                            /*
                                                            u_short flag = 0;
                                                            send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, 
                                                                    tcb_table[tcb_index]->conn[sport]->client_ip_address, 
                                                                    tcb_table[tcb_index]->conn[sport]->server_mac_address, 
                                                                    tcb_table[tcb_index]->conn[sport]->client_mac_address, 
                                                                    dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, 
                                                                    tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, 
                                                                    &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                                            */

#endif

                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;																											
                                                        //pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        //pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);									
                                                        //rcv_data_uplink_slide_win_avg_bw(tcb_index, sport, ack_num, data_len, current_time);
                                                        //rcv_data_downlink_queueing_delay_est(tcb_index, sport);


                                                    }
                                                    else if (MY_SEQ_GT(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                                    {
                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                                        u_int adv_win = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) 
                                                                * tcb_table[tcb_index]->conn[sport]->MSS;
                                                        if (adv_win >= tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd + 0.5 * tcb_table[tcb_index]->conn[sport]->dataPktBuffer.capacity * tcb_table[tcb_index]->conn[sport]->MSS || !tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd)
                                                        {
                                                            u_short flag = 0;
                                                            //tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2 > 0 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[sport]->MSS:0);
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[sport]->MSS;
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd;
                                                            //u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                            u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                            if (adv_win && adv_win != LOCAL_WINDOW)
                                                                    adv_win ++;

                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd >= tcb_table[tcb_index]->conn[sport]->MSS)
                                                                    send_win_update_forward(sport, data, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, dport, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[sport]->MSS)
                                                                    tcb_table[tcb_index]->conn[sport]->client_state.ack_count = 1; // next ready to ack
                                                        }

                                                    }
                                                    else if (ack_num == tcb_table[tcb_index]->conn[sport]->server_state.snd_una)
                                                    {
                                                        if (tcp_len > 20) // TCP Options
                                                        {
                                                            u_int tcp_opt_len = tcp_len - 20;
                                                            u_char *tcp_opt = (u_char *)th + 20;
                                                            ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index, window);
                                                        }
                                                                
                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_dup_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                    }
                                                    else
                                                    {
#ifdef DEBUG
                                                            printf("FLAGS %hu PACKET DUMPED\n", ctr_flag);
#endif
                                                    }
                                                }
                                                else
                                                {
#ifdef DEBUG
                                                        printf("FLAG %hu UNACK PACKET DUMPED IN ESTABLISH STATE\n", ctr_flag);
#endif
                                                }
                                                
                                                break;

                                                case FIN_WAIT_1:
                                                if ((ctr_flag & 0x10) == 16)
                                                {
                                                    /*
                                                    if (tcp_len > 20) // TCP Options
                                                    {
                                                        u_int tcp_opt_len = tcp_len - 20;
                                                        u_char *tcp_opt = (u_char *)th + 20;
                                                        ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index, window);
                                                    }
                                                    */

                                                    if ((ctr_flag & 0x01) == 1) //FIN Received
                                                    {
                                                        u_short flag = 0;

                                                        send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        //send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16|1, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt ++;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_max ++;
                                                        /*
                                                        send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16|1, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1);
                                                        */
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.state != CLOSED)
                                                        {
#ifdef COMPLETE_SPLITTING_TCP
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                            rcv_header_update(ih, th, tcp_len, data_len);
#endif
                                                            //tcb_table[tcb_index]->conn[sport]->client_state.state = FIN_WAIT_1;
                                                            tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
                                                            send_forward(data, &header, pkt_data);
                                                        }

                                                        data_size_in_flight(tcb_index, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size * tcb_table[tcb_index]->conn[sport]->max_data_len);
                                                        tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
#ifdef DEBUG
                                                            printf("CLOSED GATEWAY-CLIENT CONNECTION %hu\n", sport);
#endif
                                                    }
                                                    else if (data_len > 0 /*&& MY_SEQ_GEQ(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max*/) // data packet needs be acked
                                                    {
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;

#ifdef COMPLETE_SPLITTING_TCP
                                                        /*
                                                        ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest;
                                                        tmpForwardPkt->data = (void *)data;
                                                        memcpy(&(tmpForwardPkt->header), &header, sizeof(struct pcap_pkthdr));
                                                        //memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                        memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);
                                                        tmpForwardPkt->sPort = sport;
                                                        tmpForwardPkt->dPort = dport;
                                                        tmpForwardPkt->seq_num = seq_num;
                                                        tmpForwardPkt->data_len = data_len;
                                                        tmpForwardPkt->ctr_flag = ctr_flag;
                                                        tmpForwardPkt->snd_time = 0;
                                                        tmpForwardPkt->rcv_time = 0;
                                                        tmpForwardPkt->num_dup = 0;
                                                        tmpForwardPkt->is_rtx = true;
                                                        tmpForwardPkt->occupy = true;

                                                        tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;

                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.state == ESTABLISHED)
                                                        {
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                            th->window = htons(LOCAL_WINDOW);
                                                            rcv_header_update(ih, th, tcp_len, data_len);

                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
                                                            memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
                                                            memcpy(tmpForwardPkt->pkt_data, pkt_data, header.len);

                                                            send_forward(data, &header, pkt_data);
                                                            tmpForwardPkt->initPkt();
                                                        }
                                                        */

                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.size() < tcb_table[tcb_index]->conn[sport]->client_state.httpRequest.capacity)
                                                        {

                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                                       
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                                                            
                                                            //th->window = htons(LOCAL_WINDOW);
                                                            rcv_header_update(ih, th, tcp_len, data_len);              
                                                            send_forward(data, &header, pkt_data);                                                       

                                                            u_short flag = 0;
                                                            send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        }
                                                        else 
                                                        {
                                                            tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;                                                                                                       
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;                                                                                        
                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);                                                                                            
                                                            //th->window = htons(LOCAL_WINDOW);
                                                            rcv_header_update(ih, th, tcp_len, data_len);              
                                                            send_forward(data, &header, pkt_data);             

                                                            u_short flag = 0;
                                                            send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, 0, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                        }
#else
                                                        send_forward(data, &header, pkt_data);

                                                        //u_short flag = 0;
                                                        //send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

#endif
                                                    
                                                        //pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);                                                        
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        //pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        //rcv_data_uplink_slide_win_avg_bw(tcb_index, sport, ack_num, data_len, current_time);
                                                        //rcv_data_downlink_queueing_delay_est(tcb_index, sport);

                                                    }                                                                
                                                    else if (MY_SEQ_GT(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                                    {
                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                                        u_int adv_win = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
                                                        if (adv_win >= tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd + 0.5 * tcb_table[tcb_index]->conn[sport]->dataPktBuffer.capacity * tcb_table[tcb_index]->conn[sport]->MSS || !tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd)
                                                        {
                                                            u_short flag = 0;
                                                            //tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2 > 0 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[sport]->MSS:0);
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[sport]->MSS;
                                                            tcb_table[tcb_index]->conn[sport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd;
                                                            //u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                            adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                            if (adv_win && adv_win != LOCAL_WINDOW)
                                                                    adv_win ++;

                                                            if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd >= tcb_table[tcb_index]->conn[sport]->MSS)
                                                                    send_win_update_forward(sport, data, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, dport, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[sport]->MSS)
                                                                    tcb_table[tcb_index]->conn[sport]->client_state.ack_count = 1; // next ready to ack
                                                        }
                                                    }
                                                    else if (ack_num == tcb_table[tcb_index]->conn[sport]->server_state.snd_una)
                                                    {
                                                        if (tcp_len > 20) // TCP Options
                                                        {
                                                            u_int tcp_opt_len = tcp_len - 20;
                                                            u_char *tcp_opt = (u_char *)th + 20;
                                                            ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index, window);
                                                        }
        
                                                        
                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                        rcv_dup_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                    }
                                                    else
                                                    {
#ifdef DEBUG
                                                            printf("FLAGS %hu PACKET DUMPED\n", ctr_flag);
#endif
                                                    }
                                                }
                                                else
                                                {
#ifdef DEBUG
                                                        printf("FLAG %hu UNACK PACKET DUMPED IN FIN_WAIT STATE\n", ctr_flag);
#endif
                                                }
                                                break;

                                                case CLOSED:
                                                if ((ctr_flag & 0x02) == 2)
                                                {
                                                    tcb_table[tcb_index]->conn[sport]->init_state_ex(mh->mac_src, mh->mac_dst, ih->saddr, ih->daddr, sport, dport, tcb_table[tcb_index], tcb_table[tcb_index]->conn[sport]->index);
                                                    u_short flag = 0;
                                                    u_int tcp_opt_len = tcp_len - 20;
                                                    u_char *tcp_opt = (u_char *)th + 20;

                                                    syn_sack_option(tcp_opt, tcp_opt_len, sport, TRUE, tcb_index);
                                                    rcv_header_update(ih, th, tcp_len, data_len);

                                                    tcb_table[tcb_index]->conn[sport]->client_state.state = SYN_SENT;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
                                                    tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())* tcb_table[tcb_index]->conn[sport]->MSS; // can be increased

                                                    if (tcb_table[tcb_index]->send_beyong_win)
                                                        tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = TRUE;

#ifdef COMPLETE_SPLITTING_TCP                                                            
                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;



                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_una = seq_num;


                                                    tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;;

                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;

                                                    send_syn_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, seq_num + data_len + 1, flag|18, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, tcp_opt, tcp_opt_len, pkt_buffer);

#endif
                                                    send_forward(data, &header, pkt_data);

                                                }
                                                else if ((ctr_flag & 0x01) == 1)
                                                {
                                                    u_short flag = 0;                                                                        

                                                    send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, 64, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = seq_num + data_len + 1;
                                                    //tcb_table[tcb_index]->conn[sport]->server_state.snd_max ;
                                                }

                                                break;

                                            }
					}
					else //tcb exists but conn does not exist, or tcb does not exist and conn does not exists
					{
                                            if (ctr_flag == 2)  //SYN packet
                                            {
                                                if (tcb_index == -1)
                                                {
                                                    tcb_index = tcb_hash.Hash((char *)&ih->saddr, sizeof(ip_address));                                                               
                                                    if (tcb_index == -1)
                                                    {
                                                        send_forward(data, &header, pkt_data);
                                                        continue;
                                                    }

                                                    tcb_table[tcb_index]->init_tcb(ih->saddr, ih->daddr);
                                                    pool.add_tcb(tcb_index);
                                                }

                                                memcpy(key, &ih->saddr, sizeof(ip_address));
                                                memcpy(key+sizeof(ip_address), &sport, sizeof(u_short));
                                                int conn_index = conn_hash.Hash(key, sizeof(key));

                                                if (conn_index == -1)
                                                {
                                                    send_forward(data, &header, pkt_data);
                                                    continue;
                                                }

                                                conn_table[conn_index]->init_state_ex(mh->mac_src, mh->mac_dst, ih->saddr, ih->daddr, sport, dport, tcb_table[tcb_index], conn_index);
                                                tcb_table[tcb_index]->add_conn(sport, conn_table[conn_index]);
                                                pool._size ++;

                                                u_short flag = 0;
                                                u_int tcp_opt_len = tcp_len - 20;
                                                u_char *tcp_opt = (u_char *)th + 20;
                                                syn_sack_option(tcp_opt, tcp_opt_len, sport, TRUE, tcb_index);
                                                rcv_header_update(ih, th, tcp_len, data_len);                                            

                                                /*
                                                th->window = htons(LOCAL_WINDOW);
                                                th->crc = 0;
                                                memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                psd_header psdHeader;

                                                psdHeader.saddr = ih->saddr;
                                                psdHeader.daddr = ih->daddr;
                                                psdHeader.mbz = 0;
                                                psdHeader.ptoto = IPPROTO_TCP;
                                                psdHeader.tcp_len = htons(tcp_len);

                                                memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
                                                th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
                                                */

                                                tcb_table[tcb_index]->conn[sport]->client_state.state = SYN_SENT;
                                                tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
                                                tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())* tcb_table[tcb_index]->conn[sport]->MSS; // can be increased

                                                if (tcb_table[tcb_index]->send_beyong_win)
                                                    tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = TRUE;

#ifdef COMPLETE_SPLITTING_TCP
                                                tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
                                                tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                tcb_table[tcb_index]->conn[sport]->server_state.snd_una = MIN_RTT;//seq_num;



                                                //tcb_table[tcb_index]->conn[sport]->server_state.snd_una = seq_num + 100;

                                                tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;;

                                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
                                                tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;

                                                send_syn_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, seq_num + data_len + 1, flag|18, LOCAL_WINDOW, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, tcp_opt, tcp_opt_len, pkt_buffer);

#endif


                                                send_forward(data, &header, pkt_data);

                                                //send_wait_forward(data, &header, pkt_data);
                                            }
                                            else
                                            {
                                                send_forward(data, &header, pkt_data);
                                            }
                                        }
                        }
                        else
                        {
                            send_forward(data, &header, pkt_data);
                        }
                    }
		}
	}
	
		
	
	if (res < 0)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(data->dev_this));
		exit(-1);
	}
}
void* monitor(void* dummy)
{
#ifdef BW_SMOOTH
	u_short sport;
	int tcb_it, conn_it;
	u_int tcb_index;
	u_long_long current_time;





	printf("State Ack iTime(ms) RTT(ms) SendRate(KB/s) TotalEstRate(KB/s) EstRate(KB/s) Conn\n");

	while(TRUE)
	{
		pthread_mutex_lock(&pool.mutex);
		while (pool.ex_tcb.isEmpty())
			pthread_cond_wait(&pool.m_eventConnStateAvailable, &pool.mutex);

		tcb_it = pool.ex_tcb.iterator();
		tcb_index = pool.ex_tcb.state_id[tcb_it];

		pthread_mutex_unlock(&pool.mutex);


		pthread_mutex_lock(&tcb_table[tcb_index]->mutex);
		if (!tcb_table[tcb_index]->states.isEmpty())
		{
			conn_it = tcb_table[tcb_index]->states.iterator();
			sport = tcb_table[tcb_index]->states.state_id[conn_it];
		}
		else
		{
			pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);
			continue;
		}

		pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
		if(tcb_table[tcb_index]->conn[sport] && tcb_table[tcb_index]->conn[sport]->server_state.state != CLOSED)
		{
			if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL || tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
			{
				current_time = timer.Start();
				if (tcb_table[tcb_index]->sliding_avg_window.size() && current_time > tcb_table[tcb_index]->sliding_avg_window.tailTime() + 5)
				{
					tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->sliding_avg_window.bytes() * RESOLUTION / tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
					tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;
					BW_adaptation(sport, tcb_index);
#ifdef LOG_STAT
					log_data(sport, tcb_index);
#endif
				}
			}

		}

#ifndef DEBUG
		printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->RTT_limit, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, sport);
#endif

		pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
		pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);
	}
#endif

}

pcap_t *inAdHandle, *outAdHandle;

void inline list_dev()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(-1);
	}

	if (alldevs == NULL){
		fprintf(stderr, "\nNo interfaces found! Make sure Pcap is installed.\n");
		return;
	}

	/* Print the list */
	for (d = alldevs; d; d=d->next)
	{
		ifprint(d);
	}

	pcap_freealldevs(alldevs);
}
void inline init_dev()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;

	int i = 0;
	int inum, onum;
	struct bpf_program fcode;

	char inner_ad_packet_filter[128];
	char outter_ad_packet_filter[128];

    char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(-1);
	}

	/* Print the list */
	for (d = alldevs; d; d=d->next)
	{
		++ i;
		ifprint(d);
	}

	if (i == 0)
	{
		printf("\nNo interface found! Make sure WinPcap is installed.\n");
		exit(-1);
	}

	printf("Enter the input interface number and output interface number (1-%d):", i);

	fscanf(test_file, "%d\n", &inum);
	fscanf(test_file, "%d\n", &onum);

	/* Check if the user specified a valid adapter */
	if ((inum < 1 || inum > i) && (onum < 1 || onum > i))
	{
		printf("\nAdapter number out of range.\n");
		exit(-1);
	}

	printf("%d %d\n", inum, onum);

	/* Jump to the selected input adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i ++);

	int sockfd;

    if(-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0)))
    {
        perror( "socket" );
        return;
    }

    struct ifreq req;

    bzero(&req, sizeof(struct ifreq));
    strcpy(req.ifr_name, d->name);
    ioctl(sockfd, SIOCGIFHWADDR, &req);

    sprintf(inner_ad_packet_filter, "(ip || icmp || arp || rarp) && not ether host %02x:%02x:%02x:%02x:%02x:%02x",
			        (unsigned char)req.ifr_hwaddr.sa_data[0],
                                (unsigned char)req.ifr_hwaddr.sa_data[1],
                                (unsigned char)req.ifr_hwaddr.sa_data[2],
                                (unsigned char)req.ifr_hwaddr.sa_data[3],
                                (unsigned char)req.ifr_hwaddr.sa_data[4],
                                (unsigned char)req.ifr_hwaddr.sa_data[5]);
	printf("The application filter of inner adapter is %s\n", inner_ad_packet_filter);

	/* Open the input adapter */
	/*
	if ((inAdHandle = pcap_open_live(d->name, 65535, 1, 1, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}
        */

	if ((inAdHandle = pcap_create(d->name, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	pcap_set_snaplen(inAdHandle, 65535);
	pcap_set_promisc(inAdHandle, 1);
	pcap_set_timeout(inAdHandle, 1);
	pcap_set_buffer_size(inAdHandle, 200000000);
	pcap_activate(inAdHandle);


	/* set input adapter capturing direction */
	if (pcap_setdirection(inAdHandle, PCAP_D_IN))
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	/* Compile the input filter */
	if (pcap_compile(inAdHandle, &fcode, inner_ad_packet_filter, 1, 0x0) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet input filter. Check the syntax.\n");
		exit(-1);
	}

	/* Set the input filter */
	if (pcap_setfilter(inAdHandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the input filter.\n");
		exit(-1);
	}

	printf("\nlistening on %s...\n", d->description);

	/* Jump to the selected output adapter */
	for (d = alldevs, i = 0; i < onum - 1; d = d->next, i ++);

	bzero(&req, sizeof(struct ifreq));
        strcpy(req.ifr_name, d->name);
        ioctl(sockfd, SIOCGIFHWADDR, &req);

	sprintf(outter_ad_packet_filter, "(ip || icmp || arp || rarp) && not ether host %02x:%02x:%02x:%02x:%02x:%02x",
								(unsigned char)req.ifr_hwaddr.sa_data[0],
                                (unsigned char)req.ifr_hwaddr.sa_data[1],
                                (unsigned char)req.ifr_hwaddr.sa_data[2],
                                (unsigned char)req.ifr_hwaddr.sa_data[3],
                                (unsigned char)req.ifr_hwaddr.sa_data[4],
                                (unsigned char)req.ifr_hwaddr.sa_data[5]);

	printf("The application filter of outter adapter is %s\n", outter_ad_packet_filter);

	/* Open the output adapter */
	if ((outAdHandle = pcap_open_live(d->name, 65535, 1, 1, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the output adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	pcap_set_buffer_size(outAdHandle, 20000000);


	if (pcap_setdirection(outAdHandle, PCAP_D_IN))
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	/* Compile the output filter */
	if (pcap_compile(outAdHandle, &fcode, outter_ad_packet_filter, 1, 0x0) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet output filter. Check the syntax.\n");
		exit(-1);
	}

	/* Set the output filter */
	if (pcap_setfilter(outAdHandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the output filter.\n");
		exit(-1);
	}

	printf("\nlistening on %s...\n", d->description);

  	close(sockfd);
	pcap_freealldevs(alldevs);
}
int main()
{
	init_dev();

	pthread_t th_in2out_capture, th_in2out_forward, th_out2in_capture, th_out2in_forward, th_scheduler, th_monitor;

	Forward *forward_out2in, *forward_in2out;
	DATA *data_out2in, *data_in2out;
	u_int circularBufferSize = CIRCULAR_QUEUE_SIZE, out2inDelay = END_TO_END_DELAY, in2outDelay =  END_TO_END_DELAY;

	forward_out2in = new Forward(inAdHandle, circularBufferSize, out2inDelay, CLIENT_TO_SERVER);
	forward_in2out = new Forward(outAdHandle, circularBufferSize, in2outDelay, SERVER_TO_CLIENT);
	data_out2in = new DATA(outAdHandle, inAdHandle, "eth0", "eth2", CLIENT_TO_SERVER, forward_out2in, forward_in2out);
	data_in2out = new DATA(inAdHandle, outAdHandle, "eth2", "eth0", SERVER_TO_CLIENT, forward_in2out, forward_out2in);

	pthread_create(&th_out2in_forward, 0, forwarder, (void *)forward_out2in);
	pthread_create(&th_in2out_forward, 0, forwarder, (void *)forward_in2out);
	pthread_create(&th_out2in_capture, 0, capturer, (void *)data_out2in);
	pthread_create(&th_in2out_capture, 0, capturer, (void *)data_in2out);
	pthread_create(&th_scheduler, 0, scheduler, (void *)data_in2out);
	//pthread_create(&th_monitor, 0, monitor, NULL);

	//struct sched_param param;
	//param.sched_priority = sched_get_priority_max(SCHED_RR);
	//pthread_setschedparam(th_out2in_capture, SCHED_RR, &param);
	//pthread_setschedparam(th_in2out_capture, SCHED_RR, &param);

	pthread_join(th_out2in_forward, NULL);
	pthread_join(th_in2out_forward, NULL);
	pthread_join(th_out2in_capture, NULL);
	pthread_join(th_in2out_capture, NULL);
	pthread_join(th_scheduler, NULL);
	//pthread_join(th_monitor, NULL);

	if (inAdHandle != NULL)
		pcap_close(inAdHandle);
	if (outAdHandle != NULL)
		pcap_close(outAdHandle);

	delete forward_out2in;
	delete forward_in2out;
	delete data_out2in;
	delete data_in2out;

	return 0;
}
