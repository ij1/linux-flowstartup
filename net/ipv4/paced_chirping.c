/*
 *
 * The Paced Chirping start-up extension can be enabled by setting sysctl paced_chirping_enabled to 1.
 * Paced chirping is described in https://riteproject.files.wordpress.com/2018/07/misundjoakimmastersthesissubmitted180515.pdf
 *
 * Authors:
 *
 *      Joakim Misund <joakim.misund@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include "paced_chirping.h"

/* Algorithm functions */
static inline void start_new_round(struct tcp_sock *tp, struct paced_chirping *pc);
static u32 should_terminate(struct tcp_sock *tp, struct paced_chirping *pc);

/* Helper functions */
static struct cc_chirp* get_first_chirp(struct paced_chirping *pc);
static struct cc_chirp* get_last_chirp(struct paced_chirping *pc);

static u32 gap_to_Bps_ns(struct sock *sk, struct tcp_sock *tp, u32 gap_ns);
static uint32_t switch_divide(uint32_t value, uint32_t by, u8 round_up);

/* Experimental functionality */
static bool enough_data_for_chirp(struct sock *sk, struct tcp_sock *tp, int N);
static bool enough_data_committed(struct sock *sk, struct tcp_sock *tp);
static struct cc_chirp* cached_chirp_malloc(struct paced_chirping *pc);
static void cached_chirp_dealloc(struct cc_chirp *chirp);

/* Functions for debugging */
static void print_u64_array(u64 *array, u32 size, char *name, struct sock *sk);
static void print_u32_array(u32 *array, u32 size, char *name, struct sock *sk);

int paced_chirping_active(struct paced_chirping *pc)
{
	return pc->pc_state;
}
EXPORT_SYMBOL(paced_chirping_active);

void paced_chirping_exit(struct sock *sk, struct paced_chirping *pc, u32 reason)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* When Paced Chirping decides that it should exit because it has
	 * "filled the pipe" snd_cwnd and snd_ssthresh is set to match the
	 * rate estimate. This calculation is run upon loss. */
	if (pc->pc_state && reason != EXIT_TRANSITION) {
		tp->snd_cwnd = max(tp->packets_out >> 1U, 2U);
		tp->snd_ssthresh = tp->snd_cwnd;
	}
	tp->is_chirping = 0;
	tp->disable_cwr_upon_ece = 0;
	/* This will make the pacing rate 120% of that estimated when
	 * the next ack is received, if cong_control is not implemented. */
	tp->disable_kernel_pacing_calculation = 0;
	pc->pc_state = 0;

	LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,,exit=%u,gap=%u,cwnd=%u,min_rtt=%u,srtt=%u,round_length=%u,round_sent=%u,gain=%u,geometry=%u,cache=%lu\n",
		   ntohl(sk->sk_rcv_saddr),
		   ntohl(sk->sk_daddr),
		   sk->sk_num,
		   ntohs(sk->sk_dport),
		   reason,
		   pc->gap_avg_ns,
		   tp->snd_cwnd,
		   tcp_min_rtt(tp),
		   tp->srtt_us >> 3,
		   pc->round_length_us,
		   pc->round_sent,
		   (u32)pc->gain,
		   (u32)pc->geometry,
		   MEMORY_CACHE_SIZE_BYTES));
}
EXPORT_SYMBOL(paced_chirping_exit);

void paced_chirping_release(struct paced_chirping *pc)
{
	struct cc_chirp *chirp;
	if (pc->chirp_list) {
		while ((chirp = get_first_chirp(pc))) {
			list_del(&(chirp->list));
			cached_chirp_dealloc(chirp);
		}
		kfree(pc->chirp_list);
	}
	if (pc->memory_cache)
		kfree(pc->memory_cache);
}
EXPORT_SYMBOL(paced_chirping_release);

static inline void start_new_round(struct tcp_sock *tp, struct paced_chirping *pc)
{
	/* We only increase the number of chirps if we have sent the first 6 chirps
	 * and we managed to exhaust the previous allowed number of chirps.
	 * The first 6 chirps have sizes 5, 5, 8, 8, 16, 16. */
	if (pc->chirp_number >= 6)
		pc->M = (pc->M * pc->gain)>>G_G_SHIFT;

	pc->round_start = pc->chirp_number;
	pc->round_sent = pc->round_length_us = 0;
}
static u32 should_terminate(struct tcp_sock *tp, struct paced_chirping *pc)
{
	return tp->srtt_us && ((tp->srtt_us>>3) <= pc->round_length_us);
}
static struct cc_chirp* get_first_chirp(struct paced_chirping *pc)
{
	if (!pc->chirp_list || list_empty(&(pc->chirp_list->list)))
		return NULL;
	return list_first_entry(&(pc->chirp_list->list), struct cc_chirp, list);
}
static struct cc_chirp* get_last_chirp(struct paced_chirping *pc)
{
	if (!pc->chirp_list || list_empty(&(pc->chirp_list->list)))
		return NULL;
	return list_last_entry(&(pc->chirp_list->list), struct cc_chirp, list);
}

static void update_gap_avg(struct tcp_sock *tp, struct paced_chirping *pc,
			   u32 new_estimate_ns, u16 chirp_number)
{
	u32 prev_estimate_ns = pc->gap_avg_ns;

	if ((new_estimate_ns == INVALID_CHIRP) ||
	    /* Safety bound min 30us, max 10ms (400Mbps ~ 1Mbps). Use
	     * Slow Start" out of these bounds.
	     * ADDME: It might make sense to make the lower bound depend on
	     * clock granularity.
	     */
	    (new_estimate_ns > 10000000U) ||
	    (new_estimate_ns < 30000U)) {
		new_estimate_ns = prev_estimate_ns * (1 << (M_SHIFT-1)) / pc->M;
	}

	if (pc->gap_avg_ns == INITIAL_GAP_AVG && chirp_number == 0) {
		pc->gap_avg_ns = new_estimate_ns;
		return;
	}
	pc->gap_avg_ns = prev_estimate_ns -
		(prev_estimate_ns>>GAP_AVG_SHIFT) +
		(new_estimate_ns>>GAP_AVG_SHIFT);
}

static bool enough_data_for_chirp (struct sock *sk, struct tcp_sock *tp, int N)
{
	return READ_ONCE(tp->write_seq) - tp->snd_nxt >= tp->mss_cache * N;
}

static bool enough_data_committed(struct sock *sk, struct tcp_sock *tp)
{
	return SKB_TRUESIZE(tp->mss_cache) * CHIRP_SIZE  < refcount_read(&sk->sk_wmem_alloc);
}

/* Callback that kernel calls when it has packets to be sent but either has no chirp description or
 * used the current one. */
u32 paced_chirping_new_chirp (struct sock *sk, struct paced_chirping *pc)
{
	struct tcp_sock *tp = tcp_sk(sk);

	struct cc_chirp *new_chirp;
	struct cc_chirp *last_chirp;
	struct cc_chirp *cur_chirp;
	u32 N = CHIRP_SIZE;
	u32 guard_interval_ns;
	u32 gap_step_ns;
	u32 initial_gap_ns;
	u32 chirp_length_ns;

	if (!tp->is_chirping || !pc->chirp_list || !(pc->pc_state & STATE_ACTIVE)) {
		return 1;
	}

	/* Save information */
	if ((last_chirp = get_last_chirp(pc))) {
		if (!last_chirp->fully_sent) {
			last_chirp->begin_seq = tp->chirp.begin_seq;
			last_chirp->end_seq = tp->chirp.end_seq;
			last_chirp->fully_sent = 1;
		}
	}

	if (pc->chirp_number <= 1)
		N = 5;
	else if (pc->chirp_number <= 3)
		N = 8;

	/* Send marking packet
	 * This should probably made more robust. One option is to check that the sequence number change between
	 * this and the next call. */
	if (!(pc->pc_state & MARKING_PKT_SENT) && /* Not sent already */
	    (cur_chirp = get_first_chirp(pc)) &&
	    cur_chirp->chirp_number >= 0 && cur_chirp->qdelay_index > 0) /* Ack(s) of first chirp have been received */
	{
		LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,INFO:SENDING_MARK\n",
			   ntohl(sk->sk_rcv_saddr),
			   ntohl(sk->sk_daddr),
			   sk->sk_num,
			   ntohs(sk->sk_dport)));
		pc->pc_state |= MARKING_PKT_SENT;
		return 0;
	}

	/* Do not queue excessively in qDisc etc.*/
	if (enough_data_committed(sk, tp)) {
		return 1;
	}

	if (pc->round_sent >= (pc->M>>M_SHIFT)) {
		return 1;
	}

	/* TODO: Use TCP slow start as fallback?
	 * In the earlier versions of Paced Chirping we assumed that the application
	 * was sending data at a rate fast enough to not make the sending of the chirp stall.
	 * I (Joakim) am not sure if this is needed. */
	if (!enough_data_for_chirp(sk, tp, N))  {
		return 0;
	}

	if (!(new_chirp = cached_chirp_malloc(pc))) {
		trace_printk("port=%hu,ERROR_MALLOC\n",
			     tp->inet_conn.icsk_bind_hash->port);
		return 0;
	}
        /* A chirp consists of N packets sent with decreasing inter-packet time (increasing rate).
	 *
	 * Gap between packet i-1 and i is initial_gap_ns - gap_step_ns * i, where i >= 2 (second packet)
	 *
	 * initial_gap_ns is the inter-packet time between the first and second packet
	 * It is set to the average gap in the chirp times the geometry. Geometry is in the range (1.0, 3.0]
	 *
	 * gap_step_ns is the magnitude of the negative slope of the inter-packet times
	 *                   target average gap * (geometry - 1) * 2
	 * gap_step_ns =     ----------------------------------------
	 *                                      N
	 * This calculation makes the actual average gap slightly higher than the target average gap.
	 *
	 *
	 * guard_interval_ns is the time in-between chirps needed to spread the chirps evenly across the measured SRTT.
	 * We try to keep M chirp in flight each round. The code handles overflow in subtraction.
	 *
	 * guard_interval_ns = MAX( SRTT/M - chirp length , target average gap )
	 *
	 *
	 * The chirp length is the total sum of the gaps between the packets in a chirp.
	 * Denote initial gap by a, and step by s.
	 * |pkt| -------- |pkt| ------- |pkt| ------ |pkt| ----- |pkt| ----- |pkt| ...
	 *          a            (a-s)        (a-2s)       (a-3s)      (a-4s)      ...
	 *
	 * The sum is a + (a-s) + (a-2s) + ... + (a-(N-2)s)
	 *            = (N-1) * a - (1 + 2 + ... + (N-2)) * s
	 *            = (N-1) * a - s * (N-2)*(N-1)/2
	 */
	gap_step_ns = switch_divide((((pc->geometry - (1<<G_G_SHIFT))<<1))*pc->gap_avg_ns , N, 1U) >> G_G_SHIFT;
	initial_gap_ns = (pc->gap_avg_ns * pc->geometry)>>G_G_SHIFT;
	chirp_length_ns = (N-1) * initial_gap_ns - gap_step_ns * (((N-2)*(N-1))>>1);
	guard_interval_ns = switch_divide((tp->srtt_us>>3), (pc->M>>M_SHIFT), 0) << 10;
	guard_interval_ns = (guard_interval_ns > chirp_length_ns) ? max(pc->gap_avg_ns, guard_interval_ns - chirp_length_ns): pc->gap_avg_ns;

	/* Provide the kernel with the pacing information */
	tp->chirp.packets = new_chirp->N = N;
	tp->chirp.gap_ns = initial_gap_ns;
	tp->chirp.gap_step_ns = gap_step_ns;
	tp->chirp.guard_interval_ns = guard_interval_ns;
	tp->chirp.scheduled_gaps = new_chirp->scheduled_gaps;
	tp->chirp.packets_out = 0;

	/* Save needed info */
	new_chirp->chirp_number = pc->chirp_number++;
	new_chirp->end_seq = new_chirp->begin_seq = tp->snd_nxt;
	new_chirp->qdelay_index = 0;
	new_chirp->fully_sent = 0;
	new_chirp->ack_cnt = 0;

	pc->round_sent += 1;
	/* >>10 approx /1000 */
	pc->round_length_us += (pc->gap_avg_ns>>10) + (chirp_length_ns>>10);

	list_add_tail(&(new_chirp->list), &(pc->chirp_list->list));
	tp->snd_cwnd += N;
	

	LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,INFO:sched_chirp=%d,avg=%d,guard=%d,N=%u,length_us=%u,round_length=%u\n",
		   ntohl(sk->sk_rcv_saddr),
		   ntohl(sk->sk_daddr),
		   sk->sk_num,
		   ntohs(sk->sk_dport),
		   new_chirp->chirp_number,
		   pc->gap_avg_ns,
		   tp->chirp.guard_interval_ns,
		   N,
		   chirp_length_ns>>10,
		   pc->round_length_us));

	return 0;
}
EXPORT_SYMBOL(paced_chirping_new_chirp);

int check_termination(struct sock *sk, struct tcp_sock *tp, struct paced_chirping *pc)
{
	if (should_terminate(tp, pc)) {
		u32 rate, cwnd;
		/* Prevent division by 0. Should do something safer. */
		pc->gap_avg_ns = max(1U, pc->gap_avg_ns);
		/* Performance-bound during development. */
		pc->gap_avg_ns = min(5000000U, pc->gap_avg_ns);

		rate = gap_to_Bps_ns(sk, tp, pc->gap_avg_ns);
		sk->sk_pacing_rate = rate;

		/* cwnd needed to fill min_rtt at a inter-packet gap of gap_avg_ns.
		 * This makes the algorithm susceptible to under-utilization if
		 * the RTT increases due to e.g. path change. It should be noted that the
		 * termination condition uses srtt. srtt might include a standing queue. */
		cwnd = (u32)(((u64)tcp_min_rtt(tp) * 1000UL)/(u64)pc->gap_avg_ns);
		tp->snd_cwnd = max(max(cwnd, tp->packets_out), 2U);
		tp->snd_ssthresh = tp->snd_cwnd;

		/* Terminate right away. Transition phase is necessary (to ensure filled pipe)
		 * only if pacing is to be turned off as paced chirping exits. For now assume that
		 * pacing is kept on. An other option is to wait for the last chirp to be sent into the network.
		 * This change should improve responsiveness. */
		paced_chirping_exit(sk, pc, EXIT_TRANSITION);

		LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,final_gap=%u,cwnd=%d,rate_Bps=%u,length=%u,srtt=%u,minrtt=%u\n",
			   ntohl(sk->sk_rcv_saddr),
			   ntohl(sk->sk_daddr),
			   sk->sk_num,
			   ntohs(sk->sk_dport),
			   pc->gap_avg_ns, tp->snd_cwnd,rate,
			   pc->round_length_us,
			   tp->srtt_us >> 3,
			   tcp_min_rtt(tp)));
		return 1;
	}
	return 0;
}

void paced_chirping_update(struct sock *sk, struct paced_chirping *pc, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *c = NULL; /* The current chirp. Short name to make code more readable. */
	long rtt_us = rs->rtt_us;
	u32 pkts_acked = rs->acked_sacked;
	int i;
	u32 new_estimate;
	u64 cur_time, diff;
	u32 q_diff, qdelay;

	if (!pc->pc_state || rtt_us <= 0 || pkts_acked == 0)
		return;

	/* Check if Paced Chirping should terminate, and do so if. */
	if (check_termination(sk, tp, pc))
		return;

	if(!(c = get_first_chirp(pc)))
		return;

	/* Inter-arrival times are currently unused. They were used for the two first chirps/bursts
	 * in the first version of the code. Undecided whether to use it or not. */
	cur_time = ktime_to_ns(ktime_get_real());
	diff = cur_time - c->inter_arrival_times[0];
	diff = diff/pkts_acked;

	if (pkts_acked)
		c->ack_cnt++;

	/* This should also works for delayed acks, but need to check for great aggregation. */
	for (i = 0; i < pkts_acked; ++i) {
		if (!c) {
			if (!(c = get_first_chirp(pc)))
				break;
			c->ack_cnt++;
		}
		/* Packet not part of the oldest chirp.
		 * Can be marking packet or packet sent because of
		 * insufficient amount of data for a whole chirp.
		 * There is a potential issue here if a packet sent
		 * right before the start of a chirp is acked with the
		 * first packet of that chirp. It might be counted as part
		 * of the chirp. The fix will probably be to make the sequence check
		 * more robust. */
		if (!before(c->begin_seq, tp->snd_una)) {

			/* If the marking packet is acked with the
			 * first packet of the third chirp, round three
			 * will start in other check below. */
			if ((pc->pc_state & MARKING_PKT_SENT) &&
			    !(pc->pc_state & MARKING_PKT_RECVD) &&
				c->chirp_number == 2) {
				pc->pc_state |= MARKING_PKT_RECVD;
				start_new_round(tp, pc);
			}
			/* TCP Slow start ? */
			//tp->snd_cwnd++;
			LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,INFO:outoforder,RECEIVED_MARK=%d\n",
				   ntohl(sk->sk_rcv_saddr),
				   ntohl(sk->sk_daddr),
				   sk->sk_num,
				   ntohs(sk->sk_dport),
				   pc->pc_state & MARKING_PKT_RECVD));



			continue;
		}

		if (c->chirp_number >= 2U &&
		    c->chirp_number == pc->round_start &&
		    c->qdelay_index == 0) {
			start_new_round(tp, pc);
		}

		qdelay = rtt_us - tcp_min_rtt(tp);

		/* Kept for logging of qdelay */
		if (c->qdelay_index != c->N) {
                       c->inter_arrival_times[c->qdelay_index] = diff;
                       c->inter_arrival_times[0] = cur_time;
                       /* Does not (?) matter if we use minimum rtt for this chirp of for the duration of
                        * the connection because the analysis uses relative queue delay in analysis.
                        * Assumes no reordering or loss. Have to link seq number to array index. */
                       c->qdelay[c->qdelay_index] = qdelay;
		}

		if (c->qdelay_index == 0U) { /* First packet. Currently unused */

			c->uncounted = 0;
			c->in_excursion = 0;
			c->excursion_start = 0;
			c->excursion_len = 0;
			c->max_q = 0;
			c->gap_total = 0;
			c->gap_pending = 0;
			c->pending_count = 0;
			c->valid = 1;

		} else if (c->qdelay_index == 1U) { /* Second packet */

			c->last_delay = qdelay;
			c->last_gap = c->scheduled_gaps[1];

		} else if (c->qdelay_index > 1U && c->valid) { /* All other packets */

			if (c->qdelay_index < c->N &&
			    (c->last_gap<<1) < c->scheduled_gaps[c->qdelay_index]) {
				c->valid = 0;
			}

			c->uncounted++;

			if (!c->in_excursion &&
			    c->last_delay < qdelay &&
			    c->qdelay_index < c->N) {
				c->excursion_start = c->last_delay;
				c->excursion_len = 0;
				c->last_sample = c->last_gap;
				c->max_q = 0;
				c->in_excursion = 1;
			}

			if (c->in_excursion) {

				q_diff = c->last_delay - c->excursion_start;

				if (q_diff >= ((c->max_q>>1) + (c->max_q>>3))) {
					c->max_q = c->max_q > q_diff ? c->max_q:q_diff;
					c->excursion_len++;

					if (c->qdelay_index != c->N &&
					    c->last_delay < qdelay) {
						c->gap_pending += c->last_gap;
						c->pending_count++;
					}
				} else {
					if (c->excursion_len >= paced_chirping_L) {
						c->gap_total += c->gap_pending;
						c->uncounted -= c->pending_count;
					}
					c->gap_pending = 0;
					c->pending_count = 0;
					c->in_excursion = 0;

					if (!c->in_excursion &&
					    c->last_delay < qdelay &&
					    c->qdelay_index < c->N) {
						c->excursion_start = c->last_delay;
						c->excursion_len = 1;
						c->last_sample = c->last_gap;
						c->max_q = 0;
						c->in_excursion = 1;
						c->gap_pending = c->last_gap;
						c->pending_count = 1;
					}
				}
			}

			if (c->qdelay_index != c->N) {
				c->last_delay = qdelay;
				c->last_gap = c->scheduled_gaps[c->qdelay_index];
			}
		}

		if (c->qdelay_index == c->N) {
			/* For debugging */
			print_u64_array((u64*)c->scheduled_gaps, c->N, "gaps", sk);
			print_u32_array(c->qdelay, c->N, "queue", sk);
			print_u64_array(c->inter_arrival_times, c->N, "interarr", sk);
			
			if (c->in_excursion)
				c->last_sample = c->last_gap;

			c->gap_total += c->uncounted * c->last_sample;
			new_estimate = c->gap_total / (c->N - 1);

			update_gap_avg(tp, pc,
				       c->valid ? new_estimate : INVALID_CHIRP,
				       c->chirp_number);

			LOG_PRINT((KERN_INFO "[PC] %u-%u-%hu-%hu,chirp_num=%u,estimate=%u,new_avg=%u,pkts_out=%u,nxt_chirp=%u,min_rtt=%u,ack_cnt=%u\n",
				   ntohl(sk->sk_rcv_saddr),
				   ntohl(sk->sk_daddr),
				   sk->sk_num,
				   ntohs(sk->sk_dport),
				   c->chirp_number,
				   new_estimate,
				   pc->gap_avg_ns,
				   tp->packets_out,
				   pc->chirp_number,
				   tcp_min_rtt(tp),
				   c->ack_cnt));
			
			/* Second round starts when the first chirp has been analyzed. */
			if (c->chirp_number == 0U) {
				start_new_round(tp, pc);
			}
			list_del(&(c->list));
			cached_chirp_dealloc(c);
			c = NULL;
		}

		c->qdelay_index++;
	}
}
EXPORT_SYMBOL(paced_chirping_update);


/* Must be called in init */
void paced_chirping_init(struct sock *sk, struct tcp_sock *tp,
				struct paced_chirping *pc)
{
	int i;
	pc->chirp_list = kmalloc(sizeof(*pc->chirp_list), GFP_KERNEL);
	if (!pc->chirp_list) {
		return;
	}
	INIT_LIST_HEAD(&(pc->chirp_list->list));

	pc->memory_cache = NULL;
	pc->cache_index = 0;
	if (MEMORY_CACHE_SIZE_CHIRPS) {
		pc->memory_cache = kmalloc(MEMORY_CACHE_SIZE_BYTES, GFP_KERNEL);
		if (pc->memory_cache) {
			for (i = 0; i < MEMORY_CACHE_SIZE_CHIRPS; ++i)
				pc->memory_cache[i].mem_flag = MEM_UNALLOC;
			pc->memory_cache[MEMORY_CACHE_SIZE_CHIRPS-1].mem_flag |= MEM_LAST;
		}
	}

	/* Alter kernel behaviour*/
	sk->sk_pacing_rate = ~0U; /*This disables pacing until I explicitly set it.*/
	//sk_pacing_shift_update(sk, 5); /* Not sure if this is needed. Idea was to prevent excessive buffering. */
	tp->disable_kernel_pacing_calculation = 1;
	tp->disable_cwr_upon_ece = 1;
	tp->is_chirping = 1;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	pc->gap_avg_ns = INITIAL_GAP_AVG;
	pc->chirp_number = 0;
	pc->round_start = 0;
	pc->round_sent = 0;
	pc->round_length_us = 0;

	pc->M = (2<<M_SHIFT);
	pc->gain = max(paced_chirping_initial_gain, 1U << G_G_SHIFT);
	pc->geometry = min(max(paced_chirping_initial_geometry, 1U << G_G_SHIFT), 3U << G_G_SHIFT);

	pc->pc_state = STATE_ACTIVE;
}
EXPORT_SYMBOL(paced_chirping_init);

static u32 gap_to_Bps_ns(struct sock *sk, struct tcp_sock *tp, u32 gap_ns)
{
	u64 rate;
	if (!gap_ns) return 0;
	rate = tp->mss_cache;
	rate *= NSEC_PER_SEC;
	do_div(rate, gap_ns);
	return (u32)rate;
}

static uint32_t switch_divide(uint32_t value, uint32_t by, u8 round_up)
{
	switch(by) {
	case 1:
		return value;
	case 2:
		return value >> 1;
	case 4:
		return value >> 2;
	case 8:
		return value >> 3;
	case 16:
		return value >> 4;
	case 32:
		return value >> 5;
	case 0:
		trace_printk("Divide by zero!\n");
		return value;
	}
	if (round_up) {
		return DIV_ROUND_UP(value, by);
	} else {
		return value/by;
	}
}


static struct cc_chirp* cached_chirp_malloc(struct paced_chirping *pc)
{
	struct cc_chirp* ptr;

	if (pc->memory_cache) {
		ptr = pc->memory_cache + pc->cache_index;
		if (ptr->mem_flag & MEM_UNALLOC) {
			ptr->mem_flag |= MEM_CACHE;
			ptr->mem_flag &= ~MEM_UNALLOC;
			pc->cache_index++;
		        if ( ptr->mem_flag & MEM_LAST )
				pc->cache_index = 0;
			return ptr;
		}
	}

	ptr = kmalloc(sizeof(struct cc_chirp), GFP_KERNEL);
	ptr->mem_flag = MEM_ALLOC;
	return ptr;
}

static void cached_chirp_dealloc(struct cc_chirp *chirp)
{
	if (!chirp)
		return;
	if (chirp->mem_flag & MEM_CACHE) {
		chirp->mem_flag |= MEM_UNALLOC;
	} else if (chirp->mem_flag & MEM_ALLOC) {
		kfree(chirp);
	}
}







static void print_u32_array(u32 *array, u32 size, char *name, struct sock *sk)
{
	char buf[1000];
	char *ptr = buf;
	int i;
	
	//ptr += snprintf(ptr, 1000, "port=%hu,%s:", tp->inet_conn.icsk_bind_hash->port, name);
	ptr += snprintf(ptr, 1000, "%u-%u-%hu-%hu,%s:",
			ntohl(sk->sk_rcv_saddr),
			ntohl(sk->sk_daddr),
			sk->sk_num,
			ntohs(sk->sk_dport),
			name);

	for (i = 0; i < size; ++i) {
		if (!ptr)
			continue;

		ptr += snprintf(ptr, 15, "%u,", array[i]); 
	}
	LOG_PRINT((KERN_INFO "[PC] %s\n", buf));
}
static void print_u64_array(u64 *array, u32 size, char *name, struct sock *sk)
{
	char buf[1000];
	char *ptr = buf;
	int i;
	
	//ptr += snprintf(ptr, 1000, "port=%hu,%s:", tp->inet_conn.icsk_bind_hash->port, name);
	ptr += snprintf(ptr, 1000, "%u-%u-%hu-%hu,%s:",
			ntohl(sk->sk_rcv_saddr),
			ntohl(sk->sk_daddr),
			sk->sk_num,
			ntohs(sk->sk_dport),
			name);

	for (i = 0; i < size; ++i) {
		if (!ptr)
			continue;

		ptr += snprintf(ptr, 30, "%llu,", array[i]); 
	}
	LOG_PRINT((KERN_INFO "[PC] %s\n", buf));
}
