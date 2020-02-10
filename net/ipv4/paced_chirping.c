/* DataCenter TCP (DCTCP) congestion control.
 *
 * http://simula.stanford.edu/~alizade/Site/DCTCP.html
 *
 * This is an implementation of DCTCP over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. DCTCP
 * leverages Explicit Congestion Notification (ECN) in the network to
 * provide multi-bit feedback to the end hosts. DCTCP's goal is to meet
 * the following three data center transport requirements:
 *
 *  - High burst tolerance (incast due to partition/aggregate)
 *  - Low latency (short flows, queries)
 *  - High throughput (continuous data updates, large file transfers)
 *    with commodity shallow buffered switches
 *
 * The algorithm is described in detail in the following two papers:
 *
 * 1) Mohammad Alizadeh, Albert Greenberg, David A. Maltz, Jitendra Padhye,
 *    Parveen Patel, Balaji Prabhakar, Sudipta Sengupta, and Murari Sridharan:
 *      "Data Center TCP (DCTCP)", Data Center Networks session
 *      Proc. ACM SIGCOMM, New Delhi, 2010.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp-final.pdf
 *
 * 2) Mohammad Alizadeh, Adel Javanmard, and Balaji Prabhakar:
 *      "Analysis of DCTCP: Stability, Convergence, and Fairness"
 *      Proc. ACM SIGMETRICS, San Jose, 2011.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp_analysis-full.pdf
 *
 * Initial prototype from Abdul Kabbani, Masato Yasuda and Mohammad Alizadeh.
 *
 * Authors:
 *
 *	Daniel Borkmann <dborkman@redhat.com>
 *	Florian Westphal <fw@strlen.de>
 *	Glenn Judd <glenn.judd@morganstanley.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

/* Paced Chirping start-up extension can be enabled by setting sysctl dctcp_pc_enabled to 1.
 * Paced chirping is described in https://riteproject.files.wordpress.com/2018/07/misundjoakimmastersthesissubmitted180515.pdf
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_dctcp.h"

#define DCTCP_MAX_ALPHA	1024U

/* Paced Chirping */
#define INVALID_CHIRP UINT_MAX
#define STATE_TRANSITION 0x20
#define STATE_ACTIVE 0x10
#define MARKING_PKT_SENT 0x40
#define MARKING_PKT_RECVD 0x80
#define GAP_AVG_SHIFT 1           /* Average gap shift */
#define M_SHIFT 4                 /* M is the number of chirps in the current round */
#define G_G_SHIFT 10              /* Gain and geometry shift */
#define CHIRP_SIZE 16U

#define EXIT_BOGUS 0
#define EXIT_LOSS 1
#define EXIT_TRANSITION 2

struct cc_chirp {
	struct list_head list;
	u8 mem_flag;

	u16 chirp_number;
	u16 N;
	u16 qdelay_index;
	u16 ack_cnt;

	u32 begin_seq; //seq of first segment in chirp
	u32 end_seq; //seq of first segment after last packet in chirp
	u32 fully_sent;

	u32 qdelay[CHIRP_SIZE];
	u64 scheduled_gaps[CHIRP_SIZE];
};

#define MEMORY_CACHE_SIZE_CHIRPS 10U
#define MEMORY_CACHE_SIZE_BYTES (sizeof(struct cc_chirp) * MEMORY_CACHE_SIZE_CHIRPS)

#define MEM_UNALLOC 0x01
#define MEM_CACHE 0x02
#define MEM_ALLOC 0x04
#define MEM_LAST 0x10

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 loss_cwnd;

	struct chirp chirp;

	/* Paced Chirping vars */
	u8 pc_state;
	struct cc_chirp *chirp_list;

	u32 gap_avg_ns;      /* Average gap (estimate) */
	u32 round_length_us; /* Used for termination condition */
	u32 chirp_number;
	u32 M;               /* Maximum number of chirps in a round */
	u32 round_start;     /* Chirp number of the first chirp in the round */
	u32 round_sent;      /* Number of chirps sent in the round */
	u16 gain;            /* Increase of number of chirps */
	u16 geometry;        /* Range to probe for */

	/* Memory caching */
	u16 cache_index;
	struct cc_chirp *memory_cache;
};

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = 0;//DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

/* TODO This value has to be changed */
/* Paced Chirping parameters */
static unsigned int dctcp_pc_enabled __read_mostly = 1;
module_param(dctcp_pc_enabled, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_enabled, "Enable paced chirping (Default: 0)");

static unsigned int dctcp_pc_initial_gain __read_mostly = 2<<G_G_SHIFT; /* gain shifted */
module_param(dctcp_pc_initial_gain, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_gain, "Initial gain for paced chirping");

static unsigned int dctcp_pc_initial_geometry __read_mostly = 2<<G_G_SHIFT; /* geometry shifted */
module_param(dctcp_pc_initial_geometry, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_initial_geometry, "Initial geometry for paced chirping");

static unsigned int dctcp_pc_L __read_mostly = 5;
module_param(dctcp_pc_L, uint, 0644);
MODULE_PARM_DESC(dctcp_pc_L, "Number of packets that make up an excursion");

/* TODO: Figure out of the sensitivity in the analysis can be a parameter */

static struct tcp_congestion_ops dctcp_reno;

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

static struct cc_chirp* cached_chirp_malloc(struct tcp_sock *tp, struct dctcp *ca)
{
	struct cc_chirp* ptr;

	if (ca->memory_cache) {
		ptr = ca->memory_cache + ca->cache_index;
		if (ptr->mem_flag & MEM_UNALLOC) {
			ptr->mem_flag |= MEM_CACHE;
			ptr->mem_flag &= ~MEM_UNALLOC;
			ca->cache_index++;
		        if ( ptr->mem_flag & MEM_LAST )
				ca->cache_index = 0;
			return ptr;
		}
	}

	ptr = kmalloc(sizeof(struct cc_chirp), GFP_KERNEL);
	ptr->mem_flag = MEM_ALLOC;
	return ptr;
}

static void cached_chirp_dealloc(struct tcp_sock *tp, struct cc_chirp *chirp)
{
	if (!chirp)
		return;
	if (chirp->mem_flag & MEM_CACHE) {
		chirp->mem_flag |= MEM_UNALLOC;
	} else if (chirp->mem_flag & MEM_ALLOC) {
		kfree(chirp);
	}
}

static u32 gap_ns_to_rate(struct sock *sk, struct tcp_sock *tp, u32 gap_ns)
{
	u64 rate;
	if (!gap_ns)
		return 0;
	rate = tp->mss_cache;
	rate *= NSEC_PER_SEC;
	do_div(rate, gap_ns);
	return (u32)rate;
}


static void exit_paced_chirping(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if (ca->pc_state) {
		tp->snd_cwnd = max(tp->packets_out, 2U);
		tp->snd_ssthresh = tp->snd_cwnd;
	}
	tp->chirp = NULL;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
	sk->sk_pacing_rate = ~0U;
	ca->pc_state = 0;
}

static inline void start_new_round(struct tcp_sock *tp, struct dctcp *ca)
{
	if (ca->chirp_number >= 6 && ca->round_sent >= (ca->M>>M_SHIFT)) /* Next chirp to be sent */
		ca->M = (ca->M * ca->gain)>>G_G_SHIFT;

	ca->round_start = ca->chirp_number;
	ca->round_sent = ca->round_length_us = 0;
}
static u32 should_terminate(struct tcp_sock *tp, struct dctcp *ca)
{
	return tp->srtt_us && ((tp->srtt_us>>3) <= ca->round_length_us);
}
static struct cc_chirp* get_first_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || list_empty(&(ca->chirp_list->list)))
		return NULL;
	return list_first_entry(&(ca->chirp_list->list), struct cc_chirp, list);
}
static struct cc_chirp* get_last_chirp(struct dctcp *ca)
{
	if (!ca->chirp_list || list_empty(&(ca->chirp_list->list)))
		return NULL;
	return list_last_entry(&(ca->chirp_list->list), struct cc_chirp, list);
}

static void update_gap_avg(struct tcp_sock *tp, struct dctcp *ca, u32 new_estimate_ns)
{
	u32 prev_estimate_ns = ca->gap_avg_ns;

	if (new_estimate_ns == INVALID_CHIRP) {
		return;
	}
	/* Safety bound for development min 30us, max 10ms (400Mbps ~ 1Mbps)*/
	new_estimate_ns = max(min(new_estimate_ns, 10000000U), 30000U);

	if (ca->gap_avg_ns == 0U) {
		ca->gap_avg_ns = new_estimate_ns;
		return;
	}
	ca->gap_avg_ns = prev_estimate_ns -
		(prev_estimate_ns>>GAP_AVG_SHIFT) +
		(new_estimate_ns>>GAP_AVG_SHIFT);
}

static bool enough_data_for_chirp (struct sock *sk, struct tcp_sock *tp, int N)
{
	return SKB_TRUESIZE(tp->mss_cache) * (N + tp->packets_out) <= sk->sk_wmem_queued;
}
static bool enough_data_committed(struct sock *sk, struct tcp_sock *tp)
{
	return SKB_TRUESIZE(tp->mss_cache) * CHIRP_SIZE  < refcount_read(&sk->sk_wmem_alloc);
}

static u32 dctcp_new_chirp (struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	struct cc_chirp *new_chirp;
	struct cc_chirp *last_chirp;
	struct cc_chirp *cur_chirp;
	u32 N = CHIRP_SIZE;
	u32 guard_interval_ns;
	u32 gap_step_ns;
	u32 initial_gap_ns;
	u32 chirp_length_ns;

	if ((tp->chirp == NULL) || !ca->chirp_list ||
	    ca->pc_state & STATE_TRANSITION || !(ca->pc_state & STATE_ACTIVE))
		return 1;

	/* Save information */
	if ((last_chirp = get_last_chirp(ca))) {
		if (!last_chirp->fully_sent) {
			last_chirp->begin_seq = ca->chirp.begin_seq;
			last_chirp->end_seq = ca->chirp.end_seq;
			last_chirp->fully_sent = 1;
		}
	}

	if (ca->chirp_number <= 1)
		N = 5;
	else if (ca->chirp_number <= 3)
		N = 8;

	/* Send marking packet */
	if (!(ca->pc_state & MARKING_PKT_SENT) && /* Not sent already */
	    (cur_chirp = get_first_chirp(ca)) &&
	    cur_chirp->chirp_number == 0 && cur_chirp->qdelay_index > 0) /* Ack(s) of first chirp have been received */
	{
		ca->pc_state |= MARKING_PKT_SENT;
		return 0;
	}

	/* Do not queue excessively in qDisc etc */
	if (enough_data_committed(sk, tp))
		return 1;

	if (ca->round_sent >= (ca->M>>M_SHIFT))
		return 1;

	/* TODO: Use TCP slow start as fallback */
	/* Better to mark chirp as possible */
	if (ca->chirp_number == 0 && !enough_data_for_chirp(sk, tp, N))
		return 0;

	if (!(new_chirp = cached_chirp_malloc(tp, ca)))
		return 0;

	gap_step_ns = switch_divide((((ca->geometry - (1<<G_G_SHIFT))<<1))*ca->gap_avg_ns , N, 1U) >> G_G_SHIFT;
	initial_gap_ns = (ca->gap_avg_ns * ca->geometry)>>G_G_SHIFT;
	chirp_length_ns = initial_gap_ns + (((N-2) * ((initial_gap_ns<<1) - N*gap_step_ns + gap_step_ns))>>1);
	guard_interval_ns = switch_divide((tp->srtt_us>>3), (ca->M>>M_SHIFT), 0) << 10;
	guard_interval_ns = (guard_interval_ns > chirp_length_ns) ? max(ca->gap_avg_ns, guard_interval_ns - chirp_length_ns): ca->gap_avg_ns;

	/* Provide the kernel with the pacing information */
	ca->chirp.packets = new_chirp->N = N;
	ca->chirp.gap_ns = initial_gap_ns;
	ca->chirp.gap_step_ns = gap_step_ns;
	ca->chirp.guard_interval_ns = guard_interval_ns;
	ca->chirp.scheduled_gaps = new_chirp->scheduled_gaps;
	ca->chirp.packets_out = 0;

	/* Save needed info */
	new_chirp->chirp_number = ca->chirp_number++;
	new_chirp->end_seq = new_chirp->begin_seq = tp->snd_nxt;
	new_chirp->qdelay_index = 0;
	new_chirp->fully_sent = 0;
	new_chirp->ack_cnt = 0;

	ca->round_sent += 1;
	ca->round_length_us += chirp_length_ns>>10;

	list_add_tail(&(new_chirp->list), &(ca->chirp_list->list));
	tp->snd_cwnd += N;

	return 0;
}




static void dctcp_release(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *chirp;
	if (ca->chirp_list) {
		while ((chirp = get_first_chirp(ca))) {
			list_del(&(chirp->list));
			cached_chirp_dealloc(tp, chirp);
		}
		kfree(ca->chirp_list);
	}
	if (ca->memory_cache)
		kfree(ca->memory_cache);
}

static u32 analyze_chirp(struct sock *sk, struct cc_chirp *chirp)
{
	u32 N = chirp->qdelay_index;
	int i, j;
	int last_sample = N - 1;
	u64 gap_avg = 0;
	u32 *qdelay = chirp->qdelay;
	ktime_t *s;
	s32 max_q = 0;
	u32 start = 0, cnt = 0;	/* Excursion start index & len */
	u32 E[CHIRP_SIZE];

	s = chirp->scheduled_gaps;

	if (N < 2)
		return INVALID_CHIRP;
	if (chirp->ack_cnt < N>>1) /* Ack aggregation is too great */
		return INVALID_CHIRP;

	for (i = 1; i < N; ++i) {
		if ((i < N - 1) && ((s[i] << 1) < s[i+1]))
			return INVALID_CHIRP;
		E[i] = 0;
		if (cnt) {
			/* Excursion continues? */
			s32 q_diff = (s32)(qdelay[i] - qdelay[start]);
			if (q_diff > (max_q >> 1) + (max_q >> 3)) {
				max_q = max(max_q, q_diff);
				cnt++;
			} else {
				/* Excursion has ended or never started */
				if (cnt >= dctcp_pc_L)
					for (j = start; j < start + cnt; ++j)
						if (qdelay[j] < qdelay[j + 1])
							E[j] = s[j];

				cnt = start = max_q = 0;
			}
		}

		/* Start new excursion */
		if (!cnt && (i < N - 1) && (qdelay[i] < qdelay[i + 1])) {
			start = i;
			max_q = 0;
			cnt = 1;
		}
	}

	/* Unterminated excursion */
	if (cnt && cnt + start == N) {
		for (j = start; j < start + cnt; ++j)
			E[j] = s[start];
		last_sample = start;
	}

	/* Calculate the average gap */
	for (i = 1; i < N; ++i) {
		if (E[i] == 0)
			gap_avg += s[last_sample];
		else
			gap_avg += E[i];
	}

	gap_avg = gap_avg / (N - 1);
	if (gap_avg > U32_MAX)
		gap_avg = INVALID_CHIRP;
	return gap_avg;
}

static void dctcp_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cc_chirp *cur_chirp = NULL;
	u32 rtt_us = sample->rtt_us;
	int i;
	u32 new_estimate;

	if (!ca->pc_state || rtt_us == 0 || sample->pkts_acked == 0)
		return;

	/* We have terminated, but are waiting for scheduled packet to be sent */
	if (ca->pc_state & STATE_TRANSITION) {
		if ((ca->round_sent++ > (ca->round_start)))
			exit_paced_chirping(sk);
		return;
	}
	if ((cur_chirp = get_first_chirp(ca)) == NULL)
		return;

	if (sample->pkts_acked)
		cur_chirp->ack_cnt++;

	for (i = 0; i < sample->pkts_acked; ++i) {
		if (!cur_chirp) {
			if (!(cur_chirp = get_first_chirp(ca)))
				break;
			cur_chirp->ack_cnt++;
		}
		if (!before(cur_chirp->begin_seq, tp->snd_una)) {
			u32 mark = 0;
			if ((ca->pc_state & MARKING_PKT_SENT) &&
			    !(ca->pc_state & MARKING_PKT_RECVD) &&
				cur_chirp->chirp_number == 2) {
				ca->pc_state |= MARKING_PKT_RECVD;
				start_new_round(tp, ca);
				mark = 1;
			}
			continue;
		}

		if (cur_chirp->chirp_number >= 2U && cur_chirp->chirp_number == ca->round_start
		    && cur_chirp->qdelay_index == 0) {
			start_new_round(tp, ca);
		}

		if (cur_chirp->qdelay_index != cur_chirp->N) {
			/* Does not matter if we use minimum rtt for this chirp of for the duration of
			 * the connection because the analysis uses relative queue delay in analysis.
			 * Assumes no reordering or loss. Have to link seq number to array index. */
			cur_chirp->qdelay[cur_chirp->qdelay_index++] = rtt_us - tcp_min_rtt(tp);
		}

		/* Chirp is completed */
		if (cur_chirp->qdelay_index >= cur_chirp->N &&
		    (cur_chirp->fully_sent && !after(cur_chirp->end_seq, tp->snd_una))) {
			new_estimate = analyze_chirp(sk, cur_chirp);
			update_gap_avg(tp, ca, new_estimate);

			/* Second round starts when the first chirp has been analyzed. */
			if (cur_chirp->chirp_number == 0U) {
				start_new_round(tp, ca);
				//ca->pc_state |= (MARKING_PKT_RECVD | MARKING_PKT_SENT);
			}
			list_del(&(cur_chirp->list));
			cached_chirp_dealloc(tp, cur_chirp);
			cur_chirp = NULL;

			if (should_terminate(tp, ca)) {
				u32 rate = gap_ns_to_rate(sk, tp, min(5000000U, ca->gap_avg_ns));
				sk->sk_pacing_rate = rate;

				/* Send for one bdp */
				ca->round_sent = 0;
				ca->round_start = (u32)((u64)(tcp_min_rtt(tp) * 1000U)/max(1U, (u32)ca->gap_avg_ns));
				tp->snd_cwnd = max((u32)(ca->round_start<<1), 10U);

				ca->pc_state |= STATE_TRANSITION;
				tp->chirp = NULL;
			}
		}
	}
}

/* Modification of tcp_reno_cong_avoid */
static void dctcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk) || ca->pc_state)
		return;

	/* In "safe" area, increase. */
	if ((tp->snd_cwnd <= tp->snd_ssthresh)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

static void init_paced_chirping(struct sock *sk, struct tcp_sock *tp,
				struct dctcp *ca)
{
	int i;
	ca->chirp_list = kmalloc(sizeof(*ca->chirp_list), GFP_KERNEL);
	if (!ca->chirp_list) {
		return;
	}
	INIT_LIST_HEAD(&(ca->chirp_list->list));

	ca->memory_cache = NULL;
	ca->cache_index = 0;
	if (MEMORY_CACHE_SIZE_CHIRPS) {
		ca->memory_cache = kmalloc(MEMORY_CACHE_SIZE_BYTES, GFP_KERNEL);
		if (ca->memory_cache) {
			for (i = 0; i < MEMORY_CACHE_SIZE_CHIRPS; ++i)
				ca->memory_cache[i].mem_flag = MEM_UNALLOC;
			ca->memory_cache[MEMORY_CACHE_SIZE_CHIRPS-1].mem_flag |= MEM_LAST;
		}
	}

	sk->sk_pacing_rate = ~0U; /* Disable pacing until explicitly set */
	sk_pacing_shift_update(sk, 5);
	tp->chirp = &(ca->chirp);

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	ca->gap_avg_ns = 200000; /* 200 us */
	ca->chirp_number = 0;
	ca->round_start = 0;
	ca->round_sent = 0;
	ca->round_length_us = 0;

	ca->M = (2<<M_SHIFT);
	ca->gain = max(dctcp_pc_initial_gain, 1U << G_G_SHIFT);
	ca->geometry = min(max(dctcp_pc_initial_geometry, 1U << G_G_SHIFT), 3U << G_G_SHIFT);

	ca->pc_state = STATE_ACTIVE;
}


static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

static void dctcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

		ca->loss_cwnd = 0;
		ca->ce_state = 0;

		ca->pc_state = 0;
		if (dctcp_pc_enabled)
			init_paced_chirping(sk, tp, ca);

		dctcp_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for DCTCP.
	 */
	inet_csk(sk)->icsk_ca_ops = &dctcp_reno;
	INET_ECN_dontxmit(sk);

	ca->pc_state = 0;
	if (dctcp_pc_enabled)
		init_paced_chirping(sk, tp, ca);
}

static u32 dctcp_ssthresh(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

static void dctcp_update_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u32 alpha = ca->dctcp_alpha;

		/* alpha = (1 - g) * alpha + g * F */

		alpha -= min_not_zero(alpha, alpha >> dctcp_shift_g);
		if (bytes_ecn) {
			/* If dctcp_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - dctcp_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, DCTCP_MAX_ALPHA);
		}
		/* dctcp_alpha can be read from dctcp_get_info() without
		 * synchro, so we ask compiler to not use dctcp_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->dctcp_alpha, alpha);
		dctcp_reset(tp, ca);
	}
}

static void dctcp_state(struct sock *sk, u8 new_state)
{
	struct dctcp *ca = inet_csk_ca(sk);

	if (dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	} else if (new_state == TCP_CA_Loss && ca->pc_state)
		exit_paced_chirping(sk);
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
        struct dctcp *ca = inet_csk_ca(sk);
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
	case CA_EVENT_ECN_NO_CE:
	        dctcp_ece_ack_update(sk, ev, &ca->prior_rcv_nxt, &ca->ce_state);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t dctcp_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->dctcp, 0, sizeof(info->dctcp));
		if (inet_csk(sk)->icsk_ca_ops != &dctcp_reno) {
			info->dctcp.dctcp_enabled = 1;
			info->dctcp.dctcp_ce_state = (u16) ca->ce_state;
			info->dctcp.dctcp_alpha = ca->dctcp_alpha;
			info->dctcp.dctcp_ab_ecn = ca->acked_bytes_ecn;
			info->dctcp.dctcp_ab_tot = ca->acked_bytes_total;
		}

		*attr = INET_DIAG_DCTCPINFO;
		return sizeof(info->dctcp);
	}
	return 0;
}

static u32 dctcp_cwnd_undo(struct sock *sk)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static struct tcp_congestion_ops dctcp __read_mostly = {
	.init		= dctcp_init,
	.in_ack_event   = dctcp_update_alpha,
	.cwnd_event	= dctcp_cwnd_event,
	.ssthresh	= dctcp_ssthresh,
	/*.cong_avoid	= tcp_reno_cong_avoid,*/

	.cong_avoid     = dctcp_cong_avoid,
	.release        = dctcp_release,
	.pkts_acked     = dctcp_acked,
	.new_chirp      = dctcp_new_chirp,

	.undo_cwnd	= dctcp_cwnd_undo,
	.set_state	= dctcp_state,
	.get_info	= dctcp_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "chirping",
};

static struct tcp_congestion_ops dctcp_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	//.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,

	.cong_avoid     = dctcp_cong_avoid,
	.release        = dctcp_release,
	.pkts_acked     = dctcp_acked,
	.new_chirp      = dctcp_new_chirp,

	.get_info	= dctcp_get_info,
	.owner		= THIS_MODULE,
	.name		= "dctcp-reno",
};

static int __init dctcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct dctcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&dctcp);
}

static void __exit dctcp_unregister(void)
{
	tcp_unregister_congestion_control(&dctcp);
}

module_init(dctcp_register);
module_exit(dctcp_unregister);

MODULE_AUTHOR("Daniel Borkmann <dborkman@redhat.com>");
MODULE_AUTHOR("Florian Westphal <fw@strlen.de>");
MODULE_AUTHOR("Glenn Judd <glenn.judd@morganstanley.com>");
MODULE_AUTHOR("Joakim Misund <joakimmi@ifi.uio.no>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DataCenter TCP (DCTCP)");
