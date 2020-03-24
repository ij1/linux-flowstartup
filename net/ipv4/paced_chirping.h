#ifndef _TCP_PACED_CHIRPING_H
#define _TCP_PACED_CHIRPING_H

#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/module.h>

/* Paced Chirping defines
 * All of these defined should probably be made surely unique */

#define STATE_ACTIVE 0x10
#define MARKING_PKT_SENT 0x40
#define MARKING_PKT_RECVD 0x80

#define INVALID_CHIRP UINT_MAX    /* Used to ignore information from a chirp,
				   * e.g if ack aggregation is too great */

#define GAP_AVG_SHIFT 1           /* Average gap shift */
#define M_SHIFT 4                 /* M shift to allow for fractional values */
#define G_G_SHIFT 10              /* Gain and geometry shift */
#define CHIRP_SIZE 16U

#define INITIAL_GAP_AVG	200000U		/* 200 usecs */

/* Used for logging/debugging */
#define EXIT_BOGUS 0
#define EXIT_LOSS 1
#define EXIT_TRANSITION 2

/* Debugging */
#define PC_DEBUG 0
#define PC_LOG 1
#define LOG_PRINT(x) do { if (PC_LOG) printk x; if (PC_DEBUG) trace_printk x;} while (0)

/* Memory cache */
#define MEMORY_CACHE_SIZE_CHIRPS 10U
#define MEMORY_CACHE_SIZE_BYTES (sizeof(struct cc_chirp) * MEMORY_CACHE_SIZE_CHIRPS)
#define MEM_UNALLOC 0x01
#define MEM_CACHE 0x02
#define MEM_ALLOC 0x04
#define MEM_LAST 0x10

struct cc_chirp {
	struct list_head list;
	u8 mem_flag;

	u16 chirp_number; /* Chirp number, first chirp has number 0 */
	u16 N;            /* The number of packets/segments in this chirp */
	u16 qdelay_index; /* Used to record the measured queue delays */
	u16 ack_cnt;      /* The number of acks received. ack_cnt <= N*/

	u32 begin_seq;    /* Sequence number of first segment in chirp */
	u32 end_seq;      /* Sequence number of first segment after last segment in the chirp */
	u32 fully_sent;   /* The chirp has been fully sent and the kernel has requested a new chirp.
			   * This can probably be removed and replaced by a check for end_seq != 0. */

	u32 qdelay[CHIRP_SIZE];              /* Queue delay experienced by each of the packets*/
	u64 scheduled_gaps[CHIRP_SIZE];      /* Inter send times recorded by the kernel.
					      * Index 0 is (I think) unused. */
	u64 inter_arrival_times[CHIRP_SIZE]; /* Inter-arrival times of the acks. The first entry, index 0,
					      * is unusable/invalid. */

	/* These can be placed somewhere else because they are used for at most one chirp at a time */
	char uncounted;
	char in_excursion;
	u32 excursion_start;
	char excursion_len;
	u32 max_q;

	u32 last_delay;
	u64 last_gap;
	u32 last_sample;

	u64 gap_total;
	u64 gap_pending;
	char pending_count;

	char valid;
};

struct paced_chirping {
	u8 pc_state;
	struct cc_chirp *chirp_list;

	u32 gap_avg_ns;      /* Average gap (estimate). Chirps are sent out with a average gap of this value. */
	u32 round_length_us; /* Used for termination condition. It is an approximate calculation of how much
			      * time all the chirps in the current round take up */
	u32 chirp_number;    /* The next chirp number */
	u32 M;               /* Maximum number of chirps in current round */
	u32 round_start;     /* Chirp number of the first chirp in the round*/
	u32 round_sent;      /* Number of chirps sent in the round */
	u16 gain;            /* How much M is increased in-between rounds. M *= gain */
	u16 geometry;        /* Controls the range of the gaps within each chirp  */

	/* Memory caching
	 * Experimenting with allocating memory for the cc_chirp structures at the start of the flow to
	 * reduce overhead. */
	u16 cache_index;
	struct cc_chirp *memory_cache;
};


/*Paced Chirping parameters*/
static unsigned int paced_chirping_enabled __read_mostly = 0;
module_param(paced_chirping_enabled, uint, 0644);
MODULE_PARM_DESC(paced_chirping_enabled, "Enable paced chirping (Default: 0)");

static unsigned int paced_chirping_initial_gain __read_mostly = 2<<G_G_SHIFT; /* gain shifted */
module_param(paced_chirping_initial_gain, uint, 0644);
MODULE_PARM_DESC(paced_chirping_initial_gain, "Initial gain for paced chirping");

static unsigned int paced_chirping_initial_geometry __read_mostly = 2<<G_G_SHIFT; /* geometry shifted */
module_param(paced_chirping_initial_geometry, uint, 0644);
MODULE_PARM_DESC(paced_chirping_initial_geometry, "Initial geometry for paced chirping");

static unsigned int paced_chirping_L __read_mostly = 5;
module_param(paced_chirping_L, uint, 0644);
MODULE_PARM_DESC(paced_chirping_L, "Number of packets that make up an excursion");

/*************** Public functions ****************/
/* TCP CC modules must implement new_chirp and release.
 * Additionally either 1 or 2:
 * 1) cong_avoid
 * 2) pkts_acked
 * When either of these functions are called paced_chirping_update must be called.
 * It might be useful to have two version of paced_chirping_update, one for both.
 * Currently pkts_acked implementations have to create a "fake" rate_sample.
 *
 * When new_chirp is called paced_chirping_new_chirp must be called.
 * When release is called paced_chirping_release must be called.
 *
 * paced_chirping_exit should be called upon loss.
 *
 * TCP CC module should not modify cwnd and ssthresh when Paced Chirping is active.
 *
 * paced_chirping_exit should be called upon LOSS
 */

void paced_chirping_init(struct sock *sk, struct tcp_sock *tp, struct paced_chirping *pc);
u32  paced_chirping_new_chirp (struct sock *sk, struct paced_chirping *pc);
void paced_chirping_update(struct sock *sk, struct paced_chirping *pc, const struct rate_sample *rs);
int  paced_chirping_active(struct paced_chirping *pc);
void paced_chirping_exit(struct sock *sk, struct paced_chirping *pc, u32 reason);
void paced_chirping_release(struct paced_chirping* pc);

#endif
