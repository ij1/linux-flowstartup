#ifndef _TCP_PACED_CHIRPING_H
#define _TCP_PACED_CHIRPING_H

#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/module.h>

/* Paced Chirping */
#define STATE_TRANSITION 0x20     
#define STATE_ACTIVE 0x10
#define MARKING_PKT_SENT 0x40
#define MARKING_PKT_RECVD 0x80

#define INVALID_CHIRP UINT_MAX    /* Used to ignore information from a chirp. e.g if ack aggregation is too great */


#define GAP_AVG_SHIFT 1           /* Average gap shift */
#define M_SHIFT 4                 /* M is the number of chirps in the current round */
#define G_G_SHIFT 10              /* Gain and geometry shift */
#define CHIRP_SIZE 16U

#define EXIT_BOGUS 0
#define EXIT_LOSS 1
#define EXIT_TRANSITION 2

/* Debugging */
#define PC_DEBUG 0
#define PC_LOG 1
#define LOG_PRINT(x) do { if (PC_LOG) printk x; if (PC_DEBUG) trace_printk x;} while (0)

/* Memory cache*/
#define MEMORY_CACHE_SIZE_CHIRPS 10U
#define MEMORY_CACHE_SIZE_BYTES (sizeof(struct cc_chirp) * MEMORY_CACHE_SIZE_CHIRPS)
#define MEM_UNALLOC 0x01
#define MEM_CACHE 0x02
#define MEM_ALLOC 0x04
#define MEM_LAST 0x10

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
	u64 inter_arrival_times[CHIRP_SIZE];
};

struct paced_chirping {
	u8 pc_state;
	struct cc_chirp *chirp_list;

	u32 gap_avg_ns;      /*Average gap (estimate)*/
	u32 round_length_us; /*Used for termination condition*/
	u32 chirp_number;
	u32 M;               /*Maximum number of chirps in a round*/
	u32 round_start;     /*Chirp number of the first chirp in the round*/
	u32 round_sent;      /*Number of chirps sent in the round*/
	u16 gain;            /*Increase of number of chirps*/
	u16 geometry;        /*Range to probe for*/

	/*Memory caching*/
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
