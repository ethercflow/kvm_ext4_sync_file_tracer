#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/journal-head.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/virtio_blk.h>
#include <linux/blk-mq.h>
#include <linux/pagevec.h>

#define DEBUG 1

struct ext4_sync_file_ctx {
	u64 id;
	u64 start_ts;
	u64 end_ts;
	
	u32 maj;
	u32 min;
	unsigned long ino;
	unsigned long parent;
	int datasync;
	
	int sync_mode;
	
	u64 jbd2id;
	char jcomm[TASK_COMM_LEN];
	
	int tag;
	journal_t *journal;
	bool needs_barrier;

	u64 iowaker;
	
	char comm[TASK_COMM_LEN];
};

struct journal_ctx {
	u64 id;
	tid_t tid;
	handle_t *h;
};

struct jbd2_commit_txn_ctx {
	u64 id;
	u64 waker;
	char wcomm[TASK_COMM_LEN];

	u64 iowaker;
	u64 ts;
};

struct kworker_ctx {
	u64 waker;
	char wcomm[TASK_COMM_LEN];

	u64 iowaker;
};

struct rq_ctx {
	u64 id;
};

BPF_HASH(sync_events, u64, struct ext4_sync_file_ctx);
BPF_HASH(journal_instances, u64, journal_t *);
BPF_HASH(journal_start_events, journal_t*, struct journal_ctx);
BPF_HASH(commit_events, u64, struct jbd2_commit_txn_ctx);
BPF_HASH(kworker_events, u64, struct kworker_ctx);
BPF_HASH(rq_events, struct request *, struct rq_ctx);
BPF_HASH(rq_done_events, u64, struct rq_ctx);

static inline bool h_strcmp(char *comm)
{
	char filter[] = "jbd2/";
	for (int i = 0; i < sizeof(filter) - 1; ++i) {
	    if (filter[i] != comm[i])
	        return false;
	}
	return true;
}

TRACEPOINT_PROBE(ext4, ext4_sync_file_enter)
{
	struct ext4_sync_file_ctx esfc = {};
	u64 id = bpf_get_current_pid_tgid();

	esfc.id = id;
	esfc.start_ts = bpf_ktime_get_ns();
	esfc.maj = args->dev >> 20;
	esfc.min = (args->dev) & ((1U << 20) - 1);
	esfc.ino = args->ino;
	esfc.parent = args->parent;
	esfc.datasync = args->datasync;
	esfc.tag = -1;
	bpf_get_current_comm(&esfc.comm, sizeof(esfc.comm));
	
	sync_events.update(&id, &esfc);
#if DEBUG
	bpf_trace_printk("Enter ext4_sync_file\n");
#endif	
	return 0;
}

TRACEPOINT_PROBE(ext4, ext4_writepages)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;
	
	if (pesfc->maj != args->dev >> 20 ||
		pesfc->min != ((args->dev) & ((1U << 20) - 1)) ||
		pesfc->ino != args->ino) {
		bpf_trace_printk("Warning: event inconsistency "
				 "[ext4_writepages]\n");
		sync_events.delete(&id);
		return 0;
	}
	
	pesfc->sync_mode = args->sync_mode;
#if DEBUG
	bpf_trace_printk("Enter ext4_writepages\n");
#endif	
	return 0;
}


// in while
int trace_jbd2__journal_start_entry(struct pt_regs *ctx, journal_t *journal, 
				    int nblocks, int rsv_blocks,
				    gfp_t gfp_mask, unsigned int type,
				    unsigned int line_no)

{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;
	
	journal_instances.update(&id, &journal);
#if DEBUG
	bpf_trace_printk("Start journal: %p\n", journal);
#endif	
	return 0;
}

// in while
int trace_jbd2__journal_start_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct journal_ctx jc = {};
	journal_t **ppj;
	handle_t *handle;								

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;
	ppj = journal_instances.lookup(&id);
	if (!ppj)
		return 0;
	handle = (handle_t *)PT_REGS_RC(ctx);
	if (!handle)
		return 0;

	jc.id = id;
	jc.tid = handle->h_transaction->t_tid;
	jc.h = handle;		

	journal_start_events.update(ppj, &jc);
	journal_instances.delete(&id);
#if DEBUG
	bpf_trace_printk("Return from start journal handle: %p, journal: %p\n",
			 handle, *ppj);
#endif	

end:
	return 0;
}

// in while
TRACEPOINT_PROBE(ext4, ext4_da_write_pages)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;
	if (pesfc->maj != args->dev >> 20 ||
		pesfc->min != ((args->dev) & ((1U << 20) - 1)) ||
		pesfc->ino != args->ino) {
		bpf_trace_printk("Warning: event inconsistency []\n");
		sync_events.delete(&id);
		return 0;
	}
#if DEBUG
	bpf_trace_printk("Enter da_write_pages first_page %lu"
			 " nr_to_write %ld sync_mode %d\n",
			 args->first_page, args->nr_to_write, args->sync_mode);
#endif	
	return 0;
}

// in while
int trace_jbd2_journal_stop(struct pt_regs *ctx, handle_t *handle)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);
	struct journal_ctx *pjc = NULL;
	journal_t *journal = NULL;

	if (!pesfc)
		return 0;

	journal = handle->h_transaction->t_journal;
	pjc = journal_start_events.lookup(&journal);
	if (!pjc)
		return 0;
#if DEBUG
	bpf_trace_printk("Stop journal handle: %p, journal: %p\n",
			 handle, journal);
#endif
	return 0;
}

int trace_default_wake_function(struct pt_regs *ctx, wait_queue_t *curr,
                                      unsigned mode, int wake_flags, void *key)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	struct task_struct *p = curr->private;
	struct jbd2_commit_txn_ctx jctc = {};
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	char comm[TASK_COMM_LEN] = {0};
	struct rq_ctx *prc = NULL;
	u64 jbd2id;
	
	pesfc = sync_events.lookup(&id);
	if (pesfc) {
		if (!h_strcmp(&p->comm[0]))
			return 0;
		jbd2id = (u64) p->tgid << 32 | p->pid;
		pesfc->jbd2id = jbd2id;
		bpf_probe_read_str(&pesfc->jcomm, TASK_COMM_LEN, &p->comm);
		bpf_trace_printk("jcomm: %s\n", &pesfc->jcomm[0]);
		jctc.waker = id;
		jctc.ts = bpf_ktime_get_ns();
		
		commit_events.update(&jbd2id, &jctc);
#if DEBUG
		bpf_trace_printk("Ext4 wake up %s to commit txn\n",
				 &p->comm[0]);
#endif
		return 0;
	}
	prc = rq_done_events.lookup(&id);
	if (!prc) 
		return 0;	
	rq_done_events.delete(&id);
	pesfc = sync_events.lookup(&prc->id);
	if (pesfc) {
#if DEBUG
		bpf_trace_printk("Softirq %u wake up ext4_sync_file thread\n",
				 id, prc->id);
#endif
		return 0;
	}
	pjctc = commit_events.lookup(&prc->id);
	if (pjctc) {
#if DEBUG
		bpf_trace_printk("Softirq %u wake up jbd2 thread\n",
				 id, prc->id);
#endif
		return 0;
	}

	pkc = kworker_events.lookup(&prc->id);
	if (!pkc)
		return 0;
	kworker_events.delete(&prc->id);
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
#if DEBUG
		bpf_trace_printk("Softirq %u wake up kworker, id: %u "
				 "waked up by ext4_sync_file thread\n",
				 id, prc->id, pkc->waker);
#endif
		return 0;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
#if DEBUG
		bpf_trace_printk("Softirq %u wake up kworker, id: %u "
				 "waked up by jbd2 thread\n",
				 id, prc->id, pkc->waker);
#endif
		return 0;
	}

	return 0;
}

int trace_jbd2_journal_commit_transaction(struct pt_regs *ctx,
					  journal_t *journal)
{
	struct journal_ctx *pjc = NULL;

	pjc = journal_start_events.lookup(&journal);
	if (!pjc)
		return 0;	
#if DEBUG
	bpf_trace_printk("JDB2 commit thread journal: %p\n", journal);
#endif
	return 0;		
}

static inline void judge_request_type(struct request *rq, char *str)
{
	if (rq->cmd_flags & REQ_FLUSH) {
#if DEBUG
		bpf_trace_printk("%s: VIRTIO_BLK_T_FLUSH, rq: %p\n", str, rq);
#endif
	} else {
		switch (rq->cmd_type) {
		case REQ_TYPE_FS:
#if DEBUG
			bpf_trace_printk("%s: REQ_TYPE_FS, rq: %p\n", str, rq);
#endif
			break;
		case REQ_TYPE_BLOCK_PC:
#if DEBUG
			bpf_trace_printk("%s: REQ_TYPE_BLOCK_PC, rq: %p\n",
					 str, rq);
#endif
			break;
		case REQ_TYPE_DRV_PRIV:
#if DEBUG
			bpf_trace_printk("%s: REQ_TYPE_DRV_PRIV, rq: %p\n", 
					 str, rq);
#endif
			break;
		default:
#if DEBUG
			bpf_trace_printk("%s: impossible!, rq: %p\n", str, rq);
#endif
		}
	}
}

int trace_virtio_queue_rq_entry(struct pt_regs *ctx,
                                struct blk_mq_hw_ctx *hctx,
                                const struct blk_mq_queue_data *bd)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	struct rq_ctx rc = {.id = id};
	struct request *rq = bd->rq;

	pesfc = sync_events.lookup(&id);
	if (pesfc) {
		char msg[] = "ext4_sync_file thread";
		judge_request_type(rq, msg);
		goto record;
	}
	pjctc = commit_events.lookup(&id);
	if (pjctc) {
		char msg[] = "jbd2 thread";
		judge_request_type(rq, msg);
		goto record;
	}
	pkc = kworker_events.lookup(&id);
	if (!pkc)
		return 0;
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
		char msg[] = "Wake up by ext4_sync_file thread";
		judge_request_type(rq, msg);
		goto record;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
		char msg[] = "Wake up by jbd2 thread";
		judge_request_type(rq, msg);
		goto record;
	}

	return 0;

record:
	rq_events.update(&rq, &rc);
	return 0;
}

int trace_vp_notify(struct pt_regs *ctx, struct virtqueue *_vq)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;

	pesfc = sync_events.lookup(&id);
	if (pesfc) {
		bpf_trace_printk("Notify host, vq: %p\n", _vq);
		goto end;
	}
	pjctc = commit_events.lookup(&id);
	if (pjctc) {
		bpf_trace_printk("Notify host, vq: %p\n", _vq);
		goto end;
	}
	pkc = kworker_events.lookup(&id);
	if (!pkc)
		goto end;
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
		bpf_trace_printk("Wake up by ext4_sync_file thread "
				 "notify host, vq: %p\n", _vq);
		goto end;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
		bpf_trace_printk("Wake up by jbd2 thread " 
				 "notify to host, vq: %p\n",
				 _vq);
		goto end;
	}

end:
	return 0;
}

int trace_iowrite16(struct pt_regs *ctx, u16 val, void __iomem *addr)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	u64 ts = bpf_ktime_get_ns();

	pesfc = sync_events.lookup(&id);
	if (pesfc) {
		bpf_trace_printk("Send to host, addr: %p, val: %u, ts: %llu\n",
				 addr, val, ts);
		goto end;
	}
	pjctc = commit_events.lookup(&id);
	if (pjctc) {
		bpf_trace_printk("Send to host, addr: %p, val: %u, ts: %llu\n",
				 addr, val, ts);
		goto end;
	}
	pkc = kworker_events.lookup(&id);
	if (!pkc)
		goto end;
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
		bpf_trace_printk("Wake up by ext4_sync_file thread "
				 "Send to host, addr: %p, val: %u, ts: %llu\n",
				 addr, val, ts);
		goto end;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
		bpf_trace_printk("Wake up by jbd2 thread " 
				 "Send to host, addr: %p, val: %u, ts: %llu\n",
				 addr, val, ts);
		goto end;
	}

end:
	return 0;
		
}

int trace_virtblk_request_done(struct pt_regs *ctx, struct request *req)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	u64 ts = bpf_ktime_get_ns();
	struct rq_ctx *prc = NULL;
	
	prc = rq_events.lookup(&req);
	if (!prc)
		return 0;
	
#if DEBUG
	bpf_trace_printk("Enter virtblk_request_done: %llu\n", ts);
#endif
	pesfc = sync_events.lookup(&prc->id);
	if (pesfc) {
		char msg[] = "ext4_sync_file thread's rq done by host";
		judge_request_type(req, msg);
		goto end;
	}
	pjctc = commit_events.lookup(&prc->id);
	if (pjctc) {
		char msg[] = "jbd2 thread's rq done by host";
		judge_request_type(req, msg);
		goto end;
	}
	pkc = kworker_events.lookup(&prc->id);
	if (!pkc)
		return 0;
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
		char msg[] = "Wake up by ext4_sync_file thread's rq done by " 
			     "host";
		judge_request_type(req, msg);
		goto end;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
		char msg[] = "Wake up by jbd2 thread's rq done by host";
		judge_request_type(req, msg);
		goto end;
	}

end:
	rq_events.delete(&req);
	rq_done_events.update(&id, prc);
	return 0;
}

int trace_virtio_queue_rq_return(struct pt_regs *ctx)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	
	pesfc = sync_events.lookup(&id);
	if (pesfc) {
#if DEBUG
		bpf_trace_printk("Return from virtio_queue_rq, id: %u\n", id);
#endif
		return 0;	
	}
	pjctc = commit_events.lookup(&id);
	if (pjctc) {
#if DEBUG
		bpf_trace_printk("Return from virtio_queue_rq, id: %u\n", id);
#endif
		return 0;	
	}
	pkc = kworker_events.lookup(&id);
	if (!pkc)
		return 0;
	pesfc = sync_events.lookup(&pkc->waker);
	if (pesfc) {
#if DEBUG
		bpf_trace_printk("Return from virtio_queue_rq, id: %u "
				 "waked up by ext4_sync_file thread\n", id);
#endif
		return 0;
	}
	pjctc = commit_events.lookup(&pkc->waker);
	if (pjctc) {
#if DEBUG
		bpf_trace_printk("Return from virtio_queue_rq, id: %u "
				 "waked up by jbd2 thread\n", id);
#endif
		return 0;
	}

	return 0;
}

TRACEPOINT_PROBE(ext4, ext4_writepages_result)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;	

#if DEBUG
	bpf_trace_printk("Return from ext4_writepages, pages_written: %d, " 
			 "pages_skipped: %d, writeback_index: %d\n", 
			 args->pages_written, args->pages_skipped,
			 args->writeback_index);
#endif

	return 0;
}

int trace___filemap_fdatawait_range_entry(struct pt_regs *ctx,
                                          struct address_space *mapping,
                                          loff_t start_byte, loff_t end_byte)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;

#if DEBUG
	bpf_trace_printk("Enter __filemap_fdatawait_range\n");
#endif

	return 0;
}

int trace_pagevec_lookup_tag_entry(struct pt_regs *ctx,
                                   struct pagevec *pvec,
                                   struct address_space *mapping,
                                   pgoff_t *index,
                                   int tag, unsigned nr_pages)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);

	if (!pesfc)
		return 0;
	
	pesfc->tag = tag;	
	return 0;
}

int trace_pagevec_lookup_tag_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);
	int ret = PT_REGS_RC(ctx);

	if (!pesfc)
		return 0;

	switch (pesfc->tag) {
	case PAGECACHE_TAG_DIRTY:
		bpf_trace_printk("PAGECACHE_TAG_TAG: %d\n", ret);
		break;
	case PAGECACHE_TAG_WRITEBACK:
		bpf_trace_printk("PAGECACHE_TAG_WRITEBACK: %d\n", ret);
		break;
	case PAGECACHE_TAG_TOWRITE:
		bpf_trace_printk("PAGECACHE_TAG_TOWRITE: %d\n", ret);
		break;
	}

	return 0;
}

int trace___filemap_fdatawait_range_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;

#if DEBUG
	bpf_trace_printk("Return __filemap_fdatawait_range\n");
#endif
	return 0;
}

int trace_jbd2_complete_transaction_entry(struct pt_regs *ctx,
                                          journal_t *journal, tid_t tid)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct journal_ctx *pjc = NULL;

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;
	pjc = journal_start_events.lookup(&journal);
	if (!pjc)
		return 0;
	if (pjc->tid != tid)
		return 0;

#if DEBUG
	bpf_trace_printk("Enter jbd2_complete_transaction make sure "
			 "journal: %p, tid: %u will complete\n", journal, tid);
#endif
	return 0;
}

int trace_jbd2_log_start_commit_entry(struct pt_regs *ctx, journal_t *journal, tid_t tid)
{
	struct journal_ctx *pjc = NULL;

 	pjc = journal_start_events.lookup(&journal);
	if (!pjc)
		return 0;
	if (pjc->tid != tid)
		return 0;

#if DEBUG
	bpf_trace_printk("Start commit jbd2 log, journal: %p, tid: %u\n",
			 journal, tid);
#endif
	return 0;
}

int trace_jbd2_log_wait_commit_entry(struct pt_regs *ctx,
                                     journal_t *journal, tid_t tid)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);

	if (!pesfc)
		return 0;

#if DEBUG
	bpf_trace_printk("The txn has currently running, start committing "
			 "that txn before waiting for it to complete.\n");
#endif
	return 0;
}

int trace_jbd2_log_wait_commit_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	pesfc = sync_events.lookup(&id);

	if (!pesfc)
		return 0;

#if DEBUG
	bpf_trace_printk("Return from jbd2_log_wait_commit, "
			 "the txn has completed, pid: %u\n", id);
#endif
	return 0;
}

int trace_ext4_journal_commit_callback(struct pt_regs *ctx,
				       journal_t *journal,
				       transaction_t *txn)
{
	u64 id = bpf_get_current_pid_tgid();
	struct journal_ctx *pjc = NULL;

	pjc = journal_start_events.lookup(&journal);
	if (!pjc)
		return 0;
	if (pjc->tid != txn->t_tid)
		return 0;

#if DEBUG
	bpf_trace_printk("callback journal: %p, txn: %u, pid: %u\n",
			 journal, txn->t_tid, id);	
#endif
	return 0;
}

int trace_jbd2_complete_transaction_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();

	pesfc = sync_events.lookup(&id);
	if (!pesfc)
		return 0;

#if DEBUG
	bpf_trace_printk("Return from jbd2_complete_transaction\n");
#endif
    	return 0;
}

int trace_jbd2_trans_will_send_data_barrier_entry(struct pt_regs *ctx, 
					       	  journal_t *journal, 
						  tid_t tid)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);	
	if (!pesfc)
		return 0;
	
	pesfc->journal = journal;

#if DEBUG
	bpf_trace_printk("Enter will_send_data_barrier journal: %p, tid: %u\n",
			 journal, tid);
#endif
	return 0;
}

int trace_jbd2_trans_will_send_data_barrier_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	int ret = PT_REGS_RC(ctx);
	
	pesfc = sync_events.lookup(&id);	
	if (!pesfc)
		return 0;

	pesfc->needs_barrier = !ret;

#if DEBUG
	bpf_trace_printk("Needs barrier: %d\n", pesfc->needs_barrier);
#endif
	return 0;
}

int trace_submit_bio(struct pt_regs *ctx, int rw, struct bio *bio)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);	
	if (!pesfc)	
		return 0;
	if (rw != WRITE_FLUSH)
		return 0;

#if DEBUG
	bpf_trace_printk("Submit IO rq: WRITE_FLUSH\n");
#endif
	return 0;
}

int trace_blk_insert_flush(struct pt_regs *ctx, struct request *rq)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();

	pesfc = sync_events.lookup(&id);	
	if (pesfc) {
#if DEBUG
		bpf_trace_printk("%u insert a new FLUSH/FUA request\n", id);
#endif
		return 0;
	}
	pjctc = commit_events.lookup(&id);
	if (pjctc) {
#if DEBUG
		bpf_trace_printk("%u insert a new FLUSH/FUA request\n", id);
#endif
		return 0;
	}

end:
	return 0;
}

TRACEPOINT_PROBE(block, block_bio_queue)
{
    return 0;
}

TRACEPOINT_PROBE(block, block_getrq)
{
    return 0;
   
}

TRACEPOINT_PROBE(workqueue, workqueue_queue_work)
{

    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_activate_work)
{

    return 0;
}

int trace_wake_up_process(struct pt_regs *ctx, struct task_struct *p)
{
	struct jbd2_commit_txn_ctx *pjctc = NULL;
	u64 wakee = (u64) p->tgid << 32 | p->pid;
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx kc = {};
	
	pesfc = sync_events.lookup(&id);
	if (!pesfc) {
		pjctc = commit_events.lookup(&id);
		if (!pjctc)
			return 0;
#if DEBUG
		bpf_trace_printk("jp->comm: %s, p->pid: %d\n", &p->comm[0], p->pid);
#endif
	} else {
#if DEBUG
		bpf_trace_printk("fp->comm: %s, p->pid: %d\n", &p->comm[0], p->pid);
#endif
	}
	
	kc.waker = id;
	kworker_events.update(&wakee, &kc);
	return 0;
}

int trace_blk_mq_requeue_work_entry(struct pt_regs *ctx,
				    struct work_struct *work)
{
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	
	pkc = kworker_events.lookup(&id);
	if (!pkc)
		return 0;

#if DEBUG
	bpf_trace_printk("Enter blk_mq_requeue\n");
#endif
	return 0;
}

int trace_blk_mq_requeue_work_return(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	struct kworker_ctx *pkc = NULL;
	
	if (!pkc)
		return 0;

#if DEBUG
	bpf_trace_printk("Return from blk_mq_requeue\n");	
#endif
	return 0;
}

int trace_wait_for_completion_io_entry(struct pt_regs *ctx, struct completion *x)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);
	if (!pesfc) 
		return 0;

#if DEBUG
	bpf_trace_printk("wait_for_completion_io_entry\n");
#endif
	return 0;
}

int trace_wait_for_completion_io_return(struct pt_regs *ctx)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);
	if (!pesfc) 
		return 0;

#if DEBUG
	bpf_trace_printk("wait_for_completion_io_return\n");
#endif
	return 0;
}

int trace_blkdev_issue_flush_return(struct pt_regs *ctx)
{

	return 0;
}

TRACEPOINT_PROBE(ext4, ext4_sync_file_exit)
{
	struct ext4_sync_file_ctx *pesfc = NULL;
	u64 id = bpf_get_current_pid_tgid();
	
	pesfc = sync_events.lookup(&id);	
	if (!pesfc)
		return 0;
	
	journal_start_events.delete(&pesfc->journal);
	commit_events.delete(&pesfc->jbd2id);
	sync_events.delete(&id);
	
#if DEBUG
	bpf_trace_printk("ext4_sync_file_exit\n");
#endif
	return 0;
}
