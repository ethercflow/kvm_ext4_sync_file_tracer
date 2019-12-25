#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF

b = BPF(src_file=b'kvm_ext4_sync_file_tracer.c')
b.attach_kprobe(event="jbd2__journal_start",
		fn_name="trace_jbd2__journal_start_entry");
b.attach_kretprobe(event="jbd2__journal_start",
		   fn_name="trace_jbd2__journal_start_return")
b.attach_kprobe(event="jbd2_journal_stop",
		fn_name="trace_jbd2_journal_stop");
b.attach_kprobe(event="default_wake_function",
                fn_name="trace_default_wake_function")
b.attach_kprobe(event="virtio_queue_rq", fn_name="trace_virtio_queue_rq_entry")
b.attach_kprobe(event="vp_notify", fn_name="trace_vp_notify")
b.attach_kprobe(event="iowrite16", fn_name="trace_iowrite16")
b.attach_kretprobe(event="virtio_queue_rq",
                   fn_name="trace_virtio_queue_rq_return")
b.attach_kprobe(event="virtblk_request_done",
		fn_name="trace_virtblk_request_done")
b.attach_kprobe(event="__filemap_fdatawait_range",
                fn_name="trace___filemap_fdatawait_range_entry")
b.attach_kprobe(event="pagevec_lookup_tag",
                fn_name="trace_pagevec_lookup_tag_entry")
b.attach_kretprobe(event="pagevec_lookup_tag",
                   fn_name="trace_pagevec_lookup_tag_return")
b.attach_kretprobe(event="__filemap_fdatawait_range",
                   fn_name="trace___filemap_fdatawait_range_return")
b.attach_kprobe(event="jbd2_complete_transaction",
                fn_name="trace_jbd2_complete_transaction_entry")
b.attach_kprobe(event="jbd2_log_start_commit", 
		fn_name="trace_jbd2_log_start_commit_entry");
b.attach_kprobe(event="jbd2_journal_commit_transaction",
		fn_name="trace_jbd2_journal_commit_transaction");
b.attach_kprobe(event="jbd2_log_wait_commit",
                fn_name="trace_jbd2_log_wait_commit_entry")
b.attach_kretprobe(event="jbd2_log_wait_commit",
                   fn_name="trace_jbd2_log_wait_commit_return")
b.attach_kprobe(event="ext4_journal_commit_callback",
		fn_name="trace_ext4_journal_commit_callback")
b.attach_kretprobe(event="jbd2_complete_transaction",
                   fn_name="trace_jbd2_complete_transaction_return")
b.attach_kprobe(event="jbd2_trans_will_send_data_barrier",
		fn_name="trace_jbd2_trans_will_send_data_barrier_entry")
b.attach_kretprobe(event="jbd2_trans_will_send_data_barrier",
		   fn_name="trace_jbd2_trans_will_send_data_barrier_return");
b.attach_kprobe(event="submit_bio", fn_name="trace_submit_bio")
b.attach_kprobe(event="blk_insert_flush", fn_name="trace_blk_insert_flush")
b.attach_kprobe(event="wake_up_process",
                fn_name="trace_wake_up_process")
b.attach_kprobe(event="blk_mq_requeue_work",
		fn_name="trace_blk_mq_requeue_work_entry");
b.attach_kretprobe(event="blk_mq_requeue_work",
		   fn_name="trace_blk_mq_requeue_work_return")
b.attach_kprobe(event="wait_for_completion_io",
                fn_name="trace_wait_for_completion_io_entry")
b.attach_kretprobe(event="wait_for_completion_io",
                   fn_name="trace_wait_for_completion_io_return")
b.attach_kretprobe(event="blkdev_issue_flush",
                   fn_name="trace_blkdev_issue_flush_return")

while True:
    pass
