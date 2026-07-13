#!/usr/bin/env python3

# IMPORTANT:
# This file is temporary!!! 
# This uses BCC implementation and is only useful in for initial testing and debugging of the observation layer.
# If for any reason this file exists along side a properly working .bpf.c file, then delete this.
#	- Anay

from bcc import BPF
from time import sleep

C_code = r"""
BPF_ARRAY(prog_exec_cntr, u64, 1);
BPF_ARRAY(time_stamps, __u64, 2);
BPF_ARRAY(util_time, __u64, 2);

TRACEPOINT_PROBE(sched, sched_switch)
{
	pid_t prev_PID;
	u32 CPU;
	u32 PROG_EXEC_CNTR_KEY_0 = 0;
	u32 TIME_STAMPS_KEY_0 = 0; //INITIAL
	u32 TIME_STAMPS_KEY_1 = 1; //CURRENT
	u32 UTIL_TIME_KEY_0 = 0; //IDLE
	u32 UTIL_TIME_KEY_1 = 1; //TOTAL
	u64 *prog_exec_cntr_ptr;
	__u64 initial_time;
	__u64 current_time;
	__u64 time_delta;
	__u64 idle_time_passed;
	__u64 total_time_passed;
	__u64 *util_time_ptr;	

	CPU = bpf_get_smp_processor_id();
	if (CPU != 0)
		return 0;

	prog_exec_cntr_ptr = prog_exec_cntr.lookup(&PROG_EXEC_CNTR_KEY_0);
	if (prog_exec_cntr_ptr == 0)
		return 0;

	prog_exec_cntr_val = *prog_exec_cntr_ptr;

	if (prog_exec_cntr_val == 0)
	{
		initial_time = bpf_ktime_get_ns();
		time_stamps.update(&TIME_STAMPS_KEY_0, &initial_time);
	}

	current_time = bpf_ktime_get_ns();
	time_delta = current_time - initial_time;
	time_stamps.update(&TIME_STAMPS_KEY_1, &current_time);
	prev_PID = args->prev_pid;

	util_time_ptr = util_time.lookup(&UTIL_TIME_KEY_1);
	if (util_time_ptr == 0)
		return 0;

	total_time_passed = *util_time_ptr;
	total_time_passed += time_delta;
	util_time.update(&UTIL_TIME_KEY_1, &total_time_passed);

	if (prev_PID == 0)
	{
		util_time_ptr = util_time.lookup(&UTIL_TIME_KEY_0);
		if (util_time_ptr == 0)
			return 0;
		
		idle_time_passed = *util_time_ptr;
		idle_time_passed += time_delta;
		util_time.update(&UTIL_TIME_KEY_0, &idle_time_passed);
	}

	time_stamps.update(&TIME_STAMPS_KEY_0, &current_time);
	
	prog_exec_cntr_val++;
	prog_exec_cntr.update(&PROG_EXEC_CNTR_KEY_0, &prog_exec_cntr_val);

	return 0;
}
"""

bpf = BPF(text=C_code)

while True:
	sleep(2)
	idle_time_passed = bpf["util_time"][0].value
	total_time_passed = bpf["util_time"][1].value
	cpu_utilization_pct = (1 - idle_time_passed / total_time_passed) * 100
	print(f"{cpu_utilization_pct} %")
