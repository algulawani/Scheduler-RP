#!/usr/bin/env python3

"""
IMPORTANT:
   1. This program is a very rudimentary eBPF, only meant to set up the collection infrastructure at extremely
      stages. THIS WILL NOT GO ON THE FINAL OBSERVABILITY LAYER.
   2. This program has several issues, listed below:
   3. PROBLEM 1: idle_time and total_time have no way of resetting, so the value stored in them is not idle t-
      me spent in this session, it stores the amount of idle time that that CPU has spent since FOREVER.
   4. PROBLEM 2: this program only tracks utilization on a single CPU, The machine on which this will be depl-
      oyed will have multiple cores.
   5. This program uses BCC to send this code to the kernel. This means it will take an unacceptably long time
      to start logging values, eventually, it should use libbpf.
   6. This program outputs utilization to the terminal, eventually, it should print the output to a file.
   7. This program also needs a proper shutdown sequence, will be defined later.
   8. This has been my first, actual eBPF.
"""

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
	u64 prog_exec_cntr_val;
	u64 *prog_exec_cntr_ptr;
	__u64 initial_time;
	__u64 current_time;
	__u64 time_delta;
	__u64 idle_time_passed;
	__u64 total_time_passed;
	__u64 *util_time_ptr;
	__u64 *time_stamps_init_ptr;

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

	time_stamps_init_ptr = time_stamps.lookup(&TIME_STAMPS_KEY_0);
	if (time_stamps_init_ptr == 0)
		return 0;

	initial_time = *time_stamps_init_ptr;
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
	if total_time_passed != 0:
		cpu_utilization_pct = (1 - idle_time_passed / total_time_passed) * 100
		print(f"{cpu_utilization_pct} %")
	elif total_time_passed <=  0:
		print("error, negative or zero value for total_time_passed") 
