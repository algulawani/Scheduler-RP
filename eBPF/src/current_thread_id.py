#!/usr/bin/env python3

from bcc import BPF
from time import sleep

"""
IMPORTANT:
   1. This program is a very rudimentary eBPF, only meant to set up the collection infrastructure at extremely
      stages. THIS WILL NOT GO ON THE FINAL OBSERVABILITY LAYER.
   2. This program has several issues, listed below:
   3. PROBLEM 1: oberver effect. running this program outputs the PID corresponding to python3 overwhelmingly.
      This is because it doesn't exclude its own PID. This is genuinely a massive problem, and will be solved
      in the final libbpf program.
   4. This program uses BCC to send this code to the kernel. This means it will take an unacceptably long time
      to start logging values, eventually, it should use libbpf.
   5. This program outputs utilization to the terminal, eventually, it should print the output to a file.
   6. This program also needs a proper shutdown sequence, will be defined later.
"""

C_code = r"""
BPF_ARRAY(current_thread_id, pid_t, 1);

TRACEPOINT_PROBE(sched, sched_switch)
{
    pid_t current_thread_id_val;
    u32 CURRENT_THREAD_ID_KEY_0 = 0;

    current_thread_id_val = args->next_pid;
    current_thread_id.update(&CURRENT_THREAD_ID_KEY_0, &current_thread_id_val);
    return 0;
}
"""

bpf = BPF(text=C_code)

while True:
    sleep(1)
    current_thread_id = bpf["current_thread_id"][0].value
    print(current_thread_id)
