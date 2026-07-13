#!/usr/bin/env python3

from bcc import BPF
from time import sleep

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
