bpftrace -e '
tracepoint:raw_syscalls:sys_enter 
/comm == "testCGO"/ 
{ 
    printf("[%s.%03d] PID: %d, Syscall Number: %d\n", strftime("%H:%M:%S", nsecs), (nsecs / 1000000) % 1000, pid, args->id); 
}'
