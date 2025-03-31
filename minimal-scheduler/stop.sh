#!/bin/sh

# Remove the scheduler
if [ -e /sys/fs/bpf/sched_ext/sched_ops ]; then
    sudo rm /sys/fs/bpf/sched_ext/sched_ops
fi
