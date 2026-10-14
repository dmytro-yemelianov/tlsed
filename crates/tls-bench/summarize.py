#!/usr/bin/env python3
"""Summarize raw CSV; keep samples for independent reanalysis."""
import csv, math, statistics, sys
from collections import defaultdict
rows = defaultdict(list)
for filename in sys.argv[1:]:
    with open(filename, newline='') as stream:
        for row in csv.DictReader(stream):
            key = tuple(row[k] for k in ['implementation','workload','direction','payload_bytes','iterations'])
            rows[key].append(int(row['elapsed_ns']))
print('implementation,workload,direction,payload_bytes,iterations,n,mean_ns,stdev_ns,cv_percent,p50_ns,p95_ns,p99_ns,gib_per_s')
for key, values in sorted(rows.items()):
    values.sort()
    quantile = lambda p: values[max(0, math.ceil(p*len(values))-1)]
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values)>1 else 0
    throughput = int(key[3])*int(key[4])/(mean/1e9)/(1024**3) if key[1]=='bulk' else 0
    print(','.join(key)+f',{len(values)},{mean:.2f},{sd:.2f},{100*sd/mean:.2f},{quantile(.50)},{quantile(.95)},{quantile(.99)},{throughput:.6f}')
