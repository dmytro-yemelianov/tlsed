#!/usr/bin/env python3
"""Batch construction separately from retirement; use unchanged production engine."""
import csv
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
root=Path(__file__).resolve().parents[3]
binary=root/'target/cpu-audit/workspace/target/release/client_compare_construction'
output=root/'verification/results/2026-10-14-cpu-audit/construction'
output.mkdir(exist_ok=False)
manifest={'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'repeats':6,'samples':100,'batch':32,'commands':[],'controls':'no concurrent builds/tests/profiles; construction only, Drop outside timer; client order alternates per process'}
values={}
for repeat in range(6):
 command=[str(binary),'--only','construction','--suite','aes128','--group','x25519','--samples','100','--bulk-records','256','--order','tlsed-first' if repeat%2==0 else 'rustls-first']
 p=output/f'repeat-{repeat}.csv'
 with p.open('w') as stream,p.with_suffix('.stderr').open('w') as error:
  result=subprocess.run(command,cwd=root,stdout=stream,stderr=error,check=True)
 manifest['commands'].append({'argv':command,'exit_code':result.returncode})
 count=0
 for row in csv.DictReader(p.open()):
  assert int(row['iterations'])==32
  values.setdefault((row['implementation'],row['workload'],repeat),[]).append(int(row['elapsed_ns'])/32)
  count+=1
 assert count==400
 print(f'Construction repeat {repeat+1}/6 complete',flush=True)
rows=[]
for implementation,workload in sorted({(i,w) for i,w,r in values}):
 medians=[statistics.median(values[(implementation,workload,r)]) for r in range(6)]
 rows.append([implementation,workload,statistics.median(medians),min(medians),max(medians),*medians])
with (output/'comparison.csv').open('w',newline='') as stream:
 writer=csv.writer(stream);writer.writerow(['implementation','workload','median_ns_per_call','repeat_min_ns','repeat_max_ns',*[f'repeat_{r}_ns' for r in range(6)]]);writer.writerows(rows)
manifest['csv_sha256']={str(p.name):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.glob('*.csv'))}
(output/'run.json').write_text(json.dumps(manifest,indent=2)+'\n')
