"""Full-map public CLI latency, including JSON serialization/IPC/process exit.

Prints every measured result, then fails if any deadline/behavior is unmet.
Never increase the budget to turn an unsupported capacity result green.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

root=Path(sys.argv[1])
policy=root/'policy.rules'
limits=root/'limits.rules'
limits.write_text('default pass\nset live\n'+''.join(f'limit 1000000/s burst 1000000 proto udp dport {10000+i}\n' for i in range(64)))
cases=[('stats',),('jail',),('log',),('set','add','live','2001:db8::/32'),('set','del','live','2001:db8::/32'),
       ('unjail','fd00::1'),('reload',str(policy)),('reload',str(limits))]
failures=[]
for args in cases:
    start=time.monotonic()
    try:
        r=subprocess.run(['./trafficcop',*args],capture_output=True,text=True,timeout=4)
        elapsed=time.monotonic()-start
        value=json.loads(r.stdout) if r.returncode==0 and r.stdout else None
        correct=r.returncode==0 and not r.stderr
        if args[0]=='stats':correct=correct and value['jailed_sources']==1048576 and value['top_sources'][0]['packets']==1048576
        if args[0]=='jail':correct=correct and len(value)==1048576 and value[0]['src']=='fd00::1'
        if args[0]=='log':correct=correct and value==[]
        record=dict(command=list(args),seconds=round(elapsed,6),exit=r.returncode,stdout_bytes=len(r.stdout.encode()),correct=bool(correct),within_one_second=elapsed<1,stderr=r.stderr.strip())
    except subprocess.TimeoutExpired:
        record=dict(command=list(args),seconds=round(time.monotonic()-start,6),correct=False,within_one_second=False,error='process exceeded four-second diagnostic limit')
    print(json.dumps(record),flush=True)
    if not record['correct'] or not record['within_one_second']:failures.append(args[0])
print(json.dumps(dict(full_capacity_command_deadlines_passed=not failures,failures=failures)),flush=True)
sys.exit(bool(failures))
