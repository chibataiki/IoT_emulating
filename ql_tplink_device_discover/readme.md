[TOC]

## qiling

wait.

## AFL mode

tryed with qiling afl++ unicorn mode, but since there is some magic number check  and chksum mechanism, so it's hard to find deep path,  afl++ custom mutators maybe useful. 

```
AFL_AUTORESUME=1  afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ql_afl_main.py @@


             american fuzzy lop ++4.03c {default} (python3) [fast]
┌─ process timing ────────────────────────────────────┬─ overall results ────┐
│        run time : 0 days, 0 hrs, 0 min, 24 sec      │  cycles done : 0     │
│   last new find : none seen yet                     │ corpus count : 6     │
│last saved crash : none seen yet                     │saved crashes : 0     │
│ last saved hang : none seen yet                     │  saved hangs : 0     │
├─ cycle progress ─────────────────────┬─ map coverage┴──────────────────────┤
│  now processing : 1.1 (16.7%)        │    map density : 0.02% / 0.02%      │
│  runs timed out : 0 (0.00%)          │ count coverage : 1.00 bits/tuple    │
├─ stage progress ─────────────────────┼─ findings in depth ─────────────────┤
│  now trying : havoc                  │ favored items : 6 (100.00%)         │
│ stage execs : 1304/1766 (73.84%)     │  new edges on : 6 (100.00%)         │
│ total execs : 10.3k                  │ total crashes : 0 (0 saved)         │
│  exec speed : 408.9/sec              │  total tmouts : 0 (0 saved)         │
├─ fuzzing strategy yields ────────────┴─────────────┬─ item geometry ───────┤
│   bit flips : disabled (default, enable with -D)   │    levels : 1         │
│  byte flips : disabled (default, enable with -D)   │   pending : 0         │
│ arithmetics : disabled (default, enable with -D)   │  pend fav : 0         │
│  known ints : disabled (default, enable with -D)   │ own finds : 5         │
│  dictionary : n/a                                  │  imported : 0         │
│havoc/splice : 0/1664, 0/0                          │ stability : 100.00%   │
│py/custom/rq : unused, unused, unused, unused       ├───────────────────────┘
│    trim/eff : 50.00%/5, disabled                   │          [cpu000: 12%]
└────────────────────────────────────────────────────┘

```



