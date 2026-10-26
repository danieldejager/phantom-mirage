#@ persona: ubuntu2404
#@ target: ubuntu2404 (Ubuntu 24.04)
#@ os-build: unknown
#@ firewall: on
#@ ports: open_tcp=22 closed_tcp=1 closed_udp=40000
#@ lab-run: 900002 attempt 1
#@ captures: 1
#@ probe-runs: synthetic-ubuntu2404-0001,synthetic-ubuntu2404-0002,synthetic-ubuntu2404-0003
#@ probe-tool: fingerprint-lab/probe.py 0.3.2
#@ captured-utc: 2000-01-01T00:00:00Z
#@ tool-source-commit: 0000000000000000000000000000000000000000
#@ tool-versions-sha256: fcbd9e4f23635ed1f3b9930f3861600f74e08a01b96bcd8766c4cf192ce3fd4a
#@ generator: fingerprint-lab/build_db.py 0.3.2
#@ sp-isr-method: min-max range over all probe runs (see sidecar)
#@ ranges: none
#@ limit: single capture: every field rests on one lab run (900002, 3 probe runs, one boot); no restart capture to confirm it
Fingerprint ubuntu2404
SEQ(SP=17%GCD=3E8%ISR=92%TI=I%CI=Z%II=I%SS=O%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4ST11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11NW7)
WIN(W1=FAF0%W2=FAF0%W3=FAF0%W4=FAF0%W5=FAF0%W6=FAF0)
ECN(R=Y%DF=Y%T=40%TG=40%W=FAF0%O=M5B4ST11NW7%CC=N%Q=)
T1(R=Y%DF=Y%T=40%TG=40%W=FAF0%S=O%A=S+%F=AS%O=M5B4ST11NW7%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=N%T=40%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=N%T=40%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=N%T=40%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%T=40%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=Z)
