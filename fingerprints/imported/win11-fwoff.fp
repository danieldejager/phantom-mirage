#@ persona: win11-fwoff
#@ target: win11 (Windows 11)
#@ firewall: off
#@ ports: open_tcp=3389
#@ probe-runs: 6
#@ probe-tool: fingerprint-lab/probe.py 0.3.2
#@ derive: fingerprint-lab/derive.py 0.3.2
#@ source: columbo-v1.db release asset (block copied byte for byte)
#@ limit: imported from the published database, not rebuilt here: capture inputs, input hashes and derive commit are not in this repository; build_shipped_db.py cannot rebuild this block
#@ limit: not yet scored under the OS fingerprint scoring sheet; closed_tcp/closed_udp ports not published
Fingerprint win11-fwoff
SEQ(SP=103-10C%GCD=1%ISR=105-10F%TI=I%CI=I%II=I%SS=S%TS=A)
OPS(O1=M5B4NW0ST11%O2=M5B4NW0ST11%O3=M5B4NW0NNT11%O4=M5B4NW0ST11%O5=M5B4NW0ST11%O6=M5B4ST11)
WIN(W1=FA00%W2=FA00%W3=FA00%W4=FA00%W5=FA00%W6=FA00)
ECN(R=Y%DF=Y%T=80%TG=80%W=FA00%O=M5B4NW0NNS%CC=N%Q=)
T1(R=Y%DF=Y%T=80%TG=80%W=FA00%S=O%A=S+%F=AS%O=M5B4NW0ST11%RD=0%Q=)
T2(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%TG=80%CD=Z)
