#@ persona: ws2022-fwon
#@ target: ws2022 (Windows Server 2022)
#@ firewall: on
#@ lab-run: 900001 attempt 1
#@ probe-runs: synthetic-ws2022-0001,synthetic-ws2022-0002,synthetic-ws2022-0003
#@ probe-tool: fingerprint-lab/probe.py 0.1.0
#@ captured-utc: 2000-01-01T00:00:00Z
#@ tool-source-commit: 0000000000000000000000000000000000000000
#@ tool-versions-sha256: 0b5f0cb44367f1aa1baed66158e12bb728039ae82a2738b1a28dedfabf80420e
#@ generator: fingerprint-lab/build_db.py 0.1.0
#@ ranges: SEQ.ISR range 95-97 (min-max of runs), SEQ.SP range 50-56 (min-max of runs)
Fingerprint ws2022-fwon
SEQ(SP=50-56%GCD=3E8%ISR=95-97%TI=I%CI=Z%II=I%SS=O%TS=1)
OPS(O1=M5B4NW8NNS%O2=M5B4NW8NNS%O3=M5B4NW8NNS%O4=M5B4NW8NNS%O5=M5B4NW8NNS%O6=M5B4NW8NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)
ECN(R=Y%DF=Y%T=80%TG=80%W=FFFF%O=M5B4NW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%T=80%TG=80%W=FFFF%S=O%A=S+%F=AS%O=M5B4NW8NNS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=N%T=80%TG=80%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=N%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=N%T=80%TG=80%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=N%T=80%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%TG=80%CD=Z)
