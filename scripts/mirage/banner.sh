#!/bin/sh
# scripts/mirage/banner.sh SERVICE: static banner for the Debian default
# decoy template (#129), so nmap -sV sees one plausible Debian 12 host
# instead of silent open ports. SERVICE is ftp, ssh, telnet or http.
# The connection is stdin/stdout. Shell builtins only: no files, no
# network, nothing outside the --sandbox-scripts read-only root. Every
# login fails; nothing the client sends is executed or stored.
cr=$(printf '\r')
rd() { IFS= read -r line || exit 0; line=${line%"$cr"}; }
case ${1:-} in
ssh)
	printf 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n'
	rd	# the client's ident; a real key exchange is out of scope
	;;
ftp)
	printf '220 (vsFTPd 3.0.3)\r\n'
	n=0
	while rd; do
		n=$((n + 1)); [ $n -le 20 ] || exit 0
		case $line in
		[Uu][Ss][Ee][Rr]\ *) printf '331 Please specify the password.\r\n' ;;
		[Pp][Aa][Ss][Ss]*) printf '530 Login incorrect.\r\n' ;;
		[Qq][Uu][Ii][Tt]*) printf '221 Goodbye.\r\n'; exit 0 ;;
		*) printf '530 Please login with USER and PASS.\r\n' ;;
		esac
	done
	;;
telnet)
	# IAC DO TERMINAL-TYPE, TERMINAL-SPEED, X-DISPLAY, NEW-ENVIRON (as telnetd)
	printf '\377\375\030\377\375\040\377\375\043\377\375\047'
	printf '\r\nDebian GNU/Linux 12\r\n'
	for _ in 1 2 3; do
		printf 'login: '; rd
		printf 'Password: '; rd
		printf '\r\nLogin incorrect\r\n'
	done
	;;
http)
	rd
	while [ -n "$line" ]; do rd; done	# skip the request headers
	b='<html><body><h1>It works!</h1></body></html>'
	printf 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\n'
	printf 'Content-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n' $((${#b} + 1)) "$b"
	;;
esac
exit 0
