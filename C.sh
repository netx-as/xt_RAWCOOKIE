#!/bin/bash

make clean
make
#make install

iptables -F -t raw
iptables -F -t filter
iptables -F -t mangle
iptables -F -t nat

set -x
#rmmod  ipt_SYNPROXY
#insmod ./ipt_SYNPROXY.ko

rmmod  ipt_RAWCOOKIE
insmod ./ipt_RAWCOOKIE.ko

#iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j RAWCOOKIE --sack-perm --timestamp --wscale 7 --mss 1460 --senddirect --txmac 4c:ae:a3:6a:80:bc
iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j RAWCOOKIE --sack-perm --timestamp --wscale 7 --mss 1460 --senddirect --txmac 4c:ae:a3:6a:80:bc
#iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t raw -A PREROUTING -i tge22 -p tcp -m tcp --syn --dport 80 -j CT --notrack
iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -A INPUT -i tge22 -p tcp -m tcp --dport 80 -m state --state INVALID -j DROP

#iptables -I OUTPUT -j CT --notrack
#iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
#iptables -t raw -A PREROUTING -p tcp -m tcp --dport 80 -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
#iptables -t mangle -A PREROUTING -p tcp -m tcp --dport 80 -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
#iptables -t filter -A INPUT -p tcp -m tcp --dport 80 -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460


iptables -S
iptables -S -t raw
iptables -S -t mangle

sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.netfilter.nf_conntrack_max=10000000

#echo 'file ipt_RAWCOOKIE.c +p' > /sys/kernel/debug/dynamic_debug/control
dmesg -C

rm -rf /var/crash/*

