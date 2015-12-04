#!/bin/bash
#Inizia la sessione di traffic control sul client
DWN=4000kbit
RATE=4000kbit
INT=enp0s3
HOST=192.168.2.189
DL=60ms

##TC
# For bandwidth limitation
sudo tc qdisc add dev $INT root handle 1: htb default 30
sudo tc class add dev $INT parent 1: classid 1:1 htb rate $RATE 
sudo tc class add dev $INT parent 1: classid 1:2 htb rate $RATE
sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip dst $HOST/32 flowid 1:1 
sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip src $HOST/32 flowid 1:2

# For delay (RTT) increment
sudo tc qdisc add dev $INT parent 1:1 handle 10: netem delay $DL
sudo tc qdisc add dev $IF parent 10: pfifo limit 1000
sudo tc qdisc add dev $INT parent 1:2 handle 20: netem delay $DL
sudo tc qdisc add dev $IF parent 20: pfifo limit 1000
sudo tc qdisc show
