#!/bin/bash
SERVNAME=giacomo
SERV=192.168.2.189
APNAME=root
AP=192.168.0.1
CLIENT=client_log
SERVER=server_log
INT=eth0
TIME=50

RECNAME=giacomo
REC=192.168.2.189
DWN=4000kbit
RATE=4000kbit
INT=eth0
HOST=192.168.0.139
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
sudo tc qdisc add dev $INT parent 1:2 handle 20: netem delay $DL
sudo tc qdisc show

#TC client
ssh -f $RECNAME@$REC "cd Scrivania && echo lubuntu | sudo -S ./tc_start.sh"

##
ssh -f $APNAME@$AP "insmod slk up_bwt=512"
#ssh -f $APNAME@$AP "slus -b 512"
##

echo "START TRANSMISSION"

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w trasmissione.dmp &
sleep 3s

iperf -c $SERV -F "100MB.zip"  -t $TIME -i 1  | tee -a $CLIENT

sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

echo "END TRANSMISSION"

##
ssh -f $APNAME@$AP "rmmod slk"
#ssh -f $APNAME@$AP "killall slus && /usr/sbin/iptables -t mangle -F"
##

#Eliminazione del collo di bottiglia

sudo tc qdisc del dev $INT root #server
ssh -f $RECNAME@$REC "echo lubuntu | sudo -S tc qdisc del dev enp0s3 root" #client

./tcp_dump_plot.sh