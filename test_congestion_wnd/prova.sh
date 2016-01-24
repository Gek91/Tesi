#!/bin/bash

RATE=4000kbit
INT=eth0
HOST=192.168.0.139
DL=60ms

CLIENT=client_log
SERVER=server_log

SERVNAME=giacomo
SERV=192.168.2.189
ITGR="cd Scrivania/D-ITG-2.8.1-r1023/bin/ && ./ITGRecv"
APNAME=root
AP=192.168.0.1

##TC
# For bandwidth limitation
#sudo tc qdisc add dev $INT root handle 1: htb default 30
#sudo tc class add dev $INT parent 1: classid 1:1 htb rate $RATE
#sudo tc class add dev $INT parent 1: classid 1:2 htb rate $RATE
#sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip dst $HOST/32 flowid 1:1
#sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip src $HOST/32 flowid 1:2

# For delay (RTT) increment
#sudo tc qdisc add dev $INT parent 1:1 handle 10: netem delay $DL
#sudo tc qdisc add dev $INT parent 1:2 handle 20: netem delay $DL
#sudo tc qdisc show


##
#ssh -f $APNAME@$AP "insmod slk up_bwt=512"
#ssh -f $APNAME@$AP "slus -b 512"
##


#ssh -f $SERVNAME@$SERV "$ITGR"
ssh -f $SERVNAME@$SERV "iperf -s"  |  tee -a $SERVER
sudo modprobe tcp_probe port=5001 full=1
sleep 5s
sudo chmod 444 /proc/net/tcpprobe
sudo cat /proc/net/tcpprobe > tcpprobe.out &
TCPCAP=$!

sudo tcpdump -i $INT -w "tcpdump.dmp" &
sleep 3s

#ssh -f $SERVNAME@$SERV "cd Scrivania && ./scp_test.sh"
#scp 200MB.zip $SERVNAME@$SERV:Scrivania/ &
#D-ITG-2.8.1-r1023/bin/ITGSend -a 192.168.2.189 -sp 9400 -rp 9500 -t 10000 -j 1 -C 200 -c 1024 -l send.log &
#sleep 10s
#iperf -i 10 -t 90 -c $SERV | tee -a $CLIENT
iperf -c $SERV -F "200MB.zip"  -t 90 -i 10  | tee -a $CLIENT

sudo killall tcpdump #server

#killall scp
#ssh -f $SERVNAME@$SERV "killall scp"
#ssh -f $SERVNAME@$SERV "killall ITGRecv"
ssh -f  $SERVNAME@$SERV "killall iperf"
sudo kill $TCPCAP
sudo modprobe -r tcp_probe


##
#ssh -f $APNAME@$AP "rmmod slk"
#ssh -f $APNAME@$AP "killall slus && /usr/sbin/iptables -t mangle -F"
##


#sudo tc qdisc del dev $INT root

gnuplot plot

tcptrace -p tcpdump.dmp > aaaaa.txt
./adv_wnd aaaaa.txt bbbbb.txt 192.168.0.139
output="window.jpeg"
gnuplot -e "outputname='${output}'" window
rm aaaaa.txt bbbbb.txt