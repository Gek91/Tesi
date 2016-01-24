#!/bin/bash
SERVNAME=giacomo
SERV=192.168.2.189
TIME=30
APNAME=root
AP=192.168.0.1
CLIENT=client_log
SERVER=server_log

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
#ssh -f $APNAME@$AP "insmod slk up_bwt=512"
#ssh -f $APNAME@$AP "slus -b 512"
##

echo " $(date)"  | tee -a $CLIENT $SERVER > /dev/null
echo "bandwidth 4000kbit/s delay 60ms time 30sec" | tee -a $CLIENT $SERVER > /dev/null

#START TCP
echo "START TCP";
echo "TCP"   | tee -a $CLIENT $SERVER >/dev/null

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_norm  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_norm.dmp &
sleep 3s
printf "\n\nTCP normale esecuzione\n" | tee -a $CLIENT $SERVER  > /dev/null
iperf -c $SERV -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_bialt  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_bialt.dmp &
sleep 3s
printf "\n\nTCP bidirezionale alternato\n" | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -r -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_bisim  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_bisim.dmp &
sleep 3s
printf "\n\nTCP bidirezionale simultaneo\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -d -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_2flus  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_2flus.dmp &
sleep 3s
printf "\n\nTCP 2 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 2 -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_3flus  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_3flus.dmp &
sleep 3s
printf "\n\nTCP 3 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 3 -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_4flus  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_4flus.dmp &
sleep 3s
printf "\n\nTCP 4 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 4 -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_5flus  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_5flus.dmp &
sleep 3s
printf "\n\nTCP 5 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 5 -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
sudo killall tcpdump
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s
#STAR TCP
echo "END TCP";

#UDP
echo "START UDP";
printf "\n\n\n\n UDP\n" | tee -a $CLIENT $SERVER > /dev/null

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_norm  > /dev/null &
sleep 5s
printf "\n\nUDP normale esecuzione\n"   | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -u -b 4000k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_bialt  > /dev/null &
sleep 5s
printf "\n\nUDP bidirezionale alternato\n" | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -r -u -b 4000k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_bisim  > /dev/null &
sleep 5s
printf "\n\nUDP bidirezionale simultaneo\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -d -u -b 4000k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_2flus  > /dev/null &
sleep 5s
printf "\n\nUDP 2 flussi\n" | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 2 -u -b 2000k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_3flus  > /dev/null &
sleep 5s
printf "\n\nUDP 3 flussi\n" | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 3 -u -b 1333k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_4flus  > /dev/null &
sleep 5s
printf "\n\nUDP 4 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 4 -u -b 1000k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"
sleep 5s

ssh -f $SERVNAME@$SERV "iperf -s -u -D -i 1"  |  tee -a $SERVER plot/UDP_5flus  > /dev/null &
sleep 5s
printf "\n\nUDP 5 flussi\n"  | tee -a $CLIENT $SERVER > /dev/null
iperf -c $SERV -P 5 -u -b 800k -t $TIME -i 1 | tee -a $CLIENT
sleep 3s
ssh -f  $SERVNAME@$SERV "killall iperf"

#END UDP
echo "END UDP";


##
#ssh -f $APNAME@$AP "rmmod slk"
#ssh -f $APNAME@$AP "killall slus && /usr/sbin/iptables -t mangle -F"
##

#Eliminazione del collo di bottiglia
sudo tc qdisc del dev $INT root #server
ssh -f $RECNAME@$REC "echo lubuntu | sudo -S tc qdisc del dev enp0s3 root" #client

./tcp_dump_plot.sh
