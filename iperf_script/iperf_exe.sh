#!/bin/bash
SERVNAME=giacomo
SERV=192.168.2.178
TIME=30
APNAME=root
AP=192.168.0.1
CLIENT=client_log
SERVER=server_log
INT=eth0


##
ssh -f $APNAME@$AP "insmod slk up_bwt=512"
#ssh -f $APNAME@$AP "slus -b 512"
##

echo " $(date)"  | tee -a $CLIENT $SERVER > /dev/null
echo "bandwidth 4000kbit/s delay 60ms time 30sec" | tee -a $CLIENT $SERVER > /dev/null

#START TCP
echo "START TCP";
echo "TCP"   | tee -a $CLIENT $SERVER >/dev/null

ssh -f $SERVNAME@$SERV "iperf -s -D -i 1" |  tee -a $SERVER plot/TCP_norm  > /dev/null &
sleep 5s
sudo tcpdump -i $INT -w TCP_DUMP/TCP_norm.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_bialt.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_bisim.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_2flus.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_3flus.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_4flus.dmp &
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
sudo tcpdump -i $INT -w TCP_DUMP/TCP_5flus.dmp &
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
ssh -f $APNAME@$AP "rmmod slk"
#ssh -f $APNAME@$AP "killall slus && /usr/sbin/iptables -t mangle -F"
##

TCP_DUMP/tcp_dump_plot.sh
