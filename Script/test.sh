#

##VARIABILI

RECNAME=giacomo
REC=192.168.2.178
DWN=4000kbit
RATE=4000kbit
INT=eth0
HOST=192.168.0.139
DL=100ms

echo "Start test"

##TC
# For bandwidth limitation
sudo tc qdisc add dev $INT root handle 1: htb default 1
sudo tc class add dev $INT parent 1: classid 1:1 htb rate $RATE ceil $DWN
sudo tc class add dev $INT parent 1: classid 1:2 htb rate $RATE ceil $DWN
sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip dst $HOST/32 flowid 1:1
sudo tc filter add dev $INT protocol ip parent 1:0 prio 1 u32 match ip src $HOST/32 flowid 1:2

# For delay (RTT) increment
sudo tc qdisc add dev $INT parent 1:1 handle 10: netem delay $DL
sudo tc qdisc add dev $INT parent 1:2 handle 20: netem delay $DL
sudo tc qdisc show

#esecuzione slus
./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_noslus_rtt_$DL_1.log" "test_recv_noslus_rtt_$DL_1.log"

#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_b512_rtt_$DL_1.log" "test_recv_slus_b512_rtt_$DL_1.log" "-b 512"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_b512_rtt_$DL_1.log" "test_recv_slk_b512_rtt_$DL_1.log" "up_bwt=512"

#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a100_rtt_$DL_1.log" "test_recv_slus_a100_rtt_$DL_1.log" "-a 100"
#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a200_rtt_$DL_1.log" "test_recv_slus_a200_rtt_$DL_1.log" "-a 200"
#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a400_rtt_$DL_1.log" "test_recv_slus_a400_rtt_$DL_1.log" "-a 400"
#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a600_rtt_$DL_1.log" "test_recv_slus_a600_rtt_$DL_1.log" "-a 600"
#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a800_rtt_$DL_1.log" "test_recv_slus_a800_rtt_$DL_1.log" "-a 800"
#./slus_exec_esp.sh "slus_testbed_test.txt" "test_send_slus_a1000_rtt_$DL_1.log" "test_recv_slus_a1000_rtt_$DL_1.log" "-a 1000"


#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a100_rtt_$DL_1.log" "test_recv_slk_a100_rtt_$DL_1.log" "adv_wnd=100"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a200_rtt_$DL_1.log" "test_recv_slk_a200_rtt_$DL_1.log" "adv_wnd=200"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a400_rtt_$DL_1.log" "test_recv_slk_a400_rtt_$DL_1.log" "adv_wnd=400"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a600_rtt_$DL_1.log" "test_recv_slk_a600_rtt_$DL_1.log" "adv_wnd=600"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a800_rtt_$DL_1.log" "test_recv_slk_a800_rtt_$DL_1.log" "adv_wnd=800"
#./slk_exec_esp.sh "slus_testbed_test.txt" "test_send_slk_a1000_rtt_$DL_1.log" "test_recv_sk_a1000_rtt_$DL_1.log" "adv_wnd=1000"


#scp pi@$REC:D-ITG-2.8.1-r1023/bin/test_recv*.log ./ #pi
scp $RECNAME@$REC:Scrivania/D-ITG-2.8.1-r1023/bin/test_recv*.log ./
sleep 5s

./slus_make_dir_all_plots.sh

sudo tc qdisc del dev $INT root

echo "END test";






