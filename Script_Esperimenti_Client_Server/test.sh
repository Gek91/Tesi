#!/bin/bash


##Client info
RECNAME=giacomo
REC=192.168.2.178



echo "Start test"

##TC server
./tc_start.sh

#TC client
ssh -f $RECNAME@$REC "cd Scrivania && echo lubuntu | sudo -S ./tc_start.sh"

#Dummynet server
./dummy_start.sh

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

#Eliminazione del collo di bottiglia

#TC
sudo tc qdisc del dev $INT root #server
ssh -f $RECNAME@$REC "echo lubuntu | sudo -S tc qdisc del dev enp0s3 root" #client
#Dummynet
sudo ipfw -f flush

#Trasferimento risultati
scp $RECNAME@$REC:Scrivania/D-ITG-2.8.1-r1023/bin/*.dmp ./
scp $RECNAME@$REC:Scrivania/*.log ./
scp $RECNAME@$REC:Scrivania/D-ITG-2.8.1-r1023/bin/test_recv*.log ./
sleep 5s

#Stampa risultati
./slus_make_dir_all_plots.sh

rm *.log
rm *.dmp

echo "END test";






