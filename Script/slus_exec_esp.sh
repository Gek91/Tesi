#
# Creato da Giacomo Pandini partendo da un lavoro iniziale di Matteo Brunati
#
# Lo script esegue le configurazioni necessarie per il test di SLUS: SAP-LAW User Space oltre ad eseguire il programma stesso.
# Riceve in ingresso 4 parametri:
# - Nome del file contenente le informazioni sui flussi da generare con D-ITG
# - Il nome del file di output prodotto dal server
# - Il nome del file di output prodotto dal client
# - Parametri per l'esecuzione di SLUS
#

#Variabili
RECNAME=giacomo
REC=192.168.2.178
AP=root@192.168.0.1
ITGR="cd Scrivania/D-ITG-2.8.1-r1023/bin/ && ./ITGRecv"
ITGS=../D-ITG-2.8.1-r1023/bin/ITGSend
INT=eth0
#Parametri in ingresso
ditg_script=$1
ditg_serv_log_file=$2
ditg_client_log_file=$3
slus_param=$4

#Esecuzione del programma di ricezione sul client
ssh -f $RECNAME@$REC "$ITGR"
sleep 3s

ssh -f  $AP "slus $slus_param"
sleep 3s
#Esecuzione di tcpdump
sudo tcpdump -i $INT -w $ditg_client_log_file".dmp" &
sleep 3s
#Esecuzione del programma di invio sul server
$ITGS $ditg_script -l $ditg_serv_log_file -x $ditg_client_log_file &
sleep 200s
#Terminazione di tcpdump
sudo killall tcpdump
sleep 3s

ssh -f $AP "killall slus && /usr/sbin/iptables -t mangle -F"
sleep 3s
#Terminazione del programma di ricezione sul client
ssh -f $RECNAME@$REC "killall ITGRecv"
sleep 3s
