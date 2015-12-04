#!/bin/bash

#
# Creato da Giacomo Pandini partendo da un lavoro iniziale di Matteo Brunati
#
# Lo scritp stampa i risultati ottenuti dall'esecuzione del test utilizzando GNUPLOT.
# Ritorna grafici inerenti packetloss, delay, jitter, bitrate, inter arrival time, e la grandezza della advertised window
#

#Paramentri in ingresso
log_file=$1
#Variabili
ditg_dec=../D-ITG-2.8.1-r1023/bin/ITGDec
newpart=${log_file%%.*}
interesting_flows="1 2"

#Creazione dei file dat del flusso
echo "Analyzing log file"
$ditg_dec $log_file > result_$newpart.txt
$ditg_dec $log_file -s split
$ditg_dec $log_file -b 1000
$ditg_dec $log_file -j 1000
$ditg_dec $log_file -d 1000
$ditg_dec $log_file -p 1000

#Stampa risultati
#packetloss
output="packetloss"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" packetloss
#jitter
output="jitter"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" jitter
#bitrate
output="bitrate"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" bitrate
#delay
output="delay"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" delay
#inter arrival time
for flow in $interesting_flows
do
$ditg_dec $flow*.split.dat -o $flow
./iat_file_create $flow iat_out
output="iat_pack"_$log_file"_"$flow".jpeg"
gnuplot -e "outputname='${output}'" iat_pack
output="iat_sec"_$log_file"_"$flow".jpeg"
gnuplot -e "outputname='${output}'" iat_sec
rm $flow
rm iat_out
done
# advertised window server
tcptrace -p $log_file".dmp" > aaaaa.txt
./slus_advwnd aaaaa.txt bbbbb.txt
output="window_server"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" window
rm aaaaa.txt bbbbb.txt
# advertised windows client
tcptrace -p client_${log_file}.dmp > aaaaa.txt
./slus_advwnd aaaaa.txt bbbbb.txt
output="window_client"_$log_file".jpeg"
gnuplot -e "outputname='${output}'" window
rm aaaaa.txt bbbbb.txt

echo "Removing temporary files"
rm *.dat




