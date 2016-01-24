#!/bin/bash
FILES="*.dmp"

for f in $FILES
do
tcptrace -p $f > aaaaa.txt
./slus_advwnd aaaaa.txt bbbbb.txt

output="window"_$f".jpeg"
gnuplot -e "outputname='${output}'" window
rm aaaaa.txt bbbbb.txt
done
rm *.dmp

