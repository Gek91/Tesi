#!/bin/bash

# Produce tutti i grafici dei log specificati
FILES="*recv*.log"

echo "START smdalp"

for f in $FILES
do
	./slus_plot.sh $f
done

echo "END smdalp"
