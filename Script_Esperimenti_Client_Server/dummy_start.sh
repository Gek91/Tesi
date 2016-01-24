#!/bin/bash

sudo ipfw pipe 1 config bw 512KByte/s delay 45ms
sudo ipfw add pipe 1 ip from any to any
sudo ipfw show
sudo ipfw pipe 1 show