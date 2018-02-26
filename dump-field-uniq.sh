#!/bin/bash

myfile=$1
filter=$2

echo "Dumping $myfile with filter $filter"

bytes=`tshark -r "$myfile" -T fields -e "$filter" |sort -nr |uniq|sed '/^$/d'|tr -d '\r\n'`
echo $bytes