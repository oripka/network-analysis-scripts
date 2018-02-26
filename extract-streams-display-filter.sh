#!/bin/bash
#
filter="$1"
input="$2"
output="$3"


# for windows to ignore carriage return no to mess up echo output
#export SHELLOPTS
#set -o igncr

stream_filter=""
for s in `tshark -r "$input" -2 -R "$filter" -T fields -e tcp.stream`; do
	stream_filter="$stream_filter tcp.stream==$s or "
done

fixed_stream_filter=$(echo  $stream_filter | sed 's/ or$//g')

echo "Extracting streams with display filter: $fixed_stream_filter"

tshark -r "$input" -Y "$fixed_stream_filter" -w "$output"
