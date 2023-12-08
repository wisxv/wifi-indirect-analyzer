#!/bin/bash

# width can be "HT20" "HT40+" "HT40-" "80MHz"
width="${1}"
device="${2}"
channels="1 2 3 4 5 6 7 8 9 10 11 12 13"

sudo systemctl stop NetworkManager wpa_supplicant.service networking.service &&
sudo ip link set "${device}" down &&
iw dev "${device}" set monitor control &&
sudo rfkill unblock wifi &&
sudo ip link set "${device}" up &&

while true; do
	for channel in ${channels}; do
    		echo "Setting channel ${channel}, ${width}"
    		iw "dev ${device}" set channel "${channel}" "${width}"
    		sleep 0.1
	done
done
