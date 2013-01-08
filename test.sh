#!/bin/bash -xv

sudo ip rule del fwmark 1 lookup 100
sudo ip route flush table 100
sudo ip netns exec ns0 ip link del veth0
sudo ip netns del ns0

sudo ip link add type veth
sudo ip netns add ns0
sudo ip link set veth0 netns ns0
sudo ip netns exec ns0 ip link set veth0 up
sudo ip link set veth1 up
sudo ip address add 192.168.11.1/24 dev veth1
sudo ip netns exec ns0 ip address add 192.168.11.2/24 dev veth0
sudo ip netns exec ns0 ip route add default via 192.168.11.1 dev veth0
sudo ip route add local default dev veth1 table 100
sudo ip rule add fwmark 1 lookup 100
