# Traceroute and PathMTU tools
## Implemented with Dr. Mendes' specifications (Networks & Distributed Systems F 2019)

## What is Traceroute?
Traceroute is a tool included in most operating systems that displays the route between a source machine and a destination machine. 

## How does it work?
Traceroute sends a UDP datagram to the destination, but sets the Don’t Fragment (DF) IP flag and limits the IP Time To Live (TTL) to 1.

The first router along the way receives this UDP datagram and notices a TTL of 1. This prompts the router to send back an ICMP message of “Time Exceeded.”

Packets are then sent with incrementing TTL, and the sender will continue to receive “Time Exceeded” ICMP messages (Type 11, Code 0).

When the packet arrives at the expected destination, the machine will most likely send an “Destination Port Unreachable” ICMP message (Type 3, Code 3). This is an indication that the traceroute is complete, since the destination has been found.

## What is Path MTU?
PathMTU is another tool included in most operating systems that determines the maximum transmission unit on the route between a source machine and a destination machine.

## How does it work?
PathMTU sends a UDP datagram of 1500B to the destination, but sets the Don’t Fragment (DF) IP flag. Intermediary routers with an MTU smaller than the packet will drop it, and will send back an ICMP message "Fragmentation Needed" message (Type 3, Code 4).

The source machine then decreases its MTU and sends another UDP datagram.

The process continues until the packet is small enough to traverse from source to destination without any dropped packets. The machine will then send a “Destination Port Unreachable” ICMP message (Type 3, Code 3).
