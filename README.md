# Traceroute-PathMTU-Clones

## What is Traceroute?
Traceroute is a tool included in most operating systems that displays the route between your machine and a destination machine. 

## How does it work?
Traceroute sends a UDP datagram to the destination, but sets the Don’t Fragment (DF) IP flag and limits the IP Time To Live (TTL) to 1.

The first router along the way receives this UDP datagram and notices a TTL of 1. This prompts the router to send back an ICMP message of “Time Exceeded.”

Packets are then sent with incrementing TTL, and the sender will continue to receive “Time Exceeded” ICMP messages (Type 11, Code 0).

When the packet arrives at the expected destination, the machine will most likely send an “Destination Port Unreachable” ICMP message (Type 3, Code 3). This is an indication that the traceroute is complete, since the destination has been found.
