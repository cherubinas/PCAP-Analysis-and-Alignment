## PCAP Analysis and Alignment

This project aims to develop a system for capturing and analyzing network traffic during simulated cyberattacks.

## Team members

- Abraitis Martynas
- Jakolovaitė Diana 
- Kabišaitytė Evelina
- Luis Eivydas

## Description

This project simulates attacks on 2 virtual machines, where machine 1 is the threat actor and machine 2 is the target machine. Nmap scan is used as the specific exploit for attacking.

The project includes an automated script where it automatically creates an attacker machine and a target machine in the Gitlab environment, and it enables two tcpdump instances on two machines at the same time. Attacks are performed (Nmap scan) from machine 1 to machine 2 at the same time via Ansible. Target machine is left waiting to be attacked, and attacker performs an Nmap scan.Then the attack data flow is caught from machine 1 and machine 2. The data is retrieved in the captured data flow in PCAP (Packet Capture) format.
The Smith-Waterman algorithm is used to make incident detection and reconstruction in the PCAP. 

## How to run the script

An active GitLab account is required for automated virtual machine creation in the same environment; other than that, once the script is downloaded and able to run, everything is done automatically up to the point point of PCAP capture. Once those files are generated, the user is required to cut the PCAP file into smaller portions (for easier and faster analysis) and put them to the Smith-Waterman algorithm manually, using their preferred Python environment. The end result is a score of alignment. 
