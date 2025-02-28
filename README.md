## PCAP Analysis and Alignment

This project aims to develop a system for capturing and analyzing network traffic during simulated cyberattacks.

## Team members

- [Abraitis Martynas](https://github.com/mmartiss)
- Jakolovaitė Diana 
- [Kabišaitytė Evelina](https://github.com/cherubinas)
- Luis Eivydas

## Description
This project simulates a cyber attack on 2 virtual machines, where machine 1 is the threat actor and machine 2 is the target machine. Nmap scan is used as the specific exploit for attacking.

The project includes a script that automatically creates an attacker machine and a target machine in the OpenNebula environment, enabling two tcpdump instances on two machines simultaneously. Attacks are performed (Nmap scan) from machine 1 to machine 2 simultaneously via Ansible . The target machine is left waiting to be attacked, and the attacker performs a Nmap scan. Then the attack data flow is caught from machine 1 and machine 2. The data is retrieved in the captured data flow in PCAP (Packet Capture) format. The Smith-Waterman } and The Needleman-Wunsch algorithms makes incident detection and reconstruction in the PCAP. 
## How to run the script

An active GitLab account is required for automated virtual machine creation in the same environment; other than that, once the script is downloaded and able to run, everything is done automatically up to the point point of PCAP capture. Once those files are generated, the user is required to cut the PCAP file into smaller portions (for easier and faster analysis) and put them to the Smith-Waterman algorithm manually, using their preferred Python environment. The end result is a score of alignment. 
