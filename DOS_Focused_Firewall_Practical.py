import os # Used to interact with the Operating System
import sys # Handles system specific operations, such as exiting the script
import time # Will track time intervals
from collections import defaultdict # Used to store and manage packet counts for each IP address
from scapy.layers.inet import IP # Import the ability to monitor and analyse network packets
from scapy.all import sniff # Import the ability to monitor and analyse network packets


THRESHOLD = 40 # Creating a global variable to be used as the Packet Rate threshold
print(f"THRESHOLD: {THRESHOLD}") # Print to the console what the Threshold is

def packet_callback(packet): # Define the Packet Callback function
    src_ip = packet[IP].src # Grab the incoming IP and Packet data
    packet_count[src_ip] += 1 # Add 1x to the packet counter
    current_time = time.time() # set the Current time variable
    time_interval = current_time - start_time # Calculate the interval from the current time from the start time

    if time_interval >= 1: # If the time interval is greater than 1 execute the following code
        for ip, count in packet_count.items(): # Go through all of the ips and the packet counts to determine if any of the IPs are exceeding the threshold set earlier
            packet_rate = count / time_interval # calculate the packet rate. This is what will be compared to the threshold
            if packet_rate > THRESHOLD and ip not in blocked_ips: # If the packet rate exceeds the threshold and the ip is not already on the blocked ip list, then we are going to add that new IP to the list
                print(f"Blocking IP: {ip}, Packet Rate: {packet_rate}")
                os.system(f"iptables -A Input -s {ip} -j DROP")
                blocked_ips.add(ip)

        # The data below wipes the slate clean and resets the time and counter so that the firewall can restart the same process with the next suspicious IP address and network activity
        packet_count.clear()
        start_time = current_time

if __name__ == "__main__":
    if os.geteuid() != 0: # A UNIX only command
        print("This script must be run as root.") # a UNIX only comman
        sys.exit(1) # A UNIX only command

    # Defining a bunch of variables necessary for the firewall
    packet_count = defaultdict(int)
    start_time = [time.time()] # there is an issue with the localization of the start_time variable... it wont register in the packet_callback function
    blocked_ips = set()

    # Inform that the firewall has started and begin the monitoring via the sniffing
    print("Monitoring Network Traffic...")
    sniff(filter="ip", prn=packet_callback)




