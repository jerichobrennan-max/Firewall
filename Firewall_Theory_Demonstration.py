import random #used later on for eventIDs

def generate_random_ip(): #This function generates random IP addresses for the Firewall to evaluate
    return f"192.168.1.{random.randint(0,255)}"

def check_firewall_rules(ip, rules): # This function takes in an IP and the rules, and checks the IP against the rules aka Eval + Action
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "Allow"



def main(): #This is the main function
    firewall_rules = { # Setting the Firewall rules library or index
        "192.168.1.1": "block",
        "192.168.1.4": "block",
        "192.168.1.9": "block",
        "192.168.1.13": "block",
        "192.168.1.16": "block",
        "192.168.1.19": "block",
    }

    for _ in range(12): #The For Loop that runs the Firewall essentially
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, firewall_rules)
        random_number = random.randint(1, 9999)
        print(f"IP: {ip_address} | Action: {action} | Random Number: {random_number}")

if __name__ == "__main__": # the command that ensures the main function runs
    main()

