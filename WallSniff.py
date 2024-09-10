from scapy.all import sniff, TCP, IP, Raw
from scapy.all import *
import tkinter as tk
from tkinter import ttk

captured_packets = [] 

# Create the main window
window = tk.Tk()
window.title("WallSniff")

#Firewall Rules
firewall_rules = []

# Function to add a rule
def add_firewall_rule():
    ip = block_ip_entry.get()
    protocol = protocol_var.get()
    if ip or protocol:  # Only add if an IP or protocol is provided
        rule = {"ip": ip, "protocol": protocol}
        firewall_rules.append(rule)
        rules_listbox.insert(tk.END, f"Block IP: {ip} Protocol: {protocol}")

def remove_firewall_rule():
    selected_rule_index = rules_listbox.curselection()
    if selected_rule_index:
        firewall_rules.pop(selected_rule_index[0])  # Remove rule from list
        rules_listbox.delete(selected_rule_index)  # Remove from Listbox

# Function to handle packet filtering based on firewall rules
def firewall_packet_handler(packet):
    for rule in firewall_rules:
        # Check for IP match
        if rule["ip"] and packet.haslayer(IP) and packet[IP].src == rule["ip"]:
            blocked_listbox.insert(tk.END, f"Blocked: {packet.summary()}")
            return  # Drop the packet, do not process further

        # Check for protocol match
        if rule["protocol"]:
            if rule["protocol"] == "TCP" and packet.haslayer(TCP):
                blocked_listbox.insert(tk.END, f"Blocked: {packet.summary()}")
                return
            elif rule["protocol"] == "UDP" and packet.haslayer(UDP):
                blocked_listbox.insert(tk.END, f"Blocked: {packet.summary()}")
                return
    
    # If no rule matches, display packet summary
    allowed_listbox.insert(tk.END, packet.summary())

# Function to start sniffing with firewall rules applied
def start_firewall_sniffing():
    allowed_listbox.delete(0, tk.END)
    blocked_listbox.delete(0, tk.END)
    sniff(prn=firewall_packet_handler, iface="Wi-Fi", store=0,timeout=30)



# Function to process the captured packets
def packet_handler(packet):
    # Clears the firewall list
    captured_packets.append(packet)
    packet_listbox.insert(tk.END, packet.summary())
# Capture packets on network interface (default: all interfaces)
# count=0 means infinite packets, set count=N for a specific number of packets

def on_right_click(event):
    try:
        # Get the selected item index in the Listbox
        index = packet_listbox.nearest(event.y)
        packet_listbox.selection_set(index)  # Select the item
        
        # Get the actual packet associated with this listbox entry
        selected_packet = captured_packets[index]
        
        # Display the context menu
        context_menu = tk.Menu(window, tearoff=0)
        
        # Check if the selected packet has HTTP payload
        raw_data = selected_packet[Raw].load
        if b"GET" in raw_data or b"POST" in raw_data or b"HTTP" in raw_data:
            context_menu.add_command(label="Decode HTTP Payload", command=lambda: decode_http_payload(selected_packet))
        
        context_menu.post(event.x_root, event.y_root)  # Show the menu
    except IndexError:
        pass

def decode_http_payload(packet):
    raw_data = packet[Raw].load
    try:
        decoded_data = raw_data.decode('utf-8', errors='ignore')


        print(f"Decoded HTTP Payload: {decoded_data}")
    except UnicodeDecodeError:
        print("Error decoding payload")

def on_sniff_click():
    # Update label text
    packet_listbox.delete(0, tk.END)
    captured_packets.clear()
    protocol = selectProtocol.get()
    num_packets = int(selectNumPackets.get())
    filter_str = ""

    # Create filter string based on the selected protocol
    if protocol.lower() == "tcp":
        filter_str = "tcp"
    elif protocol.lower() == "udp":
        filter_str = "udp"
    elif protocol.lower() == "icmp":
        filter_str = "icmp"
    elif protocol.lower() == "arp":
        filter_str = "arp"
    elif protocol.lower() == "http":
        filter_str = "tcp port 80"
    # Add more protocols as needed
    else:
        filter_str = ""  # No filter

    # Capture packets with the specified filter
    sniff(prn=packet_handler, iface="Wi-Fi", count=num_packets, store=0, filter=filter_str)

def display_input():
    protocol = selectProtocol.get()
    num_packets = selectNumPackets.get()
    selected_protocol_label.config(text=f"Selected Protocol: {protocol}")
    selected_num_packets_label.config(text=f"Number of Packets: {num_packets}")

# Create a Notebook widget for tabs
notebook = ttk.Notebook(window)
notebook.pack(pady=10, expand=True)

# Create frames for each tab
snifferTab = tk.Frame(notebook, width=400, height=400)
firewallTab = tk.Frame(notebook, width=400, height=400)

snifferTab.pack(fill="both", expand=True)
firewallTab.pack(fill="both", expand=True)

notebook.add(snifferTab, text="Packet Sniffer")
notebook.add(firewallTab, text="Fire Wall")

# Packet list
packet_listbox = tk.Listbox(snifferTab, width=100, height=10)
packet_listbox.pack(pady=10)
packet_listbox.bind("<Button-3>", on_right_click)

# Create a frame for protocol selection and number of packets
input_frame = tk.Frame(snifferTab)
input_frame.pack(pady=5)

# Create a label and entry for selecting protocol
protocol_label = tk.Label(input_frame, text="Select Protocol:")
protocol_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

selectProtocol = tk.Entry(input_frame)
selectProtocol.grid(row=0, column=1, padx=5, pady=5)

# Label to display the selected protocol
selected_protocol_label = tk.Label(input_frame, text="Selected Protocol:")
selected_protocol_label.grid(row=0, column=2, padx=5, pady=5, sticky="w")

# Create a label and entry for selecting number of packets
num_packets_label = tk.Label(input_frame, text="Select Number of Packets:", anchor="w")
num_packets_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

selectNumPackets = tk.Entry(input_frame)
selectNumPackets.grid(row=1, column=1, padx=5, pady=5)

# Label to display the number of packets
selected_num_packets_label = tk.Label(input_frame, text="Number of Packets:")
selected_num_packets_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")

# Create a frame for buttons
button_frame = tk.Frame(snifferTab)
button_frame.pack(pady=10)

# Create submit button
submit_button = tk.Button(button_frame, text="Submit", command=display_input)
submit_button.pack(side="top", pady=5)

# Create sniff button
sniff_button = tk.Button(button_frame, text="Sniff", command=on_sniff_click)
sniff_button.pack(side="top", pady=5)


# Input for blocking IPs
block_ip_label = tk.Label(firewallTab, text="Block IP:")
block_ip_label.pack(anchor="w", padx=5, pady=5)
block_ip_entry = tk.Entry(firewallTab)
block_ip_entry.pack(anchor="w", padx=5)

# Dropdown for selecting protocol to block
protocol_label = tk.Label(firewallTab, text="Select Protocol to Block:")
protocol_label.pack(anchor="w", padx=5, pady=5)
protocol_var = tk.StringVar()
protocol_dropdown = ttk.Combobox(firewallTab, textvariable=protocol_var, values=["", "TCP", "UDP"])
protocol_dropdown.pack(anchor="w", padx=5)

# Add and remove buttons
add_rule_button = tk.Button(firewallTab, text="Add Rule", command=add_firewall_rule)
add_rule_button.pack(padx=5, pady=5)

remove_rule_button = tk.Button(firewallTab, text="Remove Rule", command=remove_firewall_rule)
remove_rule_button.pack(padx=5, pady=5)

# Listbox to display current rules
rules_listbox = tk.Listbox(firewallTab, width=50, height=5)
rules_listbox.pack(padx=5, pady=5)

# Buttons to start sniffing
start_sniff_button = tk.Button(firewallTab, text="Start Sniffing with Firewall", command=start_firewall_sniffing)
start_sniff_button.pack(pady=10)

# Listbox to display blocked packets
blocked_label = tk.Label(firewallTab,text="Blocked Packets")
blocked_label.pack(pady=5)
blocked_listbox = tk.Listbox(firewallTab, width=100, height=10)
blocked_listbox.pack(pady=10)

# Listbox to display allowed packets
allowed_label = tk.Label(firewallTab,text="Allowed Packets")
allowed_label.pack(pady=5)
allowed_listbox = tk.Listbox(firewallTab, width=100, height=10)
allowed_listbox.pack(pady=10)
# Start the GUI loop
window.mainloop()





