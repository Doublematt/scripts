import pcapy
import datetime

print("Network script")
print("Printing interfaces...")

interfaces = pcapy.findalldevs()

for interface in interfaces:
    print(interface)


chosen_interface = input("Enter interface name to sniff: ")
cap = pcapy.open_live(chosen_interface, 65536, 1, 0)

print("sniffing the interface: ", chosen_interface)

while True:
    (header, payload) = cap.next()
    print(" %s: captured %d bytes" % (datetime.datetime.now(), header.getlen(),))
