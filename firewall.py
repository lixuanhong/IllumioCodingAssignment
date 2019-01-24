import csv
import json
from collections import defaultdict

class Firewall(object):

    def __init__(self, path):
        # create the data structure for firewall
        self.firewall = defaultdict(lambda: defaultdict(dict))

        # read data from csv file and store them into firewall
        with open(path, "r") as csv_file:
            content = csv.reader(csv_file)
            for row in content:
                direction, protocol, port, ip_address = row[0], row[1], row[2], row[3]
                # IP address in a range
                if "-" in ip_address:
                    startIP, endIP = ip_address.split("-")
                    # Add IP addresses extracted from IP range
                    if port not in self.firewall[direction][protocol]:
                        self.firewall[direction][protocol][port] = self.ipExtraction(startIP, endIP)
                    else:
                        self.firewall[direction][protocol][port] += self.ipExtraction(startIP, endIP)
                # Single IP address
                else:
                    if port not in self.firewall[direction][protocol]:
                        self.firewall[direction][protocol][port] = [ip_address]
                    else:
                        self.firewall[direction][protocol][port] += [ip_address]

        # Print firewall after reading data from csv file
        print(json.dumps(self.firewall, indent=4))

    # extract IP addresses from IP ranges
    def ipExtraction(self, startIP, endIP):
        start = list(map(int, startIP.split(".")))
        end = list(map(int, endIP.split(".")))
        tmp = start
        res = []
        res.append(startIP)

        while tmp != end:
            tmp[3] += 1
            for i in (3, 2, 1):
                if tmp[i] == 256:
                    tmp[i] = 0
                    tmp[i-1] += 1
            res.append(".".join(map(str, tmp)))
        return res


    def accept_packet(self, direction, protocol, port, ip_address):
        for port_range in self.firewall[direction][protocol]:
            # Port in a range
            if "-" in port_range:
                # Extract the start port and end port
                startPort, endPort = port_range.split("-")[0], port_range.split("-")[1]
                # If port in the port range
                if int(startPort) <= port <= int(endPort):
                    # If ip_address equals to one entry in the firewall, return True
                    for ip in self.firewall[direction][protocol][port_range]:
                        if ip == ip_address:
                            return True
            # Single port condition
            elif int(port_range) == port:
                # If ip_address equals to one entry in the firewall, return True
                for ip in self.firewall[direction][protocol][port_range]:
                    if ip == ip_address:
                        return True
        return False


# Driver/Test Code
fw = Firewall("rules.csv")
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
