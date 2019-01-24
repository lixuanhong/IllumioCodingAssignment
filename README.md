# Illumio Firewall Challenge
## Coding Assumption
The PDF file suggests that the input file contains only valid, well-formed entries. Therefore, I didn't write extra codes to check the form validation of IP, port, entries and etc.

## Solution
I created a nested dictionary/json to store the rules read from csv file as follows. The space complexity is O(n) where n is the number of IP addresses possible. An auxiliary function is created to extract IP address if the IP is given in a range.
{direction: {protocol: {port/port_range: [ip addresses]}}}

The idea is that I first check if the port in the range of or equals to values in firewall["direction"]["protocol"]; If yes, then I further check whether ip_address equals to one entry in firewall["direction"]["protocol"]["port"]. It is convenient to look up whether an entry satisfies the rules stored in firewall. The time complexity is O(1).

## Test
 I created a csv file based on given rules. The code is tested using the sample entries. It works as expected.

## Team Preference
1. Data  
2. Platform
3. Policy
