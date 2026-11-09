import socket, ssl, datetime, csv

with open('hosts.txt', 'r') as hosts:
    for host in hosts:
        print(host.strip())