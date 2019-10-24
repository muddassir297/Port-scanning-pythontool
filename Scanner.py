#Nmap scanning using python 3
import nmap
import socket 

scanner = nmap.PortScanner()

print("Port scan tool using python")
print("<====================================================>")

hostname = input("Please enter the Hostname you would like to scan: ")
ip_addr = socket.gethostbyname(hostname) 

print("The IP you entered is: ", ip_addr)

type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                 1) TCP SYN scan -sS
                 2) TCP connect scan -sT
                 3) UDP scan – sU
                 4) Comprehensive Scan 
                 5) Agressive Scan
                 6) Intense scan plus UDP
                 7) TCP-FIN-Scan
                 8) TCP-NULL-Scan
                 9) TCP-Xmas-Scan
                 10) Maimon scan     \n""")

port_array=[]

if resp == '1':
    scanner.scan(ip_addr, '1-1024', '-v -sS -T4')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '2':
    scanner.scan(ip_addr, '1-1024', '-v -sT -T4')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '3':
    scanner.scan(ip_addr, '1-1024', '-v -sU -T4')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_udp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].udp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].udp(port_array[i])['name']+"\n")  
    print("<====================================================>")

elif resp == '4':
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '5':
    scanner.scan(ip_addr, '1-1024', '-v -sV -O -sS -T5')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '6':
    scanner.scan(ip_addr, '1-1024', '-sS -sU -T4 -A -v')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")

    if (scanner[ip_addr].all_tcp()):
        port_array=[]
        port_array= scanner[ip_addr].all_tcp()
        print("<================Port Scan report====================>")
        print("Status "+ "Port "+ "Services")
        for i in range(len(port_array)):
            print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")  

    if (scanner[ip_addr].all_udp()):
        port_array=[]
        print("<====================================================>"+"\n")
        port_array= scanner[ip_addr].all_udp()
        print("<================Port Scan report====================>")
        print("Status "+ "Port "+ "Services")
        for i in range(len(port_array)):
            print(scanner[ip_addr].udp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].udp(port_array[i])['name']+"\n")  
        print("<====================================================>")

elif resp == '7':
    scanner.scan(ip_addr, '1-1024', '-sN -T4 -A -v')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '8':
    scanner.scan(ip_addr, '1-1024', '-sF -T4 -A -v')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '9':
    scanner.scan(ip_addr, '1-1024', '-sX -T4 -A -v')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp == '10':
    scanner.scan(ip_addr, '1-1024', '-sM -T4 -A -v')
    print("<===============Scanner Info====================>")
    print(scanner.scaninfo())
    print("<====================================================>")
    print("IP Status: ", scanner[ip_addr].state())
    print("<====================================================>")
    print("Protocal: ", scanner[ip_addr].all_protocols())
    print("<====================================================>"+"\n")
    port_array= scanner[ip_addr].all_tcp()
    print("<================Port Scan report====================>")
    print("Status "+ "Port "+ "Services")
    for i in range(len(port_array)):
        print(scanner[ip_addr].tcp(port_array[i])['state'] +"   "+ str(port_array[i]) + "    " +scanner[ip_addr].tcp(port_array[i])['name']+"\n")    
    print("<====================================================>")

elif resp >= '11':
    print("Please enter a valid option")