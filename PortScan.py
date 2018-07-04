#!/usr/local/bin/python2.7
import dpkt
import os
import sys
import socket
import random
import datetime

print "----------------------------------- \n PORT SCAN \n----------------------------------- \nBy Rishabh Das and Piyush Kayle(CPE 549) \n"

print "Please keep the .pcap file in the following directory (If already coppied please ignore the message) \n"
print os.getcwd()
#Function for getting the file
def find():
    list1=[]
    
    i=0
    for file in os.listdir(os.getcwd()):
        if file.endswith(".pcap"):
            list1.append(file)
            i+=1
    if i==0:
        print "No .pcap file found in the directory above \nPlease copy the files and then run the program \nExiting!!"
        sys.exit()
    else:
        print "\nThe .pcap files found in the directory are as follows:- \n"
        print list1
    print "\nType the name of the file on which scan detection is to be implemented (Type \"exit\" to quit) \n"
    filename= raw_input()
    count=0
    for name in list1:
        if name == filename:
            count +=1
        elif filename== "exit":
            sys.exit()
    if count==1:     
        scan(filename)
    else:
        print"Invalid File name!! \nPlease re-enter the name \n"
        find()
#Scan detection        
def scan(filenam):
    connect(filenam,0)
    null(filenam,0)
    udp(filenam,0)
    xmas(filenam,0)
    half(filenam,0)
    icmp_scan(filenam,0)

def connect(x,run):
    prin=0
    seq=0
    lock=0
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP: #check if it is TCP
                tcp=ip.data
                fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
                urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
                ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
                cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
                if syn_flag==True and ack_flag==False and tcp.sport>tcp.dport:
                    seq=1
                    if lock==0:
                        lock+=1
                        port_x=tcp.sport
                    port_s=tcp.sport
                    port_d=tcp.dport
                    if run==1:
                        print port_d,
                    
                if (rst_flag== True and ack_flag==True and seq==1 and port_s==tcp.dport and port_d==tcp.sport) :
                          prin+=1
                          seq=0
                          port_x =tcp.dport
                          continue
                elif (syn_flag== True and ack_flag==True and seq==1 and tcp.sport<tcp.dport and port_s==tcp.dport and port_d==tcp.sport):
                        seq=2
                elif rst_flag== True and seq==2 and tcp.sport<tcp.dport and port_s==tcp.sport and port_d==tcp.dport:
                        prin +=1
                        seq=0
                        port_x=tcp.sport
                        continue
                elif seq!=1:
                    seq=0
                    prin=0
                if tcp.sport>tcp.dport and prin >0 and port_x==tcp.sport:
                    prin=0
                
                if prin>=10 and run!=1:
                  print "Connect scan Detected!!\n"
                  print "Attacker Detected!!\nIP address is " + socket.inet_ntoa(ip.src)
                  print "Port Scanned are:\n"
                  run=1
                  break
    if prin==10:
        connect(x,run)
    if prin<10 and run!=1:
      print "No Connect Scan Detected!!"        
def null(x,run):
    prin=0
    seq=0
    sec=0
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP: #check if it is TCP
                tcp=ip.data
                fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
                urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
                ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
                cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
                if sec>0:
                    sec+=1
                if syn_flag== False and fin_flag==False and rst_flag== False and psh_flag==False and ack_flag==False and urg_flag==False and seq==0 and ece_flag==False and cwr_flag==False and tcp.sport>tcp.dport:
                    seq+=1
                    sec+=1
                    if run==1:
                              print tcp.dport,
                if (rst_flag== True and ack_flag==True and seq==1 ) :
                          prin+=1                          
                          seq=0
                          sec=0
                elif (tcp.sport>tcp.dport and syn_flag== False and fin_flag==False and rst_flag== False and psh_flag==False and ack_flag==False and urg_flag==False and ece_flag==False and cwr_flag==False and seq==1 and sec==2):
                          prin+=1
                          seq=1
                          sec=1                          
                elif sec>1:
                        prin =0
                        seq=0
                        sec=0
                if prin>=10 and run==0:
                  print "Null scan Detected!!"
                  print "Attacker Detected!!\nIP address is " + socket.inet_ntoa(ip.dst)
                  print "Port Scanned are:\n"
                  run=1
                  break
    if prin==10:
        null(x,run)
    if prin<10:
      print "No Null Scan Detected!!"
      
def udp(x,run):
    prin=0
    seq=0
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            tcp=ip.data
            if ip.p==dpkt.ip.IP_PROTO_UDP : #check if it is UDP
                seq+=1
                if run==1 and ip.p==dpkt.ip.IP_PROTO_UDP:
                  print tcp.dport,
            if ip.p==dpkt.ip.IP_PROTO_ICMP and seq==1:
                prin+=1
                seq=0
            elif ip.p==dpkt.ip.IP_PROTO_UDP and seq==2:
                seq=1
            elif ip.p!=dpkt.ip.IP_PROTO_UDP and ip.p!=dpkt.ip.IP_PROTO_TCP:
                seq=0
                prin=0
               
        if prin ==10 and run!=1:
            print "UDP scan Detected!!"
            print "Attacker Detected!!\nIP address is " + socket.inet_ntoa(ip.dst)
            print "Port Scanned are:\n"
            run=1
            break
    if prin==10:
        udp(x,run)
    if prin<10:
        print "No UDP scan is detected!!"
                
  
def xmas(x,run):
    prin=0
    seq=0
    
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP: #check if it is TCP
                tcp=ip.data
                fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
                urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
                ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
                cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
                if fin_flag==True and psh_flag==True and urg_flag==True and tcp.sport>tcp.dport:
                    seq+=1
                    if run==1:
                              print tcp.dport,
                if (rst_flag== True and ack_flag==True and seq==1 ) :
                          prin+=1
                          seq=0
                elif fin_flag==True and psh_flag==True and urg_flag==True and tcp.sport>tcp.dport and seq==2:
                    seq=1
                elif seq!=1:
                        prin =0
                        seq=0
                
                if prin==10 and run!=1:
                  print "Xmas scan Detected!!"
                  print "Attacker Detected!!\nIP address is " + socket.inet_ntoa(ip.dst)
                  print "Port Scanned are:\n"
                  run=1
                  break
    if prin==10:
        xmas(x,run)            
    if prin<10:
      print "No Xmas Scan Detected!!"

def half(x,run):
    prin=0
    seq=0
    lock=0
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP: #check if it is TCP
                tcp=ip.data
                fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
                syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
                rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
                psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
                ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
                urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
                ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
                cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
                if syn_flag==True and ack_flag==False and tcp.sport>tcp.dport:
                    seq=1
                    if lock==0:
                        lock+=1
                        port_x=tcp.sport
                    port_s=tcp.sport
                    port_d=tcp.dport
                    if run==1:
                        print port_d,
                    
                if (rst_flag== True and ack_flag==True and seq==1 and port_s==tcp.dport and port_d==tcp.sport) :
                          prin+=1
                          seq=0
                          port_x =tcp.dport
                          continue
                elif (syn_flag== True and ack_flag==True and seq==1 and tcp.sport<tcp.dport and port_s==tcp.dport and port_d==tcp.sport):
                        seq=2
                elif rst_flag== True and seq==2 and tcp.sport<tcp.dport and port_s==tcp.sport and port_d==tcp.dport:
                        prin +=1
                        seq=0
                        port_x=tcp.sport
                        continue
                elif seq!=1:
                    seq=0
                    prin=0
                if tcp.sport>tcp.dport and prin >0 and port_x!=tcp.sport:
                    prin=0
                
                if prin==10 and run!=1:
                  print "Half-open scan Detected!!"
                  print "Attacker Detected!!\nIP address is " + socket.inet_ntoa(ip.src)
                  print "Port Scanned are:\n"
                  run=1
                  break
    if prin==10:
        half(x,run)                        
    if prin<10:
      print "No Half-open Scan Detected!!"
      
def icmp_scan(x,run):
    prin=0
    seq=0
    a=0
    for ts, pkt in dpkt.pcap.Reader(open(x,'rb')):
        
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP: #Checking if it is IP Packet
            ip=eth.data
            if ip.p==dpkt.ip.IP_PROTO_ICMP:
                icmp = ip.data
                if icmp.type==8 and seq==0:
                    seq+=1
                    if run==1:
                        print socket.inet_ntoa(ip.src),
                        print socket.inet_ntoa(ip.dst)
                elif icmp.type==0 and seq==1:
                    prin+=1
                    seq=0
                else:
                    seq=0
                    prin=0
            else:
                seq=0
                
        if prin ==3 and run!=1:
            print "ICMP scan Detected!!"
            print "Source and destination IP of each ping are:"
            run=1
            break
    if prin==3:
        icmp_scan(x,run)
    if prin<3:
        print "No ICMP scan is detected!!"
def ip_convert( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r

#main body code   
find()
while 1:
    print"Do you want to continue?(Y/N) \n"
    answer= raw_input()
    if answer == 'Y' or answer =='y':
        find()
    elif answer == 'N' or answer =='n':
        sys.exit()
    else:
        print "Bad Input!!"
