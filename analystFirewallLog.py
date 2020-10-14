import re
import sys
import argparse
regex = r"(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^224\.)"
class logFirewall:
    def __init__(self, date, time, action, protocol, src_ip, dst_ip, src_port, dst_port, size, tcpflags, tcpsyn, tcpack, tcpwin, icmptype, icmpcode, info, path):
        self.date = date
        self.time = time
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.size = size
        self.tcpflags = tcpflags
        self.tcpsyn = tcpsyn
        self.tcpack = tcpack
        self.tcpwin = tcpwin
        self.icmptype = icmptype
        self.icmpcode = icmpcode
        self.info = info
        self.path = path      
def getIP(file,action):
    listIP = []
    with open(file) as fp: 
        Lines = fp.readlines() 
        for line in range(5,len(Lines)): 
            logStrip = Lines[line].strip().split()
            logF = logFirewall(logStrip[0],logStrip[1],logStrip[2],logStrip[3],logStrip[4],logStrip[5],logStrip[6],logStrip[7],logStrip[8],logStrip[9],logStrip[10],logStrip[11],logStrip[12],logStrip[13],logStrip[14],logStrip[15],logStrip[16])
            pattern = re.compile(regex)
            if logF.action != action and not pattern.match(logF.dst_ip) :
                listIP.append(logF)
    return listIP
def main():
    parser = argparse.ArgumentParser(description='Option')
    parser.add_argument('--filename', dest='filename', default='pfirewall.log', action='store')
    parser.add_argument('--action', dest='action', default='ALLOW', action='store')
    args = parser.parse_args()
    fileName = args.filename
    action = args.action
    result = getIP(fileName,action)
    unique_dstIP = []
    unique_log = []
    for i in result:
        if i.dst_ip not in unique_dstIP:
            unique_dstIP.append(i.dst_ip)
            unique_log.append(i)
    for i in unique_log:
        print("Source IP: {} -> Destination IP: {}" .format(i.src_ip, i.dst_ip))    
    
main()