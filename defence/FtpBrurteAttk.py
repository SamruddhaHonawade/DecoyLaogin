from scapy.all import*

FTPconns = {}
failedFTP = {}

def FTPAnalysis(p):
    vals = p[Raw].load.strip()
    src = p[IP].src
    DST = P[IP].dst
    port = p[TCP].sport
    if vals[0] ==b"USER":
        #storing ips in key dic
        key="%s->%s" % (src,dst) #client -> server
        if not key in FTPconns:
            FTPconns[key] = {}
        FTPconns[key][port] = [vals[1].decode("utf-8"),"login"]
    elif vals[0] == b"PASS" :
        key="%s->%s" % (src,dst)
        if  key in FTPconns:
            if port in FTPconns[key]:
                FTPconns[key][port][1]="pass"
            else:
                print("Anomalous FTP PASS (%s) %s:%s" % (vals[1],key,port))
    elif vals[0] == b"530" :
        #530 is means Faild Login attempt
        key="%s->%s" % (src,dst) #server -> client
        port = p[TCP].dport
        if key in FTPconns[key]:
            v = FTPconns[key].pop(port)
            if v[0] in failedFTP:
                failedFTP[v[0]] += 1
            else:
                failedFTP[v[0]] =1

SSHconns ={}
faildSSH ={}
threshold = 5000

def analyzePacket(p):
    if p.haslayer(TCP):
        if(p[TCP].sport == 21 or p[TCP].dport ==21) and p.haslayer(Raw):
            FTPAnalysis(p)
        elif (p[TCP].sport == 22):
            SSHAnalysis(p)

def printResult(openConns,failed,protocol):
    print("open %s Connections: % protocol")
    for conn in openConns:
        c = openConns[conn]
        if len(c) > 0:
            print(conn)
            for p in c:
                print("\t port : %s User: " %(p,c[p]))
    print("Failed %S Logins: "% protocol)
    for f in failed:
        print("\t%s: %d" % (f,failed[f]))
        

