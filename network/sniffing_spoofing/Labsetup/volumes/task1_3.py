from scapy.all import *

# def print_pkt(pkt):
#     pkt.show()

if __name__ == "__main__":
    # pkt = sniff(filte='src 182.61.200.6  and  ICMP', prn = print_pkt)
    
    dst = '182.61.200.6'
    src = ''
    ttl = 1
    a = IP(dst=dst)
    while src != dst:
          
        a.ttl = ttl
        p = sr1(a/ICMP(), timeout=2, verbose=False) # timeout超时退出， verbos=False不输出反馈信息到控制台
        if p != None:
            src = p.src
        else:
            src = "****"
        print('step%-2d:    %-10s' %(ttl, src))
        ttl += 1
        if ttl == 31: break
    