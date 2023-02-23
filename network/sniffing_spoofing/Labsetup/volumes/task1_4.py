from scapy.all import *

def deal_pkt(pkt):
    # print(type(pkt))
    # print(pkt.getlayer(ICMP))
    # print(pkt.getlayer(ICMP).type)
    # print(pkt)
    
    if pkt.getlayer(ICMP).type == 8: # 8表示echo hello
        # 构建IP()层
        a = IP()
        a.dst = pkt.getlayer(IP).src
        a.src = pkt.getlayer(IP).dst 
        # a.src = '7.7.7.7'
        # 构建ICMP()层，注意 request 和 reply的报文，其标识符、代码、序号、Raw都是一样的
        b = ICMP()
        b.type = 0 # 0表示reply
        b.id = pkt.getlayer(ICMP).id # 标识符
        b.code = pkt.getlayer(ICMP).code # 代码
        b.seq = pkt.getlayer(ICMP).seq  # 序号
        str = pkt.getlayer(Raw).load    # 
        p = a/b/Raw(str) 
        send(p)
            
        print('the spoofing pkt #########')
        p.show()

if __name__ == "__main__":
    sniff(filter="icmp", prn=deal_pkt)