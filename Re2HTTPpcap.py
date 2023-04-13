from scapy.all import *
from scapy.utils import wrpcap
from scapy.layers.inet import IP, TCP ,Ether
from scapy.layers.http import HTTPRequest, HTTPResponse

# 定义目标 IP 和端口号

src_mac = "c0:25:a5:80:a4:79"
dst_mac = "c0:26:a5:80:a4:79"
http_request_prv = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
http_response_prv = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def fix_content_length(request_body):
    content_length = re.search(r'Content-Length: (\d+)', request_body)
    request_body = request_body.replace('\n', '\r\n')
    if content_length:
        if request_body[0:3] == 'GET':
            request_body = re.sub(r'Content-Length: \d+', 'Content-Length: {}'.format(0), request_body)
            return request_body
        expected_length = int(content_length.group(1))
        try:
            body = request_body.split('\r\n\r\n', 1)[1]
            actual_length = len(body)
        except:
            request_body+= "\r\n\r\n"
            actual_length = 0
        
        if actual_length != expected_length:
            request_body = re.sub(r'Content-Length: \d+', 'Content-Length: {}'.format(actual_length), request_body)
            request_body = re.sub(r'Content-MD5: .*', '', request_body)  # update the Content-MD5 header
            request_body = re.sub(r'Content-Encoding: .*', '', request_body)  # update the Content-Encoding header
    return request_body


def creat_http_pcap(http_request=http_request_prv,http_response=http_response_prv,src_ip = "172.1.1.1",src_port = 5000,dst_ip = "172.1.1.2",dst_port = 80,pcapname='out'):
    ipsrc= Ether(src=src_mac,dst=dst_mac)/IP(src=src_ip,dst=dst_ip)
    ipdst = Ether(src=dst_mac,dst=src_mac)/IP(src=dst_ip,dst=src_ip)
    seq =random.randint(10,5000)
    seq2 =random.randint(10,5000)
    src_port = random.randint(20000,50000)
    # 构造SYN数据包
    syn_packet = ipsrc/TCP(sport=src_port,dport=dst_port, seq=seq,flags="S")

    # 构造SYN/ACK数据包
    syn_ack_packet = ipdst/TCP(sport=dst_port,dport=src_port, flags="SA", seq=seq2, ack=syn_packet[TCP].seq + 1)

    # 构造ACK数据包
    ack_packet = ipsrc/TCP(sport=src_port,dport=dst_port, flags="A", seq=syn_ack_packet[TCP].ack, ack=syn_ack_packet[TCP].seq + 1)

    # 构造HTTP请求报文
    #http_request = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
    http_request_packet = ipsrc/TCP(sport=src_port,dport=dst_port, flags=24, seq=ack_packet[TCP].seq, ack=syn_ack_packet[TCP].seq + 1)/http_request.encode()


    httpack = ipdst/ TCP(sport=dst_port,dport=src_port, seq=http_request_packet[TCP].ack,ack=http_request_packet[TCP].seq + len(http_request), flags='A')

    # 构造HTTP响应报文
    #http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    http_response_packet = ipdst/TCP(sport=dst_port,dport=src_port, flags=24, seq=httpack[TCP].seq, ack=httpack[TCP].ack  )/http_response.encode()



    # 四次挥手 客户端发起
 
    fin_packet = ipsrc/TCP(sport=src_port, dport=dst_port, flags="FA", seq=http_response_packet[TCP].ack, ack=http_response_packet[TCP].seq+len(http_response))

    ack_packet_close = ipdst/TCP(sport=dst_port, dport=src_port, flags="A",seq=fin_packet[TCP].ack, ack=fin_packet[TCP].seq + 1)

    ack_packet_close2 = ipdst/TCP(sport=dst_port, dport=src_port, flags="FA",seq=ack_packet_close[TCP].seq, ack=fin_packet[TCP].seq + 1)

    fin_packet_ack = ipsrc/TCP(sport=src_port, dport=dst_port, flags="A",seq= ack_packet_close2[TCP].ack, ack=ack_packet_close2[TCP].seq + 1)

    # # 构造FIN数据包
    # fin_packet = ipdst/TCP(sport=dst_port,dport=src_port, flags="FA", seq=http_response_packet[TCP].seq+ len(http_response), ack=http_response_packet[TCP].ack)

    # # 构造ACK数据包
    # ack_packet_close = ipsrc/TCP(sport=src_port,dport=dst_port, flags="A", seq=fin_packet[TCP].ack, ack=fin_packet[TCP].seq + 1)

    # # 构造FINACK数据包
    # ack_packet_close2 = ipsrc/TCP(sport=src_port,dport=dst_port, flags="FA",seq=ack_packet_close[TCP].seq, ack=fin_packet[TCP].seq + 1)

    # # 构造ACK数据包
    # fin_packet_ack = ipdst/TCP(sport=dst_port,dport=src_port, flags="A", seq= ack_packet_close2[TCP].ack, ack=ack_packet_close2[TCP].seq + 1)

    # 构造RST数据包
    #rst_packet = Ether(src=src_mac,dst=dst_mac)/IP(src=src_ip,dst=dst_ip)/TCP(sport=src_port,dport=dst_port, flags="R", seq=fin_packet[TCP].seq + 1, ack=ack_packet[TCP].ack)

    # 将数据包列表合并为一个流量报文
 
    http_traffic = [syn_packet, syn_ack_packet, ack_packet, http_request_packet, httpack,http_response_packet, fin_packet, ack_packet_close,ack_packet_close2,fin_packet_ack]

    # 将流量报文保存到本地为 .pcap 文件
    wrpcap(pcapname+'.pcap', [http_traffic])


if __name__ == "__main__":
    dir_path = r""
    dir_list = os.listdir(dir_path)
    for i in dir_list:
        
        f = open(dir_path+"\\"+i,'r')
        req = f.read()
        reqfix = fix_content_length(req)
        creat_http_pcap(reqfix,pcapname=r''+i)