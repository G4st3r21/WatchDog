from OpenSSL import SSL
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
from scapy.layers import tls
import gzip

from scapy.packet import Raw

from PacketAnalyzer.ProtocolHelper import ProtocolHelper


class PacketAnalyzer:
    @staticmethod
    def analyze_packet(packet):
        ether_packet = Ether(packet)
        ip_pkt = ether_packet.payload
        transport_layer_name = ip_pkt.payload.name

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        match transport_layer_name:
            case 'TCP':
                src_port = ip_pkt.payload.sport
                dst_port = ip_pkt.payload.dport
            case 'UDP':
                src_port = ip_pkt.payload.sport
                dst_port = ip_pkt.payload.dport
            case 'ICMP':
                src_port = None
                dst_port = None
            case _:
                print(f"Unknown transport protocol: {transport_layer_name}")
                src_port = None
                dst_port = None

        application_name, payload = PacketAnalyzer.analyze_application_layer(packet)

        return {
            "ips": [src_ip, dst_ip],
            "ports": [src_port, dst_port],
            "transport": transport_layer_name,
            "application": application_name,
            "payload": payload
        }

    @staticmethod
    def analyze_application_layer(packet):
        application_layer_name = ProtocolHelper.get_application_layer_name(packet)
        match application_layer_name:
            case "HTTP":
                return "HTTP", PacketAnalyzer.analyze_http_packet(packet)
            case "HTTPS":
                return "HTTPS", PacketAnalyzer.analyze_https_packet(packet)
            case "FTP":
                return "FTP", PacketAnalyzer.analyze_ftp_packet(packet)
            case "DNS":
                return "DNS", PacketAnalyzer.analyze_dns_packet(packet)
            case "SMTP":
                return "SMTP", PacketAnalyzer.analyze_smtp_packet(packet)
            case "POP3":
                return "POP3", PacketAnalyzer.analyze_pop3_packet(packet)
            case "IMAP":
                return "IMAP", PacketAnalyzer.analyze_imap_packet(packet)
            case "SSH":
                return "SSH", PacketAnalyzer.analyze_ssh_packet(packet)
            case "TELNET":
                return "TELNET", PacketAnalyzer.analyze_telnet_packet(packet)
            case "UNDEFINED":
                return "UNDEFINED", -1

    @staticmethod
    def analyze_http_packet(packet):
        packet_str = packet.decode("utf-8", errors="replace")
        lines = packet_str.strip().split("\r\n")
        method, uri, version = lines[0].split()[-4:-1]
        method = method[-3:]
        headers = "\n".join(lines[1:]) + "\n"
        body = b""
        for line in lines[1:]:
            if line.startswith("Content-Encoding:"):
                encoding_type = line.split(":")[1].strip().lower()
                if encoding_type == "gzip":
                    body = gzip.decompress(body)
                    break

        return "\n\n".join([method, uri, version, headers, str(body, "utf-8")])

    @staticmethod
    def analyze_https_packet(packet):
        print("Analysing https packet")
        tls_pkt = packet[tls.TLS]
        host_name = ''
        decrypted_data = ''

        if isinstance(tls_pkt, tls.TLSClientHello):
            for extension in tls_pkt.extensions:
                if isinstance(extension, tls.TLSExtensionServerName):
                    for name in extension.servernames:
                        host_name = name.decode("utf-8")
                        break

        if host_name:
            print("host name found")
            tls_pkt = packet[TCP][Raw]
            try:
                ctx = SSL.Context(SSL.SSLv23_METHOD)
                # Установите необходимые параметры контекста (сертификаты, ключи и т.д.)
                ctx.set_cipher_list('AES256-SHA')  # Укажите подходящий алгоритм шифрования
                ssl_sock = SSL.Connection(ctx)
                ssl_sock.set_tlsext_host_name(host_name)  # Укажите имя хоста из клиентского приветствия
                ssl_sock.set_connect_state()
                ssl_sock.send(tls_pkt.load)
                decrypted_data = ssl_sock.recv()
                ssl_sock.close()
            except SSL.Error:
                pass

        if decrypted_data:
            print("decrypted data found")
            packet_str = decrypted_data.decode("utf-8", errors="replace")
            lines = packet_str.strip().split("\r\n")
            method, uri, version = lines[0].split()[-4:-1]
            method = method[-3:]
            headers = "\n".join(lines[1:]) + "\n"
            body = b""
            for line in lines[1:]:
                if line.startswith("Content-Encoding:"):
                    encoding_type = line.split(":")[1].strip().lower()
                    if encoding_type == "gzip":
                        body = gzip.decompress(body)
                        break

            return "\n\n".join([method, uri, version, headers, str(body, "utf-8")])
        return ""

    @staticmethod
    def analyze_ftp_packet(payload):
        return ""

    @staticmethod
    def analyze_dns_packet(payload):
        return ""

    @staticmethod
    def analyze_smtp_packet(payload):
        return ""

    @staticmethod
    def analyze_pop3_packet(payload):
        return ""

    @staticmethod
    def analyze_imap_packet(payload):
        return ""

    @staticmethod
    def analyze_ssh_packet(payload):
        return ""

    @staticmethod
    def analyze_telnet_packet(payload):
        return ""
