from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS
from scapy.packet import Raw
from scapy.all import *


class ProtocolHelper:
    SMTP_commands = [
        "MAIL FROM", "RCPT TO", "DATA", "HELO", "EHLO", "QUIT", "AUTH LOGIN", "AUTH PLAIN",
        "AUTH CRAM-MD5", "STARTTLS", "VRFY", "EXPN", "HELP", "NOOP", "RSET"
    ]
    POP3_commands = [
        b"USER", b"PASS", b"STAT", b"LIST", b"RETR", b"DELE", b"NOOP", b"QUIT"
    ]

    @staticmethod
    def get_application_layer_name(packet):
        if ProtocolHelper.is_http(packet):
            return "HTTP"
        if ProtocolHelper.is_https(packet):
            return "HTTPS"
        if ProtocolHelper.is_ftp(packet):
            return "FTP"
        if ProtocolHelper.is_ssh(packet):
            return "SSH"
        if ProtocolHelper.is_imap(packet):
            return "IMAP"
        if ProtocolHelper.is_smtp(packet):
            return "SMTP"
        if ProtocolHelper.is_dns(packet):
            return "DNS"
        if ProtocolHelper.is_pop3(packet):
            return "POP3"
        if ProtocolHelper.is_telnet(packet):
            return "TELNET"

        return "UNDEFINED"

    @staticmethod
    def is_http(packet):
        ether_pkt = Ether(packet)
        if ether_pkt.haslayer(TCP):
            tcp_pkt = ether_pkt[TCP]
            if tcp_pkt.payload:
                if b"HTTP" in bytes(tcp_pkt.payload):
                    return True
        return False

    @staticmethod
    def is_https(packet):
        # print("Checking https")
        ether_pkt = Ether(packet)
        if ether_pkt.haslayer(TLS):
            print("HTTPS")
            return True
        return False

    @staticmethod
    def is_ftp(packet):
        ether_pkt = Ether(packet)
        if ether_pkt.haslayer(TCP):
            # проверяем наличие команды USER в пакете
            if ether_pkt.haslayer(Raw) and b'USER' in ether_pkt[Raw].load:
                return True
            # проверяем наличие ответа от сервера в пакете
            if ether_pkt.haslayer(Raw) and b'220 ' in ether_pkt[Raw].load:
                return True
        return False

    @staticmethod
    def is_smtp(packet):
        ip_pkt = IP(packet)
        if ip_pkt.haslayer(TCP) and ip_pkt.haslayer(Raw):
            payload = ip_pkt[Raw].load
            if any(cmd in payload for cmd in ProtocolHelper.SMTP_commands):
                return True
        return False

    @staticmethod
    def is_dns(packet):
        ip_pkt = Ether(packet)
        if ip_pkt.haslayer(IP) and ip_pkt.haslayer(UDP):
            if packet[IP].proto == 17 and packet[UDP].dport == 53:
                return True
        return False

    @staticmethod
    def is_pop3(packet):
        ip_pkt = IP(packet)
        if ip_pkt.haslayer(TCP) and ip_pkt.haslayer(Raw):
            payload = ip_pkt[Raw].load
            if any(cmd in payload for cmd in ProtocolHelper.POP3_commands):
                return True
        return False

    @staticmethod
    def is_imap(packet):
        ip_pkt = IP(packet)
        if ip_pkt.haslayer(TCP) and ip_pkt.haslayer(Raw):
            payload = ip_pkt[Raw].load
            if b"IMAP" in payload:
                return True
        return False

    @staticmethod
    def is_ssh(packet):
        ip_pkt = IP(packet)
        if ip_pkt.haslayer(TCP) and ip_pkt.haslayer(Raw):
            payload = ip_pkt[Raw].load
            if payload.startswith(b"\x53\x53\x48"):
                return True
        return False

    @staticmethod
    def is_telnet(packet):
        ip_pkt = IP(packet)
        if ip_pkt.haslayer(TCP) and ip_pkt.haslayer(Raw):
            payload = ip_pkt[Raw].load
            try:
                payload.decode('ascii')
                return True
            except UnicodeDecodeError:
                pass
        return False
