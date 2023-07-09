import queue
import sys
from datetime import datetime
from threading import Thread

from scapy import packet
from scapy.all import sniff
from scapy.layers.inet import IP

from models.Services import Services
from views.ServicesView import ServicesView


class Sniffer:
    def __init__(self, logger):
        self.services: list[Services] = []
        self.filter = "tcp port 80"
        self.sniffer_thread = None
        self.sniff = None
        self.need_restart = False
        self.HTTP_packets = queue.Queue()

        self.logger = logger

    async def get_packets(self):
        packets = []
        while not self.HTTP_packets.empty():
            packets.append(self.HTTP_packets.get())
        return packets

    async def update(self):
        services = self.services.copy()
        await self.update_ips()
        if services != self.services:
            await self.set_filter()
            await self.run()

            return True

        return False

    async def update_ips(self):
        self.services = await ServicesView().get_model_objects()

    async def set_filter(self):
        ips = set([service.ip for service in self.services])
        ports = set([service.port for service in self.services])
        if ips and ports:
            self.filter = "((" + "ip src " + " or ip src ".join(ips) + ")" + \
                          " and " + "(" + " tcp port " + " or tcp port ".join(ports) + ")" + \
                          " or " + "(" + " ip dst " + "or ip dst".join(ips) + ")" + \
                          " and " + "(" + " tcp port " + " or tcp port ".join(ports) + "))"
            self.logger.info("New sniffer filter set:\n" + self.filter)
        else:
            # self.filter = "(ip src localhost) and (tcp port 8000) or (ip dst localhost) and (tcp port 8000)"
            self.filter = "tcp port 80 or udp port 80"

    async def run(self):
        if self.sniffer_thread:
            self.need_restart = True
            self.sniffer_thread.join()
            self.sniffer_thread = None
        else:
            self.sniffer_thread = Thread(target=self.start_sniffing, daemon=True)
            self.sniffer_thread.start()
            self.logger.info("Started sniffer thread")

    def start_sniffing(self):
        sniff(filter=self.filter, prn=self.packet_handler, store=False)

    def stop_sniffing(self):
        sniff(filter="", count=1)

    def packet_handler(self, packet: packet.Packet):
        if self.need_restart:
            self.need_restart = False
            sys.exit()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = datetime.now()
        if 'HTTP' in packet:
            http_headers = packet['HTTP'].fields
            http_payload = packet['HTTP'].payload

        self.HTTP_packets.put({
            "src": src_ip,
            "dst": dst_ip,
            "time": time
        })
