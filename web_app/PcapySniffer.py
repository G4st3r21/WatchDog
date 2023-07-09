import queue
import re
import threading
from loguru import logger
import pcapy

from PacketAnalyzer.PacketAnalyzer import PacketAnalyzer


class PcapySniffer:
    def __init__(self, filter_exp):
        self.interface = "eth0"
        self.filter = filter_exp
        self.stop_sniffing = False
        self.sniffer_thread = None
        self.logger = logger.add("logs/watchDog.log", format="<green>{level}</green>:     {message}")

        self.all_packets = queue.Queue()  # TODO: Починить очистку очереди

    async def get_packets(self):
        packets = []
        while not self.all_packets.empty():
            packets.append(self.all_packets.get())
        return packets

    async def start(self):
        self.sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        self.sniffer_thread.start()

    async def stop(self):
        self.stop_sniffing = True
        if self.sniffer_thread is not None:
            self.sniffer_thread.join()

    def start_sniffing(self):
        cap = pcapy.open_live(self.interface, 65536, True, 100)
        cap.setfilter(self.filter)

        while True:
            try:
                (header, packet) = cap.next()
                deciphered_info = PacketAnalyzer.analyze_packet(packet)
                if isinstance(deciphered_info["ports"][0], int):
                    src = deciphered_info["ips"][0] + ":" + str(deciphered_info["ports"][0])
                else:
                    src = deciphered_info["ips"][0]
                if isinstance(deciphered_info["ports"][1], int):
                    dst = deciphered_info["ips"][1] + ":" + str(deciphered_info["ports"][1])
                else:
                    dst = deciphered_info["ips"][1]

                if isinstance(deciphered_info["payload"], str):
                    payload = deciphered_info["payload"].replace('\n', '<br>')
                else:
                    payload = str(deciphered_info["payload"])
                self.all_packets.put(
                    {
                        "src": src,
                        "dst": dst,
                        "transport_protocol": deciphered_info["transport"],
                        "application_protocol": deciphered_info["application"],
                        "other_info": re.sub(r'[^\x00-\x7F]+', '', payload)
                    }
                )

            except pcapy.PcapError:
                continue
