from sqladmin import ModelView

from models.Packets import Packets


class PacketView(ModelView, model=Packets):
    name = "Пакет"
    name_plural = "Пакеты"
    column_list = [Packets.id, Packets.dst, Packets.src, Packets.transport_protocol, Packets.application_protocol]
