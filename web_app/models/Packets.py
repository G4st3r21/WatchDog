import re

from sqlalchemy import Column, Integer, String, select, Time
from sqlalchemy.ext.asyncio import AsyncSession

from db_session import SqlAlchemyBase


def clean_string(input_string):
    # Определяем регулярное выражение для поиска некорректных символов
    pattern = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F]')

    # Заменяем некорректные символы на пустую строку
    cleaned_string = re.sub(pattern, '', input_string)

    return cleaned_string


class Packets(SqlAlchemyBase):
    __tablename__ = "Пакеты"
    id = Column(Integer, primary_key=True, autoincrement=True)
    src = Column(String, nullable=False, unique=False)
    dst = Column(String, nullable=False, unique=False)
    transport_protocol = Column(String, nullable=False, unique=False)
    application_protocol = Column(String, nullable=False, unique=False)
    info = Column(String, nullable=False, unique=False)
    status_code = Column(Integer)

    @classmethod
    async def get_last_packet(cls, session: AsyncSession):
        packets = await session.execute(select(cls).order_by(cls.id.desc()).first())
        return packets.first()

    @classmethod
    async def get_packets(cls, session: AsyncSession, offset=0):
        packets = await session.execute(select(cls).offset(offset))
        return packets.scalars()

    @classmethod
    async def save_packets(cls, session: AsyncSession, packets: list[dict]):
        for packet_dict in packets:
            other_info = clean_string(packet_dict['other_info'])
            packet_db = Packets(
                src=packet_dict['src'],
                dst=packet_dict['dst'],
                transport_protocol=packet_dict['transport_protocol'],
                application_protocol=packet_dict['application_protocol'],
                info=other_info
            )
            session.add(packet_db)
            await session.commit()
