import asyncio
import json
import sys

from fastapi import FastAPI
from loguru import logger
from sqladmin import Admin
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from PcapySniffer import PcapySniffer
from auth import CheckUser
from Sniffer import Sniffer
from db_session import global_init, SqlAlchemyBase, create_session
from admin_config import *
from models.Packets import Packets
from views.PacketView import PacketView
from pathlib import Path

from views.ServicesView import ServicesView

app = FastAPI()
logger.add(sys.stdout, format="<green>{level}</green>:     {message}")
engine = global_init(DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME)
authentication_backend = CheckUser(secret_key=JWT_SECRET)
admin = Admin(app, engine, authentication_backend=authentication_backend)
templates = Jinja2Templates(directory="templates")
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_path), name="static")
app.add_middleware(SessionMiddleware, secret_key=JWT_SECRET)
sniffer = Sniffer(logger)
pcapy_sniffer = PcapySniffer(sniffer.filter)

last_packet_index = 0


async def generate_data():
    global last_packet_index
    async with create_session() as session:
        data = await Packets.get_packets(session, offset=last_packet_index)
        if len(list(data)) > 0:
            packets_dicts = [
                {
                    "id": packet.id,
                    "src": packet.src,
                    "dst": packet.dst,
                    "transport_protocol": packet.transport_protocol,
                    "application_protocol": packet.application_protocol,
                    "info": packet.info
                } for packet in data
            ]
            print(len(packets_dicts), list(data))
            packets_dicts.sort(key=lambda packet: packet["id"])
            last_packet_index = packets_dicts[-1]["id"]
            yield json.dumps(packets_dicts)
    await asyncio.sleep(0.5)


@app.get("/data_stream")
async def data_stream():
    return StreamingResponse(generate_data(), media_type="text/event-stream")


@app.get("/")
async def main_page(request: Request):
    return templates.TemplateResponse("main_page.html", {"request": request})


async def init_models():
    async with engine.begin() as conn:
        await conn.run_sync(SqlAlchemyBase.metadata.drop_all)
        await conn.run_sync(SqlAlchemyBase.metadata.create_all)


async def update_database():
    while True:
        # updated = await sniffer.update()
        # if updated:
        #     logger.info("Found new service(s), restarting sniffer")
        async with create_session() as session:
            packets = await pcapy_sniffer.get_packets()
            await Packets.save_packets(session, packets)


asyncio.create_task(init_models())
# asyncio.create_task(sniffer.run())
asyncio.create_task(pcapy_sniffer.start())
asyncio.create_task(update_database())

admin.add_view(PacketView)
admin.add_view(ServicesView)
