from typing import Any

from sqladmin import ModelView

from models.Services import Services


class ServicesView(ModelView, model=Services):
    name = "IP адрес"
    name_plural = "IP адреса"
    column_list = [Services.id, Services.name, Services.ip, Services.port]

