from sqlalchemy import Column, Integer, String

from db_session import SqlAlchemyBase


class Services(SqlAlchemyBase):
    __tablename__ = "Сервисы"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, nullable=False, unique=False)
    port = Column(String, nullable=False, unique=False)
    name = Column(String, nullable=False, unique=False)
