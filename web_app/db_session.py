from functools import wraps

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import sqlalchemy.ext.declarative as dec
from sqlalchemy.orm import sessionmaker

SqlAlchemyBase = dec.declarative_base()

__factory = None
engine = None


def global_init(user, password, host, port, dbname):
    global __factory
    global engine

    if __factory:
        return
    conn_str = f'postgresql+asyncpg://{user}:{password}@{host}:{port}/{dbname}'
    engine = create_async_engine(conn_str, pool_pre_ping=True)

    __factory = sessionmaker(
        engine, expire_on_commit=False, class_=AsyncSession
    )
    return engine


def create_session() -> AsyncSession:
    global __factory
    return __factory()


def session_db(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        async with create_session() as session:
            return await func(*args, session=session, **kwargs)

    return wrapper
