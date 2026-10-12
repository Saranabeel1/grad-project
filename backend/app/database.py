"""Database connection. PostgreSQL in Docker, SQLite for quick local runs and tests."""
import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

# SQLite needs this flag because FastAPI uses several threads.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: one database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def upgrade():
    """Create missing tables, and add columns that newer versions need to an existing database
    (create_all makes new tables but never changes old ones). Safe to run every start."""
    from . import models  # noqa: F401  (registers the tables)

    Base.metadata.create_all(bind=engine)
    columns = {c["name"] for c in inspect(engine).get_columns("findings")}
    if "assignee_id" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE findings ADD COLUMN assignee_id INTEGER"))
