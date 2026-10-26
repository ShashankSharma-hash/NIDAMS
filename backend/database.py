
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from models import Base


import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://shashanksharma@localhost:5432/nidams",
)

engine = create_engine(DATABASE_URL)

# Creates database sessions for API requests.
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")


def test_database_connection():
    with engine.connect() as connection:
        result = connection.execute(text("SELECT 1"))
        print("Database connection successful!")
        print("Test result:", result.scalar())


if __name__ == "__main__":
    test_database_connection()
    create_tables()
