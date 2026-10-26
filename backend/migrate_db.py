
from sqlalchemy import text

from database import engine
from models import Base


def migrate():
    # Create any missing tables, such as owners and sites.
    # Existing tables and their rows are not deleted.
    Base.metadata.create_all(bind=engine)

    # Update the existing alerts table without dropping its data.
    with engine.begin() as connection:
        connection.execute(text("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS site_id VARCHAR(100)
        """))

        connection.execute(text("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS owner VARCHAR(100)
        """))

        # Surya's alert format may omit the destination IP.
        connection.execute(text("""
            ALTER TABLE alerts
            ALTER COLUMN dst_ip DROP NOT NULL
        """))

        # New alerts default to schema version 1.1.
        # Existing records keep their current values.
        connection.execute(text("""
            ALTER TABLE alerts
            ALTER COLUMN schema_version SET DEFAULT '1.1'
        """))

        connection.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_alerts_site_id
            ON alerts (site_id)
        """))

    print("Database migration completed successfully!")


if __name__ == "__main__":
    migrate()
