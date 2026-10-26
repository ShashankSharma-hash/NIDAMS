
import json
from pathlib import Path

from sqlalchemy import select

from database import SessionLocal
from models import Alert
from schemas import AlertCreate


FILE_PATH = Path(__file__).parent / "alerts.jsonl"


def import_alerts():
    if not FILE_PATH.exists():
        print(f"File not found: {FILE_PATH}")
        return

    inserted = 0
    skipped = 0
    errors = 0

    with SessionLocal() as db:
        with FILE_PATH.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    raw = json.loads(line)
                    payload = AlertCreate.model_validate(raw)

                    existing = db.scalar(
                        select(Alert.alert_id).where(
                            Alert.alert_id == payload.alert_id
                        )
                    )

                    if existing is not None:
                        skipped += 1
                        continue

                    data = payload.model_dump()
                    allowed_columns = set(Alert.__table__.columns.keys())
                    data = {
                        key: value
                        for key, value in data.items()
                        if key in allowed_columns
                    }

                    db.add(Alert(**data))
                    db.flush()
                    inserted += 1

                except Exception as exc:
                    db.rollback()
                    errors += 1
                    print(
                        f"Line {line_number} failed: "
                        f"{type(exc).__name__}: {exc}"
                    )

        db.commit()

    print("\nImport finished.")
    print(f"Inserted: {inserted}")
    print(f"Skipped existing IDs: {skipped}")
    print(f"Errors: {errors}")


if __name__ == "__main__":
    import_alerts()
