
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import create_tables, get_db
from models import Alert
from schemas import AlertCreate, AlertResponse


app = FastAPI(
    title="NIDAMS API",
    description="Network Intrusion Detection and Monitoring System",
    version="1.1.0",
)

# Allows a locally running frontend to call this API.
# Restrict origins before deploying publicly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    create_tables()


@app.get("/")
def root():
    return {
        "message": "Welcome to NIDAMS API",
        "docs": "/docs",
    }


@app.get("/health")
def health(db: Session = Depends(get_db)):
    # A successful response also confirms the database is reachable.
    db.execute(select(1))
    return {"status": "healthy", "database": "connected"}


def alert_columns():
    return set(Alert.__table__.columns.keys())


def create_alert_record(
    payload: AlertCreate,
    db: Session,
) -> Alert:
    existing = db.get(Alert, payload.alert_id)
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="An alert with this alert_id already exists",
        )

    # Persist only fields that actually exist in the database model.
    data = payload.model_dump()
    data = {
        key: value
        for key, value in data.items()
        if key in alert_columns()
    }

    alert = Alert(**data)
    db.add(alert)

    try:
        db.commit()
        db.refresh(alert)
    except Exception:
        db.rollback()
        raise

    return alert


@app.post(
    "/alerts",
    response_model=AlertResponse,
    status_code=201,
)
@app.post(
    "/api/alerts",
    response_model=AlertResponse,
    status_code=201,
    include_in_schema=False,
)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
):
    return create_alert_record(payload, db)


def list_alert_records(
    db: Session,
    site_id: str | None,
    severity: str | None,
    status: str | None,
    limit: int,
    offset: int,
):
    query = select(Alert)

    if site_id is not None:
        query = query.where(Alert.site_id == site_id)

    if severity is not None:
        query = query.where(Alert.severity == severity)

    if status is not None:
        query = query.where(Alert.status == status)

    query = (
        query.order_by(Alert.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )

    return db.scalars(query).all()


@app.get("/alerts", response_model=list[AlertResponse])
@app.get(
    "/api/alerts",
    response_model=list[AlertResponse],
    include_in_schema=False,
)
def list_alerts(
    site_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return list_alert_records(
        db, site_id, severity, status, limit, offset
    )


@app.get(
    "/sites/{site_id}/alerts",
    response_model=list[AlertResponse],
)
def list_site_alerts(
    site_id: str,
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return list_alert_records(
        db, site_id, severity, status, limit, offset
    )


@app.patch("/alerts/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    status: str = Query(
        ...,
        description="Allowed values: new, acknowledged, resolved",
    ),
    db: Session = Depends(get_db),
):
    allowed_statuses = {"new", "acknowledged", "resolved"}

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of {sorted(allowed_statuses)}",
        )

    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert


@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    severity_rows = db.execute(
        select(Alert.severity, func.count())
        .group_by(Alert.severity)
    ).all()

    threat_rows = db.execute(
        select(Alert.threat_type, func.count())
        .group_by(Alert.threat_type)
    ).all()

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=60)

    recent_alerts = db.scalars(
        select(Alert.timestamp).where(Alert.timestamp >= start)
    ).all()

    # Count alerts in each of the past 60 one-minute buckets.
    per_minute = Counter()
    for timestamp in recent_alerts:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        minute = timestamp.astimezone(timezone.utc).replace(
            second=0, microsecond=0
        )
        per_minute[minute.isoformat()] += 1

    minute_series = []
    first_minute = start.replace(second=0, microsecond=0)
    for index in range(61):
        minute = first_minute + timedelta(minutes=index)
        minute_series.append(
            {
                "minute": minute.isoformat(),
                "count": per_minute.get(minute.isoformat(), 0),
            }
        )

    return {
        "total_alerts": db.scalar(
            select(func.count()).select_from(Alert)
        ),
        "by_severity": {
            severity: count for severity, count in severity_rows
        },
        "by_threat_type": {
            threat_type: count for threat_type, count in threat_rows
        },
        "alerts_per_minute": minute_series,
    }
