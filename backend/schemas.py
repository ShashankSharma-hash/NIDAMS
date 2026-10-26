
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertCreate(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.1"
    alert_id: str = Field(min_length=1, max_length=36)
    timestamp: datetime

    window_start: datetime | None = None
    window_end: datetime | None = None

    site_id: str | None = None
    owner: str | None = None

    src_ip: str = Field(min_length=1, max_length=45)
    dst_ip: str | None = Field(default=None, max_length=45)
    dst_port: int | None = Field(default=None, ge=1, le=65535)

    # Accept Surya's new threat labels and future detector labels.
    threat_type: str = Field(min_length=1, max_length=50)

    detected_by: Literal["rule", "ml", "hybrid"] | None = None
    rule_triggered: str | None = None
    ml_flag: bool | None = None
    anomaly_score: float | None = Field(
        default=None, ge=0, le=1
    )

    severity: Literal["Low", "Medium", "High", "Critical"]
    features: dict[str, Any] | None = None

    status: Literal["new", "acknowledged", "resolved"] = "new"


class AlertResponse(AlertCreate):
    model_config = ConfigDict(
        extra="allow",
        from_attributes=True,
    )
