# NIDAMS Alert Schema Documentation

**Schema Version:** 1.1

## 1. Purpose

This document defines the JSON format used to send security alerts to the Network Intrusion Detection and Monitoring System (NIDAMS) backend.

The detection module sends an alert to the backend. FastAPI validates the incoming data, and valid alerts are stored in PostgreSQL. The system supports rule-based, machine-learning, and hybrid detection methods.

## 2. API Endpoint

- **Method:** `POST`
- **Endpoint:** `/alerts`
- **Compatibility endpoint:** `/api/alerts`
- **Content-Type:** `application/json`
- **Successful response:** `201 Created`
- **Duplicate alert ID:** `409 Conflict`
- **Invalid request data:** `422 Unprocessable Entity`

Both endpoints accept the same alert format.

## 3. Alert Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | String | No | Alert format version; defaults to `1.1` |
| `alert_id` | String | Yes | Unique identifier for an alert; maximum 36 characters |
| `timestamp` | Date-time | Yes | Time the alert was generated |
| `window_start` | Date-time | No | Start of the analysis window |
| `window_end` | Date-time | No | End of the analysis window |
| `site_id` | String | No | Identifier of the monitored site |
| `owner` | String | No | Owner associated with the alert |
| `src_ip` | String | Yes | Source IP address |
| `dst_ip` | String | No | Destination IP address, if available |
| `dst_port` | Integer | No | Destination port, from 1 to 65535 |
| `threat_type` | String | Yes | Detected threat category |
| `detected_by` | String | No | Detection method: `rule`, `ml`, or `hybrid` |
| `rule_triggered` | String | No | Rule responsible for detection |
| `ml_flag` | Boolean | No | Whether the ML detector flagged the activity |
| `anomaly_score` | Number | No | Anomaly score between 0 and 1 |
| `severity` | String | Yes | Alert severity |
| `features` | Object | No | Extracted traffic features stored as JSONB |
| `status` | String | No | Alert status; defaults to `new` |

## 4. Allowed Values

### `threat_type`

The schema accepts a non-empty string for the threat type, with a maximum length of 50 characters. Example categories include:

- `port_scan`
- `brute_force`
- `flood_dos`
- `replay`
- `anomaly`

Other non-empty threat labels are also accepted to support additional detector categories.

### `detected_by`

Allowed values:

- `rule`
- `ml`
- `hybrid`

This field may be omitted or set to `null`.

### `severity`

Allowed values:

- `Low`
- `Medium`
- `High`
- `Critical`

### `status`

Allowed values:

- `new`
- `acknowledged`
- `resolved`

The default status is `new`.

## 5. Validation Rules

- `alert_id`, `timestamp`, `src_ip`, `threat_type`, and `severity` are required.
- `alert_id` must contain between 1 and 36 characters.
- `src_ip` and `threat_type` must be non-empty strings.
- `dst_ip` is optional and may be omitted or set to `null`.
- `dst_port`, when provided, must be between 1 and 65535.
- `anomaly_score`, when provided, must be between 0 and 1.
- `detected_by`, when provided, must be `rule`, `ml`, or `hybrid`.
- `severity` must be `Low`, `Medium`, `High`, or `Critical`.
- `status` must be `new`, `acknowledged`, or `resolved`.
- `features` must be an object when provided.
- Duplicate alert IDs are rejected with `409 Conflict`.
- Invalid request data is rejected by FastAPI/Pydantic validation before the alert is saved.
- Additional fields are accepted by the request schema. However, only fields represented by database columns are persisted as separate columns.
- The `features` field is stored in PostgreSQL using the JSONB data type.

## 6. Example Alert

```json
{
  "schema_version": "1.1",
  "alert_id": "a1b2c3d4-0001",
  "timestamp": "2026-10-26T11:30:00+05:30",
  "window_start": "2026-10-26T11:29:55+05:30",
  "window_end": "2026-10-26T11:30:00+05:30",
  "site_id": "shop1",
  "owner": "demo-owner",
  "src_ip": "172.20.0.5",
  "dst_ip": "172.20.0.2",
  "dst_port": 443,
  "threat_type": "port_scan",
  "detected_by": "hybrid",
  "rule_triggered": "port_scan_unique_ports_gt_20",
  "ml_flag": true,
  "anomaly_score": 0.87,
  "severity": "High",
  "features": {
    "unique_dst_ports": 48,
    "packet_rate": 310.5,
    "failed_logins": 0,
    "duplicate_packets": 2
  },
  "status": "new"
}
```

The example values are illustrative and do not represent a real security incident.

## 7. Schema Versioning

The request schema defaults to version `1.1`. Clients may explicitly provide a different `schema_version` because the current schema accepts a string rather than enforcing a fixed version.

Changes to the alert format should be communicated to the team before integration. New versions should preserve compatibility with existing fields wherever possible.

## 8. Database Storage

The backend uses PostgreSQL to store alert records.

- Each alert is identified by `alert_id`.
- Traffic timestamps and optional analysis-window timestamps are stored as date-time values.
- Source and destination IP addresses and threat metadata are stored in their corresponding columns.
- Extracted `features` are stored in a JSONB column.
- Alert status can be updated to `new`, `acknowledged`, or `resolved`.
- The backend provides endpoints for creating alerts, listing alerts, filtering alerts, updating status, and retrieving summary statistics.

## 9. Important Notes

- The backend must be connected to a running PostgreSQL database.
- The detector and backend should use the same agreed alert field names and compatible schema versions.
- The destination IP may be unavailable for some events, so consumers should handle a missing `dst_ip`.
- This document describes the current request and storage structure. Any future changes to the API or database should be reflected here.
