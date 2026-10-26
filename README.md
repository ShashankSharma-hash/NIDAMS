# Network Intrusion Detection and Monitoring System (NIDAMS)

## Overview

NIDAMS is a software-based network intrusion detection and monitoring system that identifies suspicious network activities and presents security information through a web-based dashboard.

The project focuses on port scanning, brute-force login attempts, network flooding/DoS, and replay attacks.

## Project Structure

- `backend/` — FastAPI backend and PostgreSQL integration
- `frontend/` — React dashboard built with Vite

## Technologies Used

- Python, FastAPI, SQLAlchemy
- PostgreSQL
- React, Vite, Recharts

## Run the Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Ensure PostgreSQL is running, the `nidams` database exists, and the connection in `database.py` matches your setup.

API documentation: http://127.0.0.1:8000/docs

## Run the Frontend

Open a second terminal from the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, usually http://localhost:5173.

## Main Features

- Security alert monitoring and filtering
- Alert acknowledgement and resolution
- Threat analytics and charts
- Security notifications
- Detection evaluation metrics

## Project Scope

This is an academic project intended for use in a controlled environment. Detection performance depends on the implemented detection modules and test data.

## Contributors

Add contributor names and responsibilities here.
