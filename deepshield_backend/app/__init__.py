import os
from pathlib import Path

from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import inspect, text

from .extensions import db
from .routes.api import api_bp


def _apply_schema_compat_migrations() -> None:
    inspector = inspect(db.engine)
    if "alerts" not in inspector.get_table_names():
        return

    columns = {col["name"] for col in inspector.get_columns("alerts")}
    if "analyst_notes" not in columns:
        db.session.execute(text("ALTER TABLE alerts ADD COLUMN analyst_notes TEXT"))
        db.session.commit()

    if "protocol" not in columns:
        db.session.execute(text("ALTER TABLE alerts ADD COLUMN protocol VARCHAR(16)"))
        db.session.commit()
    if "dst_port" not in columns:
        db.session.execute(text("ALTER TABLE alerts ADD COLUMN dst_port INTEGER"))
        db.session.commit()

    if "automation_runs" in inspector.get_table_names():
        auto_columns = {col["name"] for col in inspector.get_columns("automation_runs")}
        if "retry_count" not in auto_columns:
            db.session.execute(text("ALTER TABLE automation_runs ADD COLUMN retry_count INTEGER DEFAULT 0"))
            db.session.commit()
        if "request_payload" not in auto_columns:
            db.session.execute(text("ALTER TABLE automation_runs ADD COLUMN request_payload TEXT"))
            db.session.commit()
        if "response_status" not in auto_columns:
            db.session.execute(text("ALTER TABLE automation_runs ADD COLUMN response_status INTEGER"))
            db.session.commit()
        if "response_payload" not in auto_columns:
            db.session.execute(text("ALTER TABLE automation_runs ADD COLUMN response_payload TEXT"))
            db.session.commit()


def create_app() -> Flask:
    load_dotenv()
    # When running from deepshield_backend/, also load repo-root .env (n8n, keys, model path).
    _root = Path(__file__).resolve().parent.parent.parent
    load_dotenv(_root / ".env", override=False)

    configured_origins = [
        origin.strip()
        for origin in os.getenv(
            "IDS_CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        ).split(",")
        if origin.strip()
    ]
    if not configured_origins:
        configured_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///deepshield.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        HOST=os.getenv("IDS_HOST", "127.0.0.1"),
        PORT=int(os.getenv("IDS_PORT", "5000")),
        DEBUG=os.getenv("FLASK_DEBUG", "0") == "1",
    )

    CORS(app, origins=configured_origins)
    db.init_app(app)

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()
        _apply_schema_compat_migrations()

    app.register_blueprint(api_bp)
    return app
