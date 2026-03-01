from datetime import datetime
from flask_login import UserMixin
from extensions import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # --- СВЯЗИ (Relationships) ---
    models = db.relationship('Model', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    time_logs = db.relationship('DomainTimeLog', backref='owner', lazy='dynamic', cascade="all, delete-orphan")
    # ВОТ ЭТА СТРОЧКА БЫЛА ПРОПУЩЕНА:
    active_state = db.relationship('ActiveState', backref='owner', uselist=False, cascade="all, delete-orphan")


class Model(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    model_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    model_path = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    progress = db.Column(db.Integer, default=0)


class DomainTimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_ip = db.Column(db.String(50), nullable=False, index=True)
    domain = db.Column(db.String(200), nullable=False, index=True)
    duration_seconds = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    local_ip = db.Column(db.String(50), nullable=False)
    total_bytes = db.Column(db.BigInteger, default=0)
    packet_count = db.Column(db.Integer, default=0)
    protocols = db.Column(db.String(200))
    domains = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ActiveState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    is_monitoring = db.Column(db.Boolean, default=False)
    active_model_id = db.Column(db.Integer, nullable=True)
    interface = db.Column(db.String(100), nullable=True)
    worker_status_json = db.Column(db.Text, default='{}')