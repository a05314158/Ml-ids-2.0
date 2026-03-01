import os
import sys
import json
import subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from sqlalchemy import func, event
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None

from extensions import db, login_manager
from models import User, Model, TrafficLog, ActiveState, DomainTimeLog

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev_key_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    @event.listens_for(db.engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

login_manager.init_app(app)
login_manager.login_view = 'login'

WORKER_PROCESSES = {}

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_friendly_interfaces():
    interfaces = []
    if get_windows_if_list:
        try:
            win_list = get_windows_if_list()
            blacklist = ['virtual', 'vpn', 'miniport', 'ndis', 'loopback', 'bluetooth', 'vmware', 'virtualbox']
            for iface in win_list:
                guid, desc = iface.get('name', ''), iface.get('description', 'Unknown')
                if any(b in desc.lower() for b in blacklist) or not guid: continue
                interfaces.append({'name': desc, 'value': guid})
        except: pass
    return interfaces or [{'name': 'No Interface', 'value': ''}]

def start_user_worker(user_id):
    global WORKER_PROCESSES
    if user_id in WORKER_PROCESSES and WORKER_PROCESSES[user_id].poll() is None: return
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        log = open(os.path.join(base, "worker_errors.txt"), "a")
        cmd = [sys.executable, os.path.join(base, 'worker.py'), str(user_id)]
        si = None
        if sys.platform == "win32":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
        WORKER_PROCESSES[user_id] = subprocess.Popen(cmd, stdout=log, stderr=log, cwd=base, startupinfo=si)
    except Exception as e: print(f"Worker Error: {e}")

# --- МАРШРУТЫ ---

@app.route('/')
def home(): return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    start_user_worker(current_user.id)
    return render_template('dashboard.html', interfaces=get_friendly_interfaces(),
                           models=current_user.models.all(),
                           active_state=current_user.active_state or ActiveState(user_id=current_user.id))

@app.route('/productivity')
@login_required
def productivity():
    top_domains = db.session.query(DomainTimeLog.domain, func.sum(DomainTimeLog.duration_seconds).label('total_time')).filter_by(user_id=current_user.id).group_by(DomainTimeLog.domain).order_by(func.sum(DomainTimeLog.duration_seconds).desc()).limit(10).all()
    top_users = db.session.query(DomainTimeLog.local_ip, func.sum(DomainTimeLog.duration_seconds).label('total_time')).filter_by(user_id=current_user.id).group_by(DomainTimeLog.local_ip).order_by(func.sum(DomainTimeLog.duration_seconds).desc()).limit(5).all()
    return render_template('productivity.html', top_domains=top_domains, top_users=top_users)

@app.route('/statistics')
@login_required
def statistics():
    period = request.args.get('period', 'hour')
    delta = timedelta(hours=1) if period == 'hour' else timedelta(days=1)
    start_time = datetime.utcnow() - delta
    stats = db.session.query(TrafficLog.local_ip, func.sum(TrafficLog.total_bytes).label('bytes'), func.sum(TrafficLog.packet_count).label('packets'), func.group_concat(TrafficLog.protocols).label('protos'), func.max(TrafficLog.timestamp).label('last_seen')).filter(TrafficLog.user_id == current_user.id, TrafficLog.timestamp >= start_time).group_by(TrafficLog.local_ip).order_by(func.sum(TrafficLog.total_bytes).desc()).all()
    clean_stats = [{'ip': s.local_ip, 'mb': round(s.bytes / (1024*1024), 2), 'packets': s.packets, 'protos': ', '.join(set(filter(None, (s.protos or '').split(',')))), 'last_seen': s.last_seen.strftime('%H:%M:%S')} for s in stats]
    return render_template('statistics.html', stats=clean_stats, period=period)

# --- API ЭНДПОИНТЫ (Нужны для Dashboard) ---

@app.route('/models_status')
@login_required
def models_status():
    return jsonify([{'id': m.id, 'progress': m.progress, 'is_ready': m.model_path is not None} for m in current_user.models.all()])

@app.route('/create_model', methods=['POST'])
@login_required
def create_model():
    data = request.get_json()
    db.session.add(Model(name=data.get('model_name'), model_type=data.get('model_type'), owner=current_user))
    db.session.commit(); return jsonify({"status": "ok"})

@app.route('/activate_model', methods=['POST'])
@login_required
def activate_model():
    data = request.get_json()
    current_user.models.update({Model.is_active: False})
    m = db.session.get(Model, int(data.get('model_id')))
    if m and m.user_id == current_user.id:
        m.is_active = True
        s = current_user.active_state or ActiveState(user_id=current_user.id)
        s.is_monitoring, s.active_model_id, s.interface = True, m.id, data.get('interface')
        db.session.add(s); db.session.commit(); return jsonify({"status": "ok"})
    return jsonify({"status": "error"})

@app.route('/stop_monitoring', methods=['POST'])
@login_required
def stop_monitoring():
    current_user.models.update({Model.is_active: False})
    if current_user.active_state: current_user.active_state.is_monitoring = False
    db.session.commit(); return jsonify({"status": "ok"})

@app.route('/delete_model', methods=['POST'])
@login_required
def delete_model():
    data = request.get_json()
    m = db.session.get(Model, int(data.get('model_id')))
    if m and m.user_id == current_user.id:
        if m.model_path:
            try:
                for ext in ['', '.joblib', '.keras', '_scaler.joblib', '_threshold.joblib']:
                    p = f"{m.model_path}{ext}"
                    if os.path.exists(p): os.remove(p)
            except: pass
        db.session.delete(m); db.session.commit(); return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

@app.route('/status')
@login_required
def status():
    s = current_user.active_state
    if s and s.worker_status_json:
        try: return jsonify(json.loads(s.worker_status_json))
        except: pass
    return jsonify({"mode": "Starting...", "log": []})

# --- АУТЕНТИФИКАЦИЯ ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, e = request.form.get('username'), request.form.get('email')
        if User.query.filter((User.email == e) | (User.username == u)).first():
            flash('User exists!', 'danger'); return redirect(url_for('register'))
        user = User(username=u, email=e, password_hash=generate_password_hash(request.form.get('password')))
        db.session.add(user); db.session.commit(); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(email=request.form.get('email')).first()
        if u and check_password_hash(u.password_hash, request.form.get('password')):
            login_user(u); start_user_worker(u.id); return redirect(url_for('dashboard'))
        flash('Invalid login', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)