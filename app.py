from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from functools import wraps
from datetime import datetime, timedelta


# --- 1. Create Flask app object and configure it ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///neo727.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_super_secret_key_here'

# --- 2. Initialize SQLAlchemy and LoginManager ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # หน้าที่ต้องเข้าสู่ระบบ

# --- 3. Define database models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'editor' หรือ 'viewer'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_role(self):
        return self.role


class UserActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="logs")


class Item(db.Model):   # 👈 ถ้าคุณมีตารางเก็บข้อมูล
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Role-based access decorator ---
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.get_role() != role:
                flash('คุณไม่มีสิทธิ์เข้าหน้านี้', 'danger')
                return redirect(url_for('select_system'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- ฟังก์ชันบันทึกประวัติ ---
def log_user_action(user_id, action_type):
    log = UserActionLog(
        user_id=user_id,
        action_type=action_type,
    )
    db.session.add(log)
    db.session.commit()


# --- 4. Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        logout_user()  # ✅ ลบ session อัตโนมัติ
    return redirect(url_for('login'))


# ✅ login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('select_system'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=False)  # ✅ ไม่จำ session
            log_user_action(user_id=user.id, action_type='เข้าสู่ระบบ')
            flash('เข้าสู่ระบบสำเร็จ', 'success')
            return redirect(url_for('select_system'))
        else:
            flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


# ✅ logout
@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        log_user_action(user_id=current_user.id, action_type='ออกจากระบบ')
        logout_user()
    flash('ออกจากระบบสำเร็จ', 'success')
    return redirect(url_for('login'))


@app.route('/select_system')
@login_required
def select_system():
    return render_template('dashboard.html', user_role=current_user.get_role())


@app.route('/manage_systems')
@login_required
def manage_systems():
    return render_template('manage.html', user_role=current_user.get_role())


@app.route('/pipe_systems')
@login_required
def pipe_systems():
    return render_template('pipe_systems.html', user_role=current_user.get_role())


@app.route('/wire_systems')
@login_required
def wire_systems():
    return render_template('wire_systems.html', user_role=current_user.get_role())


@app.route('/install_systems')
@login_required
def install_systems():
    return render_template('install_systems.html', user_role=current_user.get_role())


@app.route('/QA_systems')
@login_required
def QA_systems():
    return render_template('QA_systems.html', user_role=current_user.get_role())


@app.route("/history")
@login_required
def history():
    logs = (
        db.session.query(UserActionLog.timestamp, User.username)
        .join(User, UserActionLog.user_id == User.id)
        .order_by(UserActionLog.timestamp.desc())
        .all()
    )
    return render_template("history.html", records=logs)


# ✅ CRUD Item
@app.route('/add_item', methods=['POST'])
@login_required
@role_required('editor')
def add_item():
    name = request.form['name']
    new_item = Item(name=name)
    db.session.add(new_item)
    db.session.commit()

    log_user_action(user_id=current_user.id, action_type='เพิ่มข้อมูล')
    flash("เพิ่มข้อมูลสำเร็จ", "success")
    return redirect(url_for('manage_systems'))


@app.route('/edit_item/<int:item_id>', methods=['POST'])
@login_required
@role_required('editor')
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.name = request.form['name']
    db.session.commit()

    log_user_action(user_id=current_user.id, action_type='แก้ไขข้อมูล')
    flash("แก้ไขข้อมูลสำเร็จ", "success")
    return redirect(url_for('manage_systems'))


@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
@role_required('editor')
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()

    log_user_action(user_id=current_user.id, action_type='ลบข้อมูล')
    flash("ลบข้อมูลสำเร็จ", "success")
    return redirect(url_for('manage_systems'))


# --- 5. Create default users ---
def create_default_users():
    with app.app_context():
        if not User.query.filter_by(username='inspector').first():
            user = User(username='inspector', role='editor')
            user.set_password('123')
            db.session.add(user)
            print("Created default user: 'contractor'")
        if not User.query.filter_by(username='contrator').first():
            user = User(username='contrator', role='viewer')
            user.set_password('456')
            db.session.add(user)
            print("Created default user: 'readonly'")
        db.session.commit()
        
@app.route('/save_data', methods=['POST'])
@login_required
def save_data():
    if current_user.role == 'viewer':   # ❌ block ฝั่ง server
        return "Permission denied", 403

    data_to_save = request.json
    log_user_action(
        user_id=current_user.id,
        action_type='เพิ่ม/แก้ไขข้อมูล',
    )
    return "Data saved successfully!", 200


def log_user_action(user_id, action_type):
    local_time = datetime.utcnow() + timedelta(hours=7)  # 🇹🇭 เวลาประเทศไทย (UTC+7)
    log = UserActionLog(
        user_id=user_id,
        action_type=action_type,
        timestamp=local_time
    )
    db.session.add(log)
    db.session.commit()



# --- 6. Run app ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_users()
    app.run(debug=True)

