from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    image_url = db.Column(db.String(200))
    buildings = db.relationship('Building', backref='site')

class Building(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'))
    name = db.Column(db.String(100))

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    floor = db.Column(db.Integer)
    number = db.Column(db.String(10))

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    name = db.Column(db.String(100))
    status = db.Column(db.String(10))  # '✔', '✘', ''
    fix_text = db.Column(db.Text)      # ข้อความแก้ไข
    room = db.relationship('Room', backref='tasks')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False) # Store the hashed password
    role = db.Column(db.String(10), nullable=False) # 'inspector' or 'viewer'

    def set_password(self, password):
        """Hashes the password and sets it to the model."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks the plain text password against the stored hash."""
        return check_password_hash(self.password_hash, password)
    
class UserActionLog(db.Model):
    __tablename__ = "user_action_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)  # ✅ เชื่อมกับ User
    action_type = db.Column(db.String(50), nullable=False)
    table_name = db.Column(db.String(50))
    record_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255))

    # ✅ ความสัมพันธ์ (relationship) กับ User
    user = db.relationship("User", backref="action_logs")






