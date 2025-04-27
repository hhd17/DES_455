from datetime import datetime, timezone

from extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    avatar = db.Column(db.String(150), default='img/default_avatar.png')
    history = db.relationship('History', backref='user', cascade='all, delete', passive_deletes=True)


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operation = db.Column(db.String(8), nullable=False)
    mode = db.Column(db.String(4), nullable=False)
    message_input = db.Column(db.String(512), nullable=False)
    key_input = db.Column(db.String(32), nullable=False)
    extra_param = db.Column(db.String(512))
    encrypted_message = db.Column(db.String(512))
    decrypted_message = db.Column(db.String(512))
    timestamp_utc = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
