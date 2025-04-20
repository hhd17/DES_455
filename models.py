from extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    history = db.relationship('History', backref='user', lazy=True)


class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_message = db.Column(db.String(512), nullable=False)
    decrypted_message = db.Column(db.String(512), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
