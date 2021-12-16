from . import db


class User(db.Model):
    """
    Maps user object for SQLite db
    """
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True, index = True)
    password = db.Column(db.String(80))
    active_jwt = db.Column(db.String(350), unique = True)