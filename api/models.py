# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from datetime import datetime

import json

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    points = db.Column(db.Integer(), default=0)  # new field
    xp = db.Column(db.Integer(), default=0)  # new field
    level = db.Column(db.Integer(), default=0)  # new field
    family_size = db.Column(db.Integer(), default=0)  # new field
    username = db.Column(db.String(32), nullable=False)
    password = db.Column(db.Text())
    jwt_auth_active = db.Column(db.Boolean())
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow)
    # metrics = db.Column(db.JSON, default=dict)
    def __repr__(self):
        return f"User {self.username}"

    def save(self):
        db.session.add(self)
        db.session.commit()

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def update_email(self, new_email):
        self.email = new_email

    def update_username(self, new_username):
        self.username = new_username

    def check_jwt_auth_active(self):
        return self.jwt_auth_active

    def set_jwt_auth_active(self, set_status):
        self.jwt_auth_active = set_status

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def get_all(cls):
        return cls.toDICT(cls.query.all())

    def toDICT(self):
        cls_dict = {}
        cls_dict['_id'] = self.id
        cls_dict['username'] = self.username
        cls_dict['points'] = self.points  # new field
        cls_dict['xp'] = self.xp  # new field
        cls_dict['level'] = self.level  # new field
        cls_dict['family_size'] = self.family_size  # new field
        return cls_dict

    def toJSON(self):
        return self.toDICT()

class JWTTokenBlocklist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jwt_token = db.Column(db.String(), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)

    def __repr__(self):
        return f"Expired Token: {self.jwt_token}"

    def save(self):
        db.session.add(self)
        db.session.commit()

class Quests(db.Model):     # Idk if this works
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(), nullable=False, unique=True)
    description = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(15), nullable=False)  

class UserQuests(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    userid = db.Column(db.Integer(), nullable=False)
    status = db.Column(db.String(12), nullable=False)
    expiry = db.Column(db.String(10), nullable=False)
    completed = db.Column(db.String(10), nullable=True)

    def update_status(self, status):
        self.status = status

    def update_completed(self, completed):
        self.completed = completed
    
class Tasks(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    questId = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    metric = db.Column(db.String(50), nullable=False)
    requiredAmount = db.Column(db.Integer(), primary_key=False)
    moreOrLess = db.Column(db.String(4), nullable=True)