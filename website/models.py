import time
from typing import Callable

import bcrypt
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from cuid2 import cuid_wrapper
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

cuid_generator: Callable[[], str] = cuid_wrapper()


class User(db.Model):
    __tablename__ = 'User'

    id = db.Column(db.String, primary_key=True, default=cuid_generator)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)

    def get_user_id(self):
        return self.id

    def check_password(self, password) -> bool:
        return bcrypt.checkpw(password.encode('UTF-8'), self.password.encode('UTF-8'))


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'OAuth2Client'

    id = db.Column(db.String, primary_key=True, default=cuid_generator)
    user_id = db.Column(
        db.String, db.ForeignKey('User.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'OAuth2AuthorizationCode'

    id = db.Column(db.String, primary_key=True, default=cuid_generator)
    user_id = db.Column(
        db.String, db.ForeignKey('User.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'OAuth2Token'

    id = db.Column(db.String, primary_key=True, default=cuid_generator)
    user_id = db.Column(
        db.String, db.ForeignKey('User.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
