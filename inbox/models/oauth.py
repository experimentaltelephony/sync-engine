import hashlib
import uuid
import datetime

from functools import partial
from sqlalchemy import Column, Interval, String, BigInteger, ForeignKey, func
from sqlalchemy.orm import relationship, column_property
from sqlalchemy.ext.hybrid import hybrid_property

from inbox.util.secrets import generate_secret_string
from inbox.models.base import MailSyncBase


class OAuthGrant(MailSyncBase):
    expires_in = Column(Interval, default=datetime.timedelta(minutes=10))
    grant_code = Column(String, nullable=False)
    account_id = Column(BigInteger, ForeignKey('account.id', ondelete='CASCADE'), nullable=False)
    account = relationship('Account', lazy='joined', uselist=False)
    client_id = Column(BigInteger, ForeignKey('oauthclient.id', ondelete='CASCADE'), nullable=False)
    oauth_client = relationship('OAuthClient', uselist=False)

    @hybrid_property
    def expiry_date(self):
        return self.created_at + self.expires_in

    @expiry_date.expression
    def expiry_date(cls):
        return cls.created_at + cls.expires_in

    @hybrid_property
    def expired(self):
        return datetime.datetime.utcnow() > self.expiry_date

    @expired.expression
    def expired(cls):
        return func.now() > cls.expiry_date

    @classmethod
    def create(cls, account, client_id):
        secret = generate_secret_string(20)
        hash = hashlib.sha256(secret).hexdigest()
        return cls(account=account, grant_code=hash, client_id=client_id), secret


class OAuthBearerToken(MailSyncBase):
    namespace_id = Column(BigInteger, ForeignKey('namespace.id', ondelete='CASCADE'), nullable=False)
    namespace = relationship('Namespace', lazy='joined', uselist=False)
    access_token = Column(String, nullable=False)
    client_id = Column(BigInteger, ForeignKey('oauthclient.id', ondelete='CASCADE'), nullable=False)
    oauth_client = relationship('OAuthClient', uselist=False)

    @classmethod
    def create(cls, grant):
        secret = generate_secret_string(20)
        hash = hashlib.sha256(secret).hexdigest()
        return cls(namespace=grant.account.namespace, access_token=hash, oauth_client=grant.oauth_client), secret


class OAuthClient(MailSyncBase):
    name = Column(String)
    client_id = Column(String, default=partial(generate_secret_string, 20), nullable=False)
    client_secret = Column(String)

    @classmethod
    def create(cls, name):
        secret = generate_secret_string(20)
        hash = hashlib.sha256(secret).hexdigest()
        return cls(name=name, client_secret=hash), secret

