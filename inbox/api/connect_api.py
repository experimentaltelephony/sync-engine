import json
import hashlib

from copy import deepcopy
from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

from sqlalchemy import func
from sqlalchemy.orm.exc import NoResultFound
from inbox.api.kellogs import APIEncoder
from inbox.auth.base import handler_from_provider
from inbox.api.err import InputError
from inbox.models.session import session_scope_by_shard_id, session_scope, global_session_scope
from inbox.models import Account
from inbox.models.oauth import OAuthClient, OAuthBearerToken, OAuthGrant
from inbox.basicauth import AuthError, NotSupportedError

app = Blueprint('connect_api', __name__, url_prefix='')


@app.route('/connect/authorize', methods=('POST',))
def authorize():
    shard_id = 0
    try:
        data = request.get_json(force=True)
    except BadRequest:
        raise InputError("No JSON body")
    try:
        name = data['name']
        client_id = data['client_id']
        email_address = data['email_address']
        provider = data['provider']
        settings = data['settings']
        reauth_account_id = data.get('reauth_account_id') or data.get('reauth')
        reauth = bool(reauth_account_id)
    except KeyError as exc:
        field_name = exc.args[0]
        raise InputError("Missing required field %s" % field_name)

    with global_session_scope() as global_db_session:
        try:
            oauth_client = global_db_session.query(OAuthClient).filter_by(client_id=client_id).one()
        except NoResultFound:
            raise Forbidden("Invalid client_id %s" % client_id)
        account = global_db_session.query(Account).filter_by(email_address=email_address).first()
        if account is not None and not reauth:
            raise InputError('Already have this account!')
        if reauth and not account:
            reauth = False
        auth_handler = handler_from_provider(provider)
        auth_info = deepcopy(settings)
        for protocol in ('smtp', 'imap'):
            for setting in ('hostname', 'port'):
                key = '{protocol}_{setting}'.format(protocol=protocol, setting=setting)
                new_key = '{protocol}_server_{setting}'.format(protocol=protocol, setting=setting)
                if key in auth_info:
                    auth_info[new_key] = auth_info.pop(key)
        auth_info['name'] = 'name'
        auth_info['provider'] = provider
        auth_info['email'] = email_address
    try:
            if reauth:
                session_manager = session_scope(account.namespace.id)
            else:
                account = auth_handler.create_account(email_address, auth_info)
                session_manager = session_scope_by_shard_id(shard_id)
            with session_manager as db_session:
                db_session.add(account)
                if reauth:
                    account = auth_handler.update_account(account, auth_info)
                if auth_handler.verify_account(account):
                    grant, code = OAuthGrant.create(account, oauth_client.id)
                    db_session.add(grant)
                    db_session.commit()
                    return jsonify({"code": code})
                else:
                    raise Forbidden()
    except (NotSupportedError, AuthError) as e:
            raise Forbidden(str(e))


@app.route('/connect/token', methods=('POST',))
def token():
    try:
        code = request.get_json(force=True)['code']
        client_id = request.get_json(force=True)['client_id']
        client_secret = request.get_json(force=True)['client_secret']
    except KeyError as exc:
        field_name = exc.args[0]
        raise InputError("Missing required field %s" % field_name)

    with global_session_scope() as db_session:
        try:
            oauth_client = db_session.query(OAuthClient).filter_by(client_id=client_id).one()
        except NoResultFound:
            raise Forbidden("Invalid client_id %s" % client_id)
        if oauth_client.client_secret != hashlib.sha256(client_secret).hexdigest():
            raise Forbidden("Invalid client_secret")
        try:
            grant = db_session.query(OAuthGrant).filter_by(oauth_client=oauth_client, expired=False, grant_code=hashlib.sha256(code).hexdigest()).one()
        except NoResultFound:
            raise Forbidden()
        for old_token in db_session.query(OAuthBearerToken).filter_by(oauth_client=oauth_client, namespace=grant.account.namespace):
            db_session.delete(old_token)
        token, secret = OAuthBearerToken.create(grant)
        db_session.delete(grant)
        db_session.commit()
        account_id = grant.account_id
    with session_scope(account_id) as db_session:
        db_session.add(token)
        db_session.commit()
        encoder = APIEncoder(token.namespace.public_id, False)
        encoded_account = json.loads(encoder.cereal(token.namespace))
        encoded_account["access_token"] = secret
        return jsonify(encoded_account)

