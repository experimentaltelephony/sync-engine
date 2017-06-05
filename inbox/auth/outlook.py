import datetime

import sqlalchemy.orm.exc

from nylas.logging import get_logger
log = get_logger()

from inbox.auth.oauth import OAuthAuthHandler
from inbox.basicauth import OAuthError
from inbox.models import Namespace
from inbox.config import config
from inbox.models.backends.outlook import OutlookAccount
from inbox.models.backends.oauth import token_manager
from inbox.util.url import url_concat

PROVIDER = '_outlook'
AUTH_HANDLER_CLS = 'OutlookAuthHandler'

# Outlook OAuth app credentials
OAUTH_CLIENT_ID = config.get('MS_LIVE_OAUTH_CLIENT_ID')
OAUTH_CLIENT_SECRET = config.get('MS_LIVE_OAUTH_CLIENT_SECRET')
OAUTH_REDIRECT_URI = config.get('MS_LIVE_OAUTH_REDIRECT_URI')

OAUTH_AUTHENTICATE_URL = 'https://login.live.com/oauth20_authorize.srf'
OAUTH_ACCESS_TOKEN_URL = 'https://login.live.com/oauth20_token.srf'
OAUTH_USER_INFO_URL = 'https://apis.live.net/v5.0/me'
OAUTH_BASE_URL = 'https://apis.live.net/v5.0/'

OAUTH_SCOPE = ' '.join([
    'wl.basic',            # Read access for basic profile info + contacts
    'wl.offline_access',   # ability to read / update user's info at any time
    'wl.emails',           # Read access to user's email addresses
    'wl.imap'])            # R/W access to user's email using IMAP / SMTP


class OutlookAuthHandler(OAuthAuthHandler):
    OAUTH_CLIENT_ID = OAUTH_CLIENT_ID
    OAUTH_CLIENT_SECRET = OAUTH_CLIENT_SECRET
    OAUTH_REDIRECT_URI = OAUTH_REDIRECT_URI
    OAUTH_AUTHENTICATE_URL = OAUTH_AUTHENTICATE_URL
    OAUTH_ACCESS_TOKEN_URL = OAUTH_ACCESS_TOKEN_URL
    OAUTH_USER_INFO_URL = OAUTH_USER_INFO_URL
    OAUTH_BASE_URL = OAUTH_BASE_URL
    OAUTH_SCOPE = OAUTH_SCOPE

    def create_account(self, email_address, response):
        # This method assumes that the existence of an account for the
        # provider and email_address has been checked by the caller;
        # callers may have different methods of performing the check
        # (redwood auth versus bin/inbox-auth)
        namespace = Namespace()
        account = OutlookAccount(namespace=namespace)
        return self.update_account(account, response)


    def update_account(self, account, response):
        email_address = response.get('email')
        account.refresh_token = response['refresh_token']
        account.date = datetime.datetime.utcnow()
        tok = response.get('access_token')
        expires_in = response.get('expires_in')
        token_manager.cache_token(account, tok, expires_in)
        account.scope = response.get('scope')
        account.email_address = email_address
        account.o_id_token = response.get('user_id')
        account.o_id = response.get('id')
        account.name = response.get('name')
        account.gender = response.get('gender')
        account.link = response.get('link')
        account.locale = response.get('locale')

        account.client_id = response.get('client_id', OAUTH_CLIENT_ID)
        account.client_secret = response.get('client_secret', OAUTH_CLIENT_SECRET)

        # Ensure account has sync enabled.
        account.enable_sync()

        return account

    def validate_token(self, access_token):
        return self._get_user_info(access_token)

    def interactive_auth(self, email_address=None):
        url_args = {'redirect_uri': self.OAUTH_REDIRECT_URI,
                    'client_id': self.OAUTH_CLIENT_ID,
                    'response_type': 'code',
                    'scope': self.OAUTH_SCOPE,
                    'access_type': 'offline'}
        url = url_concat(self.OAUTH_AUTHENTICATE_URL, url_args)

        print ('Please visit the following url to allow access to this '
               'application. The response will provide '
               'code=[AUTHORIZATION_CODE]&lc=XXXX in the location. Paste the'
               ' AUTHORIZATION_CODE here:')
        print '\n{}'.format(url)

        while True:
            auth_code = raw_input('Enter authorization code: ').strip()
            try:
                auth_response = self._get_authenticated_user(auth_code)
                return auth_response
            except OAuthError:
                print '\nInvalid authorization code, try again...\n'
                auth_code = None

    def get_account(self, target, email_address, response):
        account = account_or_none(target, OutlookAccount, email_address)
        if not account:
            account = self.create_account(email_address, response)
        account = self.update_account(account, response)
        return account

