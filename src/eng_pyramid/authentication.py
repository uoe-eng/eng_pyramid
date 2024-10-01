import jwt
import logging
import time
from authomatic import Authomatic
from authomatic.adapters import WebObAdapter
from authomatic.providers import oauth2
from functools import cached_property
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPFound,
    HTTPUnauthorized,
    HTTPInternalServerError,
)
from pyramid.response import Response
from pyramid.settings import aslist, asbool
from urllib.parse import quote

from .ldap import *

log = logging.getLogger(__name__)


def default_session_populator(request, auth_type=None):
    '''
    Populate the session dictionary. The only thing that's guaranteed to be in the session
    is the username as session['id'].
    '''
    session = request.session
    settings = request.registry.settings
    username = session['id']

    if 'expiry' not in session:
        session['expiry'] = time.time() + int(settings.get('login.expiry', 86400))

    if asbool(settings.get('login.sessions.add_active_user', 'true')):
        session['active_id'] = username

    if asbool(settings.get('login.sessions.add_ldap_groups', 'false')):
        session.update(ldap_info(request, username))
        if asbool(settings.get('login.sessions.add_active_user')):
            session.update({'active_memberOf': session['memberOf'].copy})


def authentication_view_deriver(view, info):
    def wrapped_view(context, request):
        settings = request.registry.settings

        try:
            populator = request.registry.session_populator
        except AttributeError:
            populator = default_session_populator
        # Authen / populate session from direct methods (jwt, certs, etc)
        for auth_type_name in (aslist(settings.get(
            'login.sessions.non_interactive',
            'jwt debug'
        ))):
            sess_func = getattr(locals, f'session_from_{auth_type_name}')
            if sess_func(request):
                populator(request, auth_type=auth_type_name)
                break   # break rather than return so that it's still possible to
                        # reach the login page

        if request.matched_route and request.matched_route.name in {'login', 'login_main'}:
            # Heading to the login view. You shall pass.
            return view(context, request)

        # check if authentication is valid
        if not request.session.get('expiry', 0) - time.time() > 0:
            # Not logged in. You shall not pass.
            return HTTPUnauthorized('Not logged in to API')

        # authz
        # alllowed at all?
        #     401
        return view(context, request)
    return wrapped_view


def get_jwt_secret(request):
    try:
        return request.registry.settings['jwt.secret']
    except KeyError:
        raise HTTPInternalServerError('There is no jwt.secret')


def session_from_jwt(request):
    header = request.headers.get('Authorization')
    if header and header.startswith('Bearer '):
        token = header[7:]
        log.debug(f'logging in with bearer token: {token}')
        jwt_secret = get_jwt_secret(request)
        try:
            decoded = jwt.decode(token, jwt_secret, algorithms="HS256")
        except jwt.exceptions.PyJWTError as err:
            raise HTTPBadRequest from err
        log.debug(f'decoded token: {decoded}')
        session = request.session
        username = decoded['user_id']
        session['id'] = username
        return True
    return False


def session_from_debug(request):
    if not asbool(request.registry.settings.get('login.on', 'true')):
        if not request.session.get('id'):
            request.session['id'] = request.registry.settings.get('login.debug_username', 'guest')
        return True
    return False


class AuthomaticView:
    provider_name = None

    def __init__(self, request):
        self.request = request

    def __call__(self):
        request = self.request
        request.session.invalidate()
        settings = request.registry.settings
        authomatic = Authomatic(config=self.config, secret=settings['authomatic.secret'])
        session = request.session
        response = Response()
        # Many Oauth2 providers preserve the contents of the 'user_state' param across the self.request process.
        # If set by the client, use it's value as the URL to redirect to after successful auth
        # Otherwise redirect to the session_info json route to verify login details
        result = authomatic.login(WebObAdapter(request, response), self.provider_name)
        if result:
            if result.error:
                log.warning(f'Oauth2 auth failure:\n {result.error}\n {session}')
                raise HTTPUnauthorized('Authentication not complete.')
            elif result.user:
                result.user.update()
                uinfo = self.user_info(result.user)
                session.update(uinfo)
                session.cookie_expires = uinfo['expiry']
                redirect_url = oauth2.OAuth2.decode_state(request.params.get(self.state_param)) or request.route_url('session_info')
                raise HTTPFound(redirect_url)
        return response

    @cached_property
    def config(self):
        return {}

    def user_info(self, user):
        return {}


class MSOnline(AuthomaticView):
    provider_name = 'msonline'
    state_param = 'state'

    @cached_property
    def config(self):
        return {
            'msonline': {
                'id': 1,
                'class_': oauth2.MicrosoftOnline,
                'consumer_key': self.request.registry.settings['oauth2.msonline.client_id'],
                'consumer_secret': self.request.registry.settings['oauth2.msonline.client_secret'],
                'domain': 'ed.ac.uk',
                'scope': ['User.Read'],
            }
        }

    def user_info(self, user):
        info = {
            'GUID': user.id,
            'id': user.username.partition('@')[0],
            'expiry': user.credentials.expiration_time,
        }
        return info


class Google(AuthomaticView):
    provider_name = 'google'
    state_param = 'user_state'

    @cached_property
    def config(self):
        return {
            'google': {
                'id': 1,
                'class_': oauth2.Google,
                'consumer_key': self.request.registry.settings['oauth2.google.client_id'],
                'consumer_secret': self.request.registry.settings['oauth2.google.client_secret'],
                'scope': ['email', 'profile'],
            }
        }

    def user_info(self, user):
        session = {}
        session['id'] = quote(user.id)
        session['expiry'] = user.credentials.expiration_time
        return session
