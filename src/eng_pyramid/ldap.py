import ldap3
import logging

from pyramid.httpexceptions import HTTPForbidden
from pyramid.settings import asbool
from functools import cache


log = logging.getLogger(__name__)


@cache
def get_ldap_connection(settings):
    if asbool(settings.get('ldap.fake_server')):
        ldap_server = ldap3.Server('eps_fake_ldap')
        ldap_strategy = ldap3.MOCK_SYNC
    else:
        ldap_server = ldap3.Server(settings.get('ldap.url'), use_ssl=True, connect_timeout=10)
        ldap_strategy = ldap3.RESTARTABLE
    ldap_connection = ldap3.Connection(
        ldap_server,
        settings.get('ldap.user'), settings.get('ldap.password'),
        client_strategy=ldap_strategy,
    )
    return ldap_connection


def ldap_info(request, uid, prefix='', ldap_con=None):
    con = ldap_con
    if not con:
        con = get_ldap_connection(request.registry.settings)
    base = request.registry.settings.get('ldap.user_search_base')
    info = {
        f'{prefix}memberOf': {}
    }
    if not base:
        log.warning('Empty people_base from settings. Returning info with empty groups.')
        return info
    if not con.bind():
        log.warning('LDAP bind failed. Returning info with empty groups.')
        return info
    log.debug(f'looking up {uid} at {base} in {con.server}')
    try:
        res = con.search(base, f'(uid={uid})', attributes=['memberOf'])
    except ldap3.core.exceptions.LDAPInvalidDnError as e:
        log.warning(e)
        return info
    if res:
        person = con.entries[0]
        info[f'{prefix}memberOf'] = {group:None for group in person.memberOf}
        if asbool(request.registry.settings.get('login.use_login_filter', 'true')):
            # use the login filter as a proxy for being a member of the engineering group
            info[f'{prefix}memberOf'][request.registry.settings.get('eng_dn')] = None
        log.debug(f'  found them - returning info: {info}')
        return info
    log.warning(f'uid={uid} not found on server - returning empty info.')
    return info
