import os
import urllib.parse

from dataclasses import dataclass

DB_ENV_MAP = {
    'dburl.scheme': 'POSTGRES_SCHEME',
    'dburl.username': 'POSTGRES_USER',
    'dburl.password': 'POSTGRES_PASSWORD',
    'dburl.hostname': 'POSTGRES_HOST',
    'dburl.port': 'POSTGRES_PORT',
    'dburl.path': 'POSTGRES_DB',
}


@dataclass
class Netloc:
    hostname: str
    username: str = None
    password: str = None
    port: int = None

    @classmethod
    def from_parsed_url(cls, url):
        return cls(hostname=url.hostname, username=url.username, password=url.password, port=url.port)

    def __str__(self):
        self.hostname = self.hostname or ''
        netloc = ''
        if self.username is not None:
            netloc = netloc + self.username
        if self.password is not None:
            netloc = netloc + ':' + self.password

        if netloc == '':
            netloc = self.hostname
        else:
            netloc = netloc + '@' + self.hostname

        if self.port is not None:
            netloc = netloc + ':' + str(self.port)
        return netloc


def settings_from_env(prefix='ENG_', settings_map=DB_ENV_MAP):
    # Start with settings constructed from the map.
    env_settings = {
        setting_name: os.environ.get(env_name)
        for setting_name, env_name in settings_map.items()
        if env_name in os.environ
    }

    # Find all env variables which start with <prefix> and transform the name
    # with '__' (double under) going to '.'.
    env_settings.update(
        {k[len(prefix):].replace('__', '.').lower():v for k,v in os.environ.items() if k.startswith(prefix)}
    )

    return env_settings


def sqlalchemy_url_from_settings(settings, base_url='postgresql://postgres@localhost:7654/test'):
    # Deconstruct and then reconstruct the sqlalchemy.url merging in changes from env.
    db_url = urllib.parse.urlparse(settings.get('sqlalchemy.url', base_url))
    netloc = Netloc.from_parsed_url(db_url)
    db_replacements = {}
    # scheme and path can be directly replaced in a parsed url.
    for setting in {'scheme', 'path'} & settings.keys():
        db_replacements[setting] = settings[f'dburl.{setting}']
    # other settings need to be folded into the netloc part.
    for part in settings.keys() & {'dburl.username', 'dburl.password', 'dburl.hostname', 'dburl.port'}:
        setattr(netloc, part.partition('.')[2], settings[part])
    db_replacements['netloc'] = str(netloc)
    db_url = db_url._replace(**db_replacements)
    return urllib.parse.urlunparse(db_url)