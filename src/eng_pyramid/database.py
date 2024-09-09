import inspect
import re
import testing.postgresql
import urllib.parse

from collections import (
    namedtuple,
)
from collections.abc import Mapping
from dataclasses import dataclass, field
from sqlalchemy import (
    Column,
    ForeignKey,
    func,
    select,
    text,
)
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import (
    relationship,
    backref,
    Session,
)
from sqlalchemy.dialects.postgresql import UUID
from typing import Protocol
from warnings import warn

IdType = UUID(as_uuid=True)

def IdColumn(*args, **kwargs):
    '''Convenience function: the default Column for object ids.'''
    return Column(
        IdType,
        *args,
        primary_key=True,
        server_default=func.gen_random_uuid(),
        **kwargs,
    )


def IdRefColumn(reference, *args, **kwargs):
    '''Convenience function: the default Column for references to object ids.'''
    return Column(IdType, ForeignKey(reference), *args, **kwargs)


AssocDescriptor = namedtuple('AssocDescriptor', 'table singular')


def camel_case(s):
    return re.sub(r'[_-]+', ' ', s).title().replace(' ', '')


def assoc_relationship(ao_table_name, left, right, base=None, mixins=tuple(), namespace=None, *args, **kwargs):
    if not namespace:
        info = inspect.stack()[1]
        mod = inspect.getmodule(info.frame)
        namespace = mod.__dict__
    if not base:
        base = namespace.get('Base')
    if not base:
        raise Exception(
            f'You must either specify base or make sure the module ({mod.__name__}) ' +
            'defines or imports a base class called "Base"'
        )
    ao_class_name = camel_case(ao_table_name)
    namespace[ao_class_name] = type(
        ao_class_name,
        (base, *mixins),
        {
            '__tablename__': ao_table_name,
            'uuid': IdColumn(),
            f'{left.singular}_id': IdRefColumn(f'{left.table}.uuid', nullable=False),
            f'{right.singular}_id': IdRefColumn(f'{right.table}.uuid', nullable=False),
            left.singular: relationship(
                camel_case(left.table),
                backref=backref(ao_table_name, cascade="all, delete-orphan")
            ),
            right.singular: relationship(
                camel_case(right.table),
                backref=backref(ao_table_name, cascade="all, delete-orphan")
            ),
        }
    )
    return association_proxy(ao_table_name, right.singular, *args, **kwargs)


def setup_userspace_db(settings):
    db_url = urllib.parse.urlparse(settings.get('sqlalchemy.url'))
    base_dir = settings.get('testing.postgresql.base_dir')
    print('Setting up database in {}.'.format(base_dir))
    db = testing.postgresql.Postgresql(
        base_dir=base_dir,
        port=db_url.port,
    )
    print('Database serving on {}.'.format(db.url()))
    return db


def add_db_parser_args(parser):
    parser.add_argument(
        '--destroy',
        action='store_true',
        help='drop_all tables before recreating.'
    )
    parser.add_argument(
        '-w', '--wait',
        action='store_true',
        help='Wait for a keypress before exiting. Keep DB service running.'
    )
    parser.add_argument(
        '--test-corner',
        action='store_true',
        help='Add corner case test cases to database.'
    )
    parser.add_argument(
        '--test-bulk',
        action='store_true',
        help='Add bulk test cases to database.'
    )
    parser.add_argument(
        '-t', '--test-data',
        action='store_true',
        help='Add test data to the database.'
    )


class DataCreator(Protocol):

    def add_initial(self):
        ...

    def add_test_corner(self):
        ...

    def add_test_bulk(self):
        ...


@dataclass
class DataFactory(DataCreator):
    dbsession: Session
    default_n: int = 250
    children: list['DataFactory'] = field(default_factory=list)

    def add_initial(self):
        for child in self.children:
            child.add_initial()
        self._add_initial()

    def add_test_corner(self):
        for child in self.children:
            child.add_test_corner()
        self._add_test_corner()

    def add_test_bulk(self):
        for child in self.children:
            child.add_test_bulk()
        self._add_test_bulk()

    def _add_initial(self):
        pass

    def _add_test_corner(self):
        pass

    def _add_test_bulk(self):
        pass


def add_test_data(factory, test_corner=False, test_bulk=False):
    factory.add_initial()
    if test_corner:
        factory.add_test_corner()
    if test_bulk:
        factory.add_test_bulk()

class DBMap(Mapping):

    def __init__(self, dbsession, model, keycol=None, where='', dict_keyfunc=None):
        self.dbsession = dbsession
        self.model = model
        if keycol is None:
            pks = inspect(model).primary_key
            if len(pks) == 1:
                keycol = pks[0].name
            else:
                keycol = tuple(col.name for col in pks)
        self.keycol = keycol
        self.where = where
        if dict_keyfunc:
            self.dict_keyfunc = dict_keyfunc
        else:
            self.dict_keyfunc = self.default_keyfunc
        self.refresh()

    def default_keyfunc(self, obj):
        if isinstance(self.keycol, str):
            return getattr(obj, self.keycol)
        else:
            return tuple(getattr(obj, key) for key in self.keycol)

    def refresh(self):
        # slct = select(self.model)
        self.data = {
            self.dict_keyfunc(obj): obj for obj in
            self.dbsession.execute(
                select(self.model).where(text(self.where))
            ).scalars().all()
        }

    def __getitem__(self, key):
        return self.data[key]

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)
