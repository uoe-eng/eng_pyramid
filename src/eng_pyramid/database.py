import inspect
import re
from collections import (
    namedtuple,
)
from sqlalchemy import (
    Column,
    ForeignKey,
    func,
)
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import (
    relationship,
    backref,
)
from sqlalchemy.dialects.postgresql import UUID

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
