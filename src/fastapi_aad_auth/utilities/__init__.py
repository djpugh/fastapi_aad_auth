"""Utilities."""
import importlib
from pathlib import Path
from typing import List, Union

from pydantic import SecretStr
from pydantic.main import ModelMetaclass
from starlette.requests import Request

from fastapi_aad_auth.utilities import logging  # noqa: F401
from fastapi_aad_auth.utilities import urls  # noqa: F401
from fastapi_aad_auth.utilities.basemodel import InheritableBaseModel, InheritableBaseSettings, InheritablePropertyBaseModel, InheritablePropertyBaseSettings, PropertyBaseModel, PropertyBaseSettings  # noqa: F401
from fastapi_aad_auth.utilities.deprecate import DeprecatableFieldsMixin, deprecate, deprecate_module, DeprecatedField, is_deprecated  # noqa: F401


def is_interactive(request: Request):
    """Check if a request is from an interactive client."""
    return any([u in request.headers['user-agent'] for u in ['Mozilla', 'Gecko', 'Trident', 'WebKit', 'Presto', 'Edge', 'Blink']])


def bool_from_env(env_value: Union[bool, str]) -> bool:
    """Convert environment variable to boolean."""
    if isinstance(env_value, str):
        env_value = env_value.lower() in ['true', '1']
    return env_value


def list_from_env(env_value: Union[List[str], str]) -> List[str]:
    """Convert environment variable to list."""
    if isinstance(env_value, str):
        env_value = [u for u in env_value.split(',') if u]
    return env_value


def klass_from_str(value: str):
    """Convert an import path to a class."""
    if isinstance(value, str):
        if ':' in value:
            module_name, klass_name = value.split(':')
        else:
            split_path = value.split('.')
            module_name = '.'.join(split_path[:-1])
            klass_name = split_path[-1]
        module = importlib.import_module(module_name)
        value = getattr(module, klass_name)
    return value


def expand_doc(klass: ModelMetaclass) -> ModelMetaclass:
    """Expand pydantic model documentation to enable autodoc."""
    docs = ['', '', 'Keyword Args:']
    for name, field in klass.__fields__.items():  # type: ignore
        default_str = ''
        #
        if field.default:
            default_str = ''
            if field.default:
                if SecretStr not in field.type_.__mro__:
                    default = field.default
                    if Path in field.type_.__mro__:
                        default = str(Path(default).relative_to(Path(default).parents[2]))
                    if field.name == 'user_klass':
                        default_str = f' [default: :class:`{default.replace("`", "").replace(":", ".")}`]'
                    else:
                        default_str = f' [default: ``{default}``]'
                else:
                    default_str = ' [default: ``uuid.uuid4()``]'
        module = field.outer_type_.__module__
        if module != 'builtins':
            if hasattr(field.outer_type_, '__origin__'):
                type_ = f' ({field.outer_type_.__origin__.__name__}) '
            elif not hasattr(field.outer_type_, '__name__'):
                type_ = ''
            else:
                type_ = f' ({module}.{field.outer_type_.__name__}) '
        else:
            type_ = f' ({field.outer_type_.__name__}) '
        env_var = ''
        if 'env' in field.field_info.extra:
            env_var = f' (Can be set by ``{field.field_info.extra["env"]}`` environment variable)'
        docs.append(f'    {name}{type_}: {field.field_info.description}{default_str}{env_var}')
    if klass.__doc__ is None:
        klass.__doc__ = ''
    klass.__doc__ += '\n'.join(docs)
    return klass
