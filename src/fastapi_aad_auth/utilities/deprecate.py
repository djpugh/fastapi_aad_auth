"""Method, class, module and Field Deprecation handlers."""
from functools import wraps
import warnings

from pkg_resources import parse_version
from pydantic import Field

from fastapi_aad_auth._version import get_versions


__version__ = get_versions()['version']
del get_versions

BASE_VERSION = parse_version(parse_version(__version__).base_version)  # type: ignore


class APIDeprecationWarning(FutureWarning):
    """Warning when an API component is being deprecated."""


class DeprecatedError(Exception):
    """Warning for developers when a component is planned to be deprecated."""


@wraps(Field)
def DeprecatedField(*args, **kwargs):  # noqa: D103
    deprecated_in = kwargs.get('deprecated_in')
    kwargs['warn_from'] = kwargs.get('warn_from', __version__)
    replaced_by = kwargs.get('replaced_by', None)
    description = kwargs.get('description', '')
    additional_info = kwargs.get('additional_info', '')
    if not description:
        description = ''
        sep = ''
    else:
        sep = ' '
    deprecation_message = _get_deprecation_message('Field', deprecated_in, replaced_by, additional_info)
    description += sep + deprecation_message
    kwargs['description'] = description
    kwargs['deprecated'] = True
    return Field(*args, **kwargs)


class DeprecatableFieldsMixin:
    """Mixin for deprecatable fields."""
    def __new__(cls, *args, **kwargs):
        """Initialise the Field Deprecation Validator."""
        for field_name, field in cls.__fields__.items():
            if field.field_info.extra.get('deprecated', False):
                if field.pre_validators is None:
                    field.pre_validators = []
                field.pre_validators.insert(0, cls._deprecator_validator)
        return super().__new__(cls)

    @staticmethod
    def _deprecator_validator(cls, value, kw, field, *args, **kwargs):
        if field.field_info.extra.get('deprecated', False):
            deprecated_object_description = f'{cls.__module__}:{cls.__name__}.{field.name}'
            env = field.field_info.extra.get('env', None)
            if env:
                deprecated_object_description += f' (env={env})'
            deprecated_in = field.field_info.extra.get('deprecated_in')
            warn_from = field.field_info.extra.get('warn_from', __version__)
            replaced_by = field.field_info.extra.get('replaced_by', None)
            deprecation_message = _get_deprecation_message(deprecated_object_description, deprecated_in, replaced_by)
            _warn(deprecation_message, deprecated_in, warn_from)
        return value


def deprecate(deprecated_in, warn_from=__version__, replaced_by=None, additional_info=''):
    """Deprecate a function, method or class."""

    def wrapper(deprecated_object, deprecation_message=None):
        if deprecation_message is None:
            deprecated_object_description = f'{deprecated_object.__module__}:{deprecated_object.__qualname__}'
            deprecation_message = _get_deprecation_message(deprecated_object_description, deprecated_in, replaced_by, additional_info)

        try:
            deprecated_object.__doc__ = _update_docstring(deprecation_message, deprecated_object.__doc__)
        except AttributeError:
            pass

        if hasattr(deprecated_object, 'mro'):
            deprecated_object.__init__ = wrapper(deprecated_object.__init__, deprecation_message)
            wrapped = deprecated_object

        else:
            @wraps(deprecated_object)
            def wrapped(*args, **kwargs):
                _warn(deprecation_message, deprecated_in, warn_from)
                return deprecated_object(*args, **kwargs)

        wrapped.deprecated_in = deprecated_in

        return wrapped

    return wrapper


def deprecate_module(module_locals, deprecated_in, warn_from=__version__, replaced_by=None, additional_info=''):
    """Deprecate a module."""
    deprecated_object_description = module_locals['__name__']
    deprecation_message = _get_deprecation_message(deprecated_object_description, deprecated_in, replaced_by, additional_info)
    module_locals['__doc__'] = _update_docstring(deprecation_message, module_locals['__doc__'])
    _warn(deprecation_message, deprecated_in, warn_from)


def _update_docstring(deprecation_message, docstring=None):
    if docstring is None:
        docstring = ''
    else:
        docstring += '\n\n'
    docstring += f"DEPRECATED - {deprecation_message}"
    return docstring


def _get_deprecation_message(deprecated_object_description, deprecated_in, replaced_by=None, additional_info=''):
    replacement = ''
    if replaced_by:
        replacement = f', and is replaced by {replaced_by}'
    if parse_version(__version__) < parse_version(deprecated_in):
        tense = ' will be'
        joiner = 'in'
    else:
        tense = ' is'
        joiner = 'since'
    deprecation_message = f'{deprecated_object_description}{tense} deprecated {joiner} version {deprecated_in}{replacement}{additional_info}'
    return deprecation_message


def _warn(deprecation_message, deprecated_in, warn_from):
    if BASE_VERSION >= parse_version(deprecated_in):
        raise DeprecatedError(deprecation_message)
    else:
        if BASE_VERSION >= parse_version(warn_from):
            warnings.warn(deprecation_message, APIDeprecationWarning)
        else:
            warnings.warn(deprecation_message, DeprecationWarning)


def is_deprecated(obj):
    """Check if an object is deprecated."""
    deprecated_in = getattr(obj, 'deprecated_in', None)
    if deprecated_in is None:
        # Check if it's a field
        if hasattr(obj, 'field_info'):
            deprecated_in = obj.field_info.extra.get('deprecated_in', None)
    return (deprecated_in is not None) and (BASE_VERSION >= parse_version(deprecated_in))
