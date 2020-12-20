"""Provide inheritable property dictable basemodel.

Implements pydantic work arounds for:
* https://github.com/samuelcolvin/pydantic/issues/265
* https://github.com/samuelcolvin/pydantic/issues/935

"""
from functools import wraps

from pydantic import BaseModel, BaseSettings
from pydantic.validators import dict_validator


class InheritableMixin:
    """BaseModel that will Validate with inheritance rather than the original Class."""

    @classmethod
    def get_validators(cls):
        """Get the validator for the object."""
        yield cls.validate

    @classmethod
    def validate(cls, value):
        """Validate the class as itself."""
        if isinstance(value, cls):
            return value
        else:
            return cls(**dict_validator(value))


class PropertyMixin:
    """BaseModel with Properties in dict.

    A Pydantic BaseModel that includes properties in it's dict() result
    enabling a mix of both fields and properties
    """

    @classmethod
    def get_properties(cls):
        """Get the properties."""
        return [prop for prop in dir(cls) if cls._is_property(prop)]

    @classmethod
    def _is_property(cls, prop):
        return isinstance(getattr(cls, prop), property) \
                    and prop not in ("__values__", "fields")

    @wraps(BaseModel.dict)
    def dict(self,
             *,
             include=None,
             exclude=None,
             by_alias: bool = False,
             skip_defaults: bool = None,
             exclude_unset: bool = False,
             exclude_defaults: bool = False,
             exclude_none: bool = False,):
        """Return the object as a dictionary."""
        attribs = super().dict(
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            skip_defaults=skip_defaults,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none
        )
        props = self.get_properties()
        # Include and exclude properties
        if include:
            props = [prop for prop in props if prop in include]
        if exclude:
            props = [prop for prop in props if prop not in exclude]

        # Update the attribute dict with the properties
        if props:
            attribs.update({prop: getattr(self, prop) for prop in props})

        return attribs


class InheritableBaseSettings(InheritableMixin, BaseSettings):
    """A Pydantic BaseSettings that allows inheritance."""


class PropertyBaseSettings(PropertyMixin, BaseSettings):
    """A Pydantic BaseSettings that allows roperties in the dict."""


class InheritablePropertyBaseSettings(InheritableMixin, PropertyBaseSettings):
    """A Pydantic BaseSettings that allows inheritance and properties in the dict."""


class InheritableBaseModel(InheritableMixin, BaseModel):
    """A Pydantic BaseModel that allows inheritance."""


class PropertyBaseModel(PropertyMixin, BaseModel):
    """A Pydantic BaseModel that allows roperties in the dict."""


class InheritablePropertyBaseModel(InheritableMixin, PropertyBaseModel):
    """A Pydantic BaseModel that allows inheritance and properties in the dict."""
