"""Provide Jinja2 Helpers."""
from jinja2 import BaseLoader, ChoiceLoader, Environment, TemplateNotFound
from pkg_resources import resource_string
from starlette.templating import Jinja2Templates as _Jinja2Templates


class PkgResourcesTemplateLoader(BaseLoader):
    """Load jinja templates via pkg_resources."""

    @staticmethod
    def get_source(environment: Environment, template: str):
        """Load the template via package resources."""
        source = None
        if ':' in template:
            pkg, resource = template.split(':')
            try:
                source = resource_string(pkg, resource).decode()
            except FileNotFoundError:
                pass
        if source is None:
            raise TemplateNotFound(template)
        return source, None, lambda: True


class Jinja2Templates(_Jinja2Templates):  # noqa: D101
    __doc__ = _Jinja2Templates.__doc__

    def get_env(self, directory: str) -> Environment:
        """Get the environment."""
        env = super().get_env(directory)
        # We want to setup the choice loader here
        env.loader = ChoiceLoader([PkgResourcesTemplateLoader(), env.loader])  # type: ignore[list-item]
        return env
