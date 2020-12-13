"""Utilities."""

def bool_from_env(env_value):
    """Convert environment variable to boolean."""
    if isinstance(env_value, str):
        env_value = env_value.lower() in ['true', '1']
    return env_value


def list_from_env(env_value):
    """Convert environment variable to list."""
    if isinstance(env_value, str):
        env_value = [u for u in env_value.split(',') if u]
    return env_value


def expand_doc(klass):
    """Expand pydantic model documentation to enable autodoc."""
    docs = ['', '', 'Keyword Args:']
    for name, field in klass.__fields__.items():
        default_str = ''
        if field.default:
            default_str = f' [default: ``{field.default}``]'
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
