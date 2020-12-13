

def with_redirect(url, post_redirect=None):
    if post_redirect is not None:
        url = f'{url}?redirect={post_redirect}'
    return url


def append(base_url, *args):
    extension = '/'.join([u.strip('/') for u in args])
    if extension:
        url = base_url.rstrip('/')+'/'+extension
    else:
        url = base_url
    return url
