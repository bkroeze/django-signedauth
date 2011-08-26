import logging
import os
import httplib2
import simplejson
from urllib import urlencode
from signedauth.models import UserKey

log = logging.getLogger(__file__)

def can_loop_over(maybe):
    """Test value to see if it is list like"""
    try:
        iter(maybe)
    except:
        return 0
    else:
        return 1

def is_string_like(maybe):
    """Test value to see if it acts like a string"""
    try:
        maybe+""
    except TypeError:
        return 0
    else:
        return 1

def is_scalar(maybe):
    """Test to see value is a string, an int, or some other scalar type"""
    return is_string_like(maybe) or not can_loop_over(maybe)

def flatten_list(sequence, scalarp=is_scalar, result=None):
    """flatten out a list by putting sublist posts in the main list"""
    if result is None:
        result = []

    for item in sequence:
        if scalarp(item):
            result.append(item)
        else:
            flatten_list(item, scalarp, result)

def flatten(sequence, scalarp=is_scalar):
    """flatten out a list by putting sublist posts in the main list"""
    for item in sequence:
        if scalarp(item):
            yield item
        else:
            for subitem in flatten(item, scalarp):
                yield subitem

def get_flat_list(sequence):
    """flatten out a list and return the flat list"""
    flat = []
    flatten_list(sequence, result=flat)
    return flat

def url_join(*args):
    """Join any arbitrary strings into a forward-slash delimited list.
    Do not strip leading / from first element, nor trailing / from last element."""
    if len(args) == 0:
        return ""

    args = get_flat_list(args)

    if len(args) == 1:
        return str(args[0])

    else:
        args = [str(arg).replace("\\", "/") for arg in args]

        work = [args[0]]
        for arg in args[1:]:
            if arg.startswith("/"):
                work.append(arg[1:])
            else:
                work.append(arg)

        joined = reduce(os.path.join, work)

    return joined.replace("\\", "/")


def remote_json(remote, url, user=None, data=None, method='GET'):
    """
    Gets the dictionary, returned via JSON, from a remote server.
    If "user" is passed, signs the request using that user.
    """
    url = url_join(remote, url)

    if user is not None:
        try:
            key = UserKey.objects.get(user=user)
        except UserKey.DoesNotExist:
            key = UserKey(user=user, active=True)
            key.save()

        url = key.sign_url(url, seed=None)

    log.debug('getting remote url: %s', url)
    http = httplib2.Http()
    if method == 'GET':
        resp, content = http.request(url)
    else:
        resp, content = http.request(url, method, body=urlencode(data))

    #log.debug('response: %s, \ncontent: %s', resp, content)
    if resp['status'] == 200:
        data = simplejson.loads(content)
        log.debug('JSON return: %s', data)
    else:
        data = content
    return resp, data
