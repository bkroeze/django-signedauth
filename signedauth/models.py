from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
import base64
import datetime, time
import hashlib
import logging
import os
import types
import urllib
import urlparse

try:
    parse_qs = urlparse.parse_qs
except AttributeError:
    from cgi import parse_qs

log = logging.getLogger(__name__)

class UserSeed(models.Model):
    """Stores a single "Seed" linked to a User.

    These UserSeeds are automatically removed after expiration by the django command "signedauth_expire",
    which should be set up in a daily cron job.
    """

    user = models.ForeignKey(User, null = True, db_index=True)
    seed = models.CharField('Seed', max_length=44, blank=True, null=False, db_index=True)
    timestamp = models.DateTimeField('Time Stamp', auto_now_add=True)


class UserKey(models.Model):
    """A key associated to a user."""

    label = models.CharField('Label', blank=False, null=False, max_length=10, help_text='Enter anything here to create the key')
    key = models.CharField('Key', blank=False, null=False, max_length=44)
    timestamp = models.DateTimeField('Time Stamp', auto_now_add=True)
    active = models.BooleanField(default=False)
    user = models.ForeignKey(User, null=True)

    def __unicode__(self):
        if not self.user:
            return 'Unsaved userkey'

        username = None
        if self.user:
            username = self.user.username
        return "Userkey for %s=%s" % (username, self.key)

    def save(self, *args, **kwargs):
        """Create the random key and save the object."""

        if not self.key:
            self.key = base64.encodestring(os.urandom(32))[:-1]

        super(UserKey, self).save(*args, **kwargs)

    def sign(self, url, seed=None):
        return sign(url, seed, self.key)

    def sign_url(self, url, seed=None):
        """Sign an url.

        Args:
            url: An url to sign.  It can have query parameters which will be preserved.
                 If there is no "seed" provided as a keyword arg, it will look in the
                 query params for it before finally simply giving up and using the
                 current timestamp as the seed.

        Kwargs:
            seed: An explicit seed string to use for signing.

        Returns:
            The same url, with its signature added to the querystring.
        """
        username = None
        if self.user:
            username = self.user.username

        return sign_url(url, username, self.key, seed)

    def verify(self, work, seed, sig):
        """Validate that the signature for 'work' is 'sig'

        Args:
            work: the string to verify
            seed: the seed to use
            sig: the signature to validate

        Returns:
            Boolean result
        """
        username = None
        if self.user:
            username = self.user.username

        return verify(username, work, seed, self.key, sig)

    def verify_url(self, url):
        """Validate a signed url using this key.

        Args:
            url: the signed url

        Returns:
            A two-member tuple: (Boolean status of validation, Message string)
        """

        if not self.active:
            return (False, 'UserKey not active')

        username = None
        if self.user:
            username = self.user.username

        log.debug('verifying url %s user %s, key %s', url, username, self.key)
        return verify_url(url, username, self.key)

# maybe monkeypatch user to use UserKey as its profile without forcing all users to have keys
if settings.AUTH_PROFILE_MODULE == 'signedauth.UserKey':
    User.profile = property(lambda u: UserKey.objects.get_or_create(user=u)[0])

class WhitelistedIPManager(models.Manager):
    def request_is_whitelisted(self, request):
        """Tests whether the request's IP is whitelisted.

        Args:
            request: A django Request object

        Returns:
            Boolean
        """

        ip = request.META.get('REMOTE_ADDR', None)
        return self.ip_is_whitelisted(ip)

    def whitelisted_user(self, request = None, ip = None):
        """Returns the whitelisted user, else None"""
        if not ip and request is not None:
            ip = request.META.get('REMOTE_ADDR', None)

        if ip is not None and ip:
            white = self.filter(ip=ip)
            if white.count() > 0:
                return white[0].user
        return None

    def ip_is_whitelisted(self, ip):
        """Tests whether the request's IP is whitelisted.

        Args:
            IP: a string representing the IP to be tested

        Returns:
            Boolean
        """
        return ip is not None and ip and self.filter(ip = ip).count() > 0

class WhitelistedIP(models.Model):
    """A single IP Address that doesn't have to explicitly
    provide signatures to be authenticated as the attached user."""

    label = models.CharField("Label", max_length=30)
    ip = models.IPAddressField("Ip Address", db_index=True)
    user = models.ForeignKey(User)

    objects = WhitelistedIPManager()

    def __unicode__(self):
        return u"%s: %s = %s" % (self.label, self.ip, self.user.username)

class WhitelistedDomainManager(models.Manager):
    def request_is_whitelisted(self, request):
        """Tests whether the request's domain is whitelisted.

        Args:
            request: A django Request object

        Returns:
            Boolean
        """

        domain = request.META.get('HTTP_REFERER', None)
        return self.domain_is_whitelisted(domain)

    def whitelisted_user(self, request = None, domain = None):
        """Returns the whitelisted user, else None"""
        if not domain and request is not None:
            domain = request.META.get('HTTP_REFERER', None)

        if not domain:
            return None

        url = urlparse.urlsplit(domain)
        domain = url.netloc
        domain = domain.split(':')[0]
        # now get just the last part, if needed
        parts = domain.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[1:])
        else:
            subdomain = 'INVALID'

        if domain is not None and domain:
            white = self.filter(models.Q(domain=domain) | models.Q(domain=subdomain, subdomains=True))
            if white.count() > 0:
                return white[0].user
        return None

    def domain_is_whitelisted(self, domain):
        """Tests whether the request's domain is whitelisted.

        Args:
            domain: a string representing the domain to be tested

        Returns:
            Boolean
        """
        return domain is not None and domain and self.filter(domain = domain).count() > 0

class WhitelistedDomain(models.Model):
    """A domain or group of domains that don't have to explicitly
    provide signatures to be authenticated at the attached user."""

    label = models.CharField("Label", max_length=30)
    domain = models.CharField("Domain name", db_index=True, max_length=100)
    subdomains = models.BooleanField("Include Subdomains?", default=False)
    user = models.ForeignKey(User)

    objects = WhitelistedDomainManager()

    def __unicode__(self):
        return u"%s: %s = %s" % (self.label, self.domain, self.user.username)


def sign_url(url, user, key, seed=None):
    """Sign an url.

    Args:
        url: An url to sign.  It can have query parameters which will be preserved.
             If there is no "seed" provided as a keyword arg, it will look in the
             query params for it before finally simply giving up and using the
             current timestamp as the seed.
        user: the username
        key: the key to use

    Kwargs:
        seed: An explicit seed string to use for signing.

    Returns:
        The same url, with its signature added to the querystring.
    """
    origurl = url
    parsed = urlparse.urlsplit(url)
    query = parsed.query
    qs = parse_qs(query)


    if not seed:
        # first look at query
        if 'seed' in qs:
            seed = qs['seed']
            query = _remove_query_param(query,'seed')
        else:
            timestamp = datetime.datetime.now()
            timestamp = time.mktime(timestamp.timetuple())
            seed = str(int(timestamp))
            log.debug('sign_url: no seed, using timestamp %s', seed)

    if user:
        if 'user' in qs:
            username = qs['user']
            if type(username) is types.ListType:
                username = username[0]
            if username != user:
                query = _replace_query_param(query, 'user', user)
        else:
            query = _add_query_param(query, 'user', user)
    else:
        if 'user' in qs:
            query = _remove_query_param(query, 'user')

    url = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    sig = sign(url, seed, key)
    query = _add_query_param(query, 'seed', seed)
    query = _add_query_param(query, 'sig', sig)

    url = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
    log.debug('Signed %s = %s', origurl, url)
    return url

def sign(work, seed, key):
    """Sign a string with the given seed.

    Args:
        work: The string to sign
        seed: The seed to use as part of the signature
        key: the key to use to sign

    Returns:
        The hexdigest of the signature string

    """
    log.debug('Signing: "%s" with seed "%s"', work, seed)
    processor = hashlib.md5(work)
    processor.update(seed)
    processor.update(key)
    sig = processor.hexdigest()
    return sig.lower()

def verify(user, work, seed, key, sig):
    goodsig = sign(work, seed, key)
    if goodsig != sig:
        log.debug('Signature mismatch: %s != %s', sig, goodsig)
        return False
    return True

def verify_url(url, user, key):
    """Validate a signed url using this key.

    Args:
        url: the signed url
        user: username
        key: key

    Returns:
        A two-member tuple: (Boolean status of validation, Message string)
    """

    log.debug('verify url: %s, user %s, key %s', url, user, key)

    origurl = url
    parsed = urlparse.urlsplit(url)
    query = parsed.query
    qs = parse_qs(query)

    if not 'seed' in qs:
        log.debug('No seed in: %s', origurl)
        return (False, 'No seed in url')

    if user is not None:
        log.debug('user is not none')
        if not 'user' in qs:
            log.debug('No user in: %s', origurl)
            return (False, 'No user in url')
        user = qs['user']
        if type(user) is types.ListType:
            user = user[0]
        if user != user:
            log.debug('Username mismatch: %s != %s', user, user)
            return (False, 'Wrong user')
        try:
            u = User.objects.get(username=user)
            if not u.is_active:
                log.debug('User not active: %s', user)
                return (False, 'User not active')
        except User.DoesNotExist:
            return (False, 'User does not exist')


    elif 'user' in qs:
        log.debug('no user, checking in qs')
        log.debug('No user should be sent for an anonymous query: %s', url)
        return(False, 'No user should be sent for an anonymous query')

    else:
        u = None

    if not 'sig' in qs:
        log.debug('No sig in: %s', origurl)
        return (False, 'URL is not signed')

    seed = qs['seed']
    query = _remove_query_param(query, 'seed')
    if type(seed) is types.ListType:
        seed = seed[0]

    seedobj, created = UserSeed.objects.get_or_create(user=u, seed=seed)

    if created:
        log.debug('Disallowing seed reuse: %s', seed)
        return (False, 'Signature invalid - seed has been used')

    sig = qs['sig']
    query = _remove_query_param(query, 'sig')
    if type(sig) is types.ListType:
        sig = sig[0]
    sig.lower()

    url = urlparse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    if not verify(user, url, seed, key, sig):
        return (False, 'Signature does not validate')

    return (True,'OK')

def _add_query_param(query, param, val):
    """Add a querystring parameter to the url"""

    last = '%s=%s' % (param, urllib.quote_plus(val))
    if query:
        return "%s&%s" % (query, last)
    else:
        return last

def _remove_query_param(query, param):
    """Removes a query param, leaving the querystring in order"""
    parts = query.split('&')
    look = "%s=" % param
    for ix in range(len(parts)-1, -1, -1):
        if parts[ix].startswith(look):
            del parts[ix]

    return '&'.join(parts)

def _replace_query_param(query, param, val):
    """Replaces a query param, leaving the querystring in order"""
    parts = query.split('&')
    look = "%s=" % param
    for ix in range(0, len(parts)):
        if parts[ix].startswith(look):
            parts[ix] = "%s=%s" % (param, urllib.quote_plus(val))
            break
    return '&'.join(parts)
