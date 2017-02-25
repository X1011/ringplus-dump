#!/usr/bin/python

# this script originally written by Chris P., a.k.a. liberal-almond-matte-spider-203286, on the RingPlus forums: https://social.ringplus.net/discussion/comment/149574/#Comment_149574 / http://archive.is/Bm32I#Item_17

# vim: set ts=4 sw=)

import sys
from functools import wraps
from json import loads
from datetime import datetime, timedelta
from time import mktime
try:
    from urllib import urlencode
    from urllib2 import Request, urlopen
    from urlparse import urlsplit, urlunsplit, parse_qsl

    # monkeypatch httpmessage
    from httplib import HTTPMessage
    def get_charset(self):
        try:
            data = filter(lambda s: 'Content-Type' in s, self.headers)[0]
            if 'charset' in data:
                cs = data[data.index(';') + 1:-2].split('=')[1].lower()
                return cs
        except IndexError:
            pass

        return 'utf-8'
    HTTPMessage.get_content_charset = get_charset 
except ImportError: # pragma: no cover
    from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
    from urllib.request import Request, urlopen


class Client(object):
    """ OAuth 2.0 client object
    """

    def __init__(self, auth_endpoint=None, token_endpoint=None,
        resource_endpoint=None, client_id=None, client_secret=None,
        token_transport=None):
        """ Instantiates a `Client` to authorize and authenticate a user

        :param auth_endpoint: The authorization endpoint as issued by the
                              provider. This is where the user should be
                              redirect to provider authorization for your
                              application.
        :param token_endpoint: The endpoint against which a `code` will be
                               exchanged for an access token.
        :param resource_endpoint: The base url to use when accessing resources
                                  via `Client.request`.
        :param client_id: The client ID as issued by the provider.
        :param client_secret: The client secret as issued by the provider. This
                              must not be shared.
        """
        assert token_transport is None or hasattr(token_transport, '__call__')

        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.resource_endpoint = resource_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_transport = token_transport or transport_query
        self.token_expires = -1
        self.refresh_token = None

    def auth_uri(self, redirect_uri=None, scope=None, scope_delim=None, 
        state=None, **kwargs):

        """  Builds the auth URI for the authorization endpoint

        :param scope: (optional) The `scope` parameter to pass for
                      authorization. The format should match that expected by
                      the provider (i.e. Facebook expects comma-delimited,
                      while Google expects space-delimited)
        :param state: (optional) The `state` parameter to pass for
                      authorization. If the provider follows the OAuth 2.0
                      spec, this will be returned to your `redirect_uri` after
                      authorization. Generally used for CSRF protection.
        :param **kwargs: Any other querystring parameters to be passed to the
                         provider.
        """
        kwargs.update({
            'client_id': self.client_id,
            'response_type': 'code',
        })

        if scope is not None:
            kwargs['scope'] = scope

        if state is not None:
            kwargs['state'] = state

        if redirect_uri is not None:
            kwargs['redirect_uri'] = redirect_uri

        return '%s?%s' % (self.auth_endpoint, urlencode(kwargs))

    def request_token(self, parser=None, redirect_uri=None, **kwargs):
        """ Request an access token from the token endpoint.
        This is largely a helper method and expects the client code to
        understand what the server expects. Anything that's passed into
        ``**kwargs`` will be sent (``urlencode``d) to the endpoint. Client
        secret and client ID are automatically included, so are not required
        as kwargs. For example::

            # if requesting access token from auth flow:
            {
                'code': rval_from_auth,
            }

            # if refreshing access token:
            {
                'refresh_token': stored_refresh_token,
                'grant_type': 'refresh_token',
            }

        :param parser: Callback to deal with returned data. Not all providers
                       use JSON.
        """
        kwargs = kwargs and kwargs or {}

        parser = parser or _default_parser
        kwargs.update({
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'grant_type' in kwargs and kwargs['grant_type'] or \
                'authorization_code'
        })
        if redirect_uri is not None:
            kwargs.update({'redirect_uri': redirect_uri})

        # TODO: maybe raise an exception here if status code isn't 200?
        msg = urlopen(self.token_endpoint, urlencode(kwargs).encode('utf-8'))
        data = parser(msg.read().decode(msg.info().get_content_charset() or 'utf-8'))

        # expires_in is RFC-compliant. if anything else is used by the
        # provider, token_expires must be set manually
        print data
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        if hasattr(self, 'expires_in'):
            try:
                # python3 dosn't support long
                seconds = long(self.expires_in)
            except:
                seconds = int(self.expires_in)
            self.token_expires = mktime((datetime.utcnow() + timedelta(
                seconds=seconds)).timetuple())

    def refresh(self):
        self.request_token(refresh_token=self.refresh_token,
            grant_type='refresh_token')

    def request(self, url, method=None, data=None, headers=None, parser=None): 
        """ Request user data from the resource endpoint
        :param url: The path to the resource and querystring if required
        :param method: HTTP method. Defaults to ``GET`` unless data is not None
                       in which case it defaults to ``POST``
        :param data: Data to be POSTed to the resource endpoint
        :param parser: Parser callback to deal with the returned data. Defaults
                       to ``json.loads`.`
        """
        assert self.access_token is not None
        parser = parser or loads 

        if not method:
            method = 'GET' if not data else 'POST'

        req = self.token_transport('{0}{1}'.format(self.resource_endpoint, 
            url), self.access_token, data=data, method=method, headers=headers)

        resp = urlopen(req)
        data = resp.read()
        try:
            return parser(data.decode(resp.info().get_content_charset() or
                'utf-8'))
            # try to decode it first using either the content charset, falling
            # back to utf-8

        except UnicodeDecodeError:
            # if we've gotten a decoder error, the calling code better know how
            # to deal with it. some providers (i.e. stackexchange) like to gzip
            # their responses, so this allows the client code to handle it
            # directly.
            return parser(data)


def transport_headers(url, access_token, data=None, method=None, headers=None):
    try:
        req = Request(url, data=data, method=method)
    except TypeError:
        req = Request(url, data=data)
        req.get_method = lambda: method

    add_headers = {'Authorization': 'Bearer {0}'.format(access_token)}
    if headers is not None:
        add_headers.update(headers)

    req.headers.update(add_headers)
    return req


def transport_query(url, access_token, data=None, method=None, headers=None):
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query.update({
        'access_token': access_token
    })
    url = urlunsplit((parts.scheme, parts.netloc, parts.path,
        urlencode(query), parts.fragment))
    try:
        req = Request(url, data=data, method=method)
    except TypeError:
        req = Request(url, data=data)
        req.get_method = lambda: method

    if headers is not None:
        req.headers.update(headers)

    return req


def _default_parser(data):
    try:
        return loads(data)
    except ValueError:
        return dict(parse_qsl(data))


from flask import Flask
app = Flask(__name__)
@app.route('/')
def homepage():
    text = '<a href="%s">Authenticate with reddit</a>'
    return text % make_authorization_url()

def make_authorization_url():
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    from uuid import uuid4
    state = str(uuid4())
    save_created_state(state)
    params = {"client_id": CLIENT_ID,
              "response_type": "code",
              "state": state,
              "redirect_uri": REDIRECT_URI,
              "duration": "temporary",
              "scope": "identity"}
    import urllib
    url = "https://ssl.reddit.com/api/v1/authorize?" + urllib.urlencode(params)
    return url


'''
# redirect user to authorization page
my_redirect(client.flow.authorization_uri(state=my_state))

# get access token and make a resource request
c.request_token(response_dict)
'''


import webbrowser
from pprint import pprint
from optparse import OptionParser
def main():
    redirect_uri='https://home/chris/ringplus_token.html'
    client = Client(
    	auth_endpoint="https://my.ringplus.net/oauth/authorize",
    	token_endpoint="https://my.ringplus.net/oauth/token",
    	resource_endpoint="https://api.ringplus.net",
    	client_id="1152bde8eefe4584165f666c4b168f017dad38dfd43850656ce94915d0eb816c",
    	client_secret="575e9bcd5b3b3673094599caa4b753e6286c40b9c087ee0a59e79d83c6fdafe1",
    	)
    
    parser = OptionParser()
    parser.add_option("-t", "--token", dest="access_token",
                  help="Launch the app. using specified access_token")
    parser.add_option("-r", "--refresh", dest="refresh_token",
                  help="Use the specified refresh token to get the access_token")
    parser.add_option("-c", "--code", dest="code",
                  help="Use the specified authorization code to get the access_token")
    (options, args) = parser.parse_args()
    
    if not options.access_token and not options.refresh_token:
       if not options.code:
          authorize_url = client.auth_uri(redirect_uri=redirect_uri)
          webbrowser.open(authorize_url)
          sys.stderr.write("Enter authorization 'code' from bad URL: ")
          options.code = raw_input()
    
    if not options.access_token:
       if options.refresh_token:
          client.refresh_token = options.refresh_token
          client.refresh()
       else:
          client.request_token(code=options.code, redirect_uri=redirect_uri)
    else:
       client.access_token = options.access_token
       client.refresh_token = options.refresh_token
    
    # Now that we're authenticated, we can begin to actually use the RingPlus API
    users = client.request('/users')
    sys.stderr.write("\nAuthentication Successful!  Please wait as account data is output ...\n")
    print '\nUsers:'
    pprint(users)
    
    for user in users['users']:
        for acct in user['accounts']:
            acct_id = acct['id']
            acct_name = acct['name']
            acct_phone = acct.get('phone_number', '')
            if acct_phone:
                acct_phone = '(%s)%s-%s' % (acct_phone[1:4], acct_phone[4:7], acct_phone[7:])
            
            print '\n\nAccount %d Details: [%s - %s]' % (acct_id, acct_phone, acct_name)
            acct_obj = client.request('/accounts/%d' % acct_id)
            pprint(acct_obj)
            
            # Save off the voicemail_box ID for later
            voicemail_box = acct_obj['account'].get('voicemail_box', None)
            if voicemail_box:
                voicemail_box = voicemail_box['id']
            
            print '\nAccount %d Call Log: [%s - %s]' % (acct_id, acct_phone, acct_name)
            print 'start_time,direction,originating_phone_number,destination_phone_number,total_time_in_ms,status,cost'
            page = 1
            while True:
                acct_obj = client.request('/accounts/%d/phone_calls?per_page=1000&page=%d' % (acct_id, page))
                #pprint(acct_obj) # All entries, in JSON format
                if not acct_obj['phone_calls']:
                    break
                #pprint(acct_obj['phone_calls'][0])  # First entry only
                for item in acct_obj['phone_calls']:
                    print \
                        item['start_time'] + ',' + \
                        item['direction'] + ',' + \
                        item['originating_phone_number'] + ',' + \
                        item['destination_phone_number'] + ',' + \
                        str(item['total_time_in_ms']) + ',' + \
                        item['status'] + ',' + \
                        '%0.2f' % item['cost']
                page += 1
            print '(%d calls found)' % acct_obj['meta']['count']
            
            print '\nAccount %d Texts Log: [%s - %s]' % (acct_id, acct_phone, acct_name)
            print 'occurred_at,direction,mode,originating_phone_number,destination_phone_number,cost'
            page = 1
            while True:
                acct_obj = client.request('/accounts/%d/phone_texts?per_page=1000&page=%d' % (acct_id, page))
                #pprint(acct_obj) # All entries, in JSON format
                if not acct_obj['phone_texts']:
                    break
                #pprint(acct_obj['phone_texts'][0])  # First entry only
                for item in acct_obj['phone_texts']:
                    print \
                        item['occurred_at'] + ',' + \
                        item['direction'] + ',' + \
                        item['mode'] + ',' + \
                        item['originating_phone_number'] + ',' + \
                        item['destination_phone_number'] + ',' + \
                        '%0.2f' % item['cost']
                page += 1
            print '(%d texts found)' % acct_obj['meta']['count']
            
            print '\nAccount %d Data Usage Log: [%s - %s]' % (acct_id, acct_phone, acct_name)
            print 'occurred_at,mode,quantity_in_bytes'
            page = 1
            while True:
                acct_obj = client.request('/accounts/%d/phone_data?per_page=1000&page=%d' % (acct_id, page))
                #pprint(acct_obj) # All entries, in JSON format
                if not acct_obj['phone_data']:
                    break
                #pprint(acct_obj['phone_data'][0])  # First entry only
                for item in acct_obj['phone_data']:
                    print \
                        item['occurred_at'] + ',' + \
                        item['mode'] + ',' + \
                        str(item['quantity_in_bytes'])
                page += 1
            print '(%d records found)' % acct_obj['meta']['count']
            
            if voicemail_box:
                print '\nAccount %d Voicemail Log: [%s - %s]' % (acct_id, acct_phone, acct_name)
                print 'received_on,sent_by,archived,recording,transcription'
                page = 1
                while True:
                    acct_obj = client.request('/voicemail_boxes/%d/voicemail_messages?per_page=1000&page=%d' % (voicemail_box, page))
                    #pprint(acct_obj) # All entries, in JSON format
                    if not acct_obj['voicemail_messages']:
                        break
                    #pprint(acct_obj['phone_data'][0])  # First entry only
                    for item in acct_obj['voicemail_messages']:
                        print \
                            item['received_on'] + ',' + \
                            item['sent_by'] + ',' + \
                            str(item['archived']) + ',' + \
                            item['recording'] + ',' + \
                            repr(str(item['transcription']))
                    page += 1
                print '(%d voicemail messages found)' % acct_obj['meta']['count']
            
            print ''


if __name__ == "__main__":
    main()

