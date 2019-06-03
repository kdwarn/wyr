'''
    TODO:
        - disable email to WYR about client registration unless explicitly enabled? (to avoid
          emails while testing)
'''

import datetime
import time

import jwt
import pytest

from app import models
from app import api


# def get_user_token(client, user):
#     '''Use API to get user's token for use in calls to API.'''
    
#     response = client.get('/api/get_token')

#     json_data = response.get_json()

#     token = json_data['token']

#     return token


# def test_get_token_works(client, user4):
#     token = get_user_token(client, user4)
#     response = client.get('/api/check_token',
#                           query_string={'token': token},
#                           data=dict(username='tester4'),
#                           follow_redirects=True)

#     json_data = response.get_json()
#     assert (json_data['status'] == 'Ok' and
#             json_data['message'] == 'Success! The token works.')


###################
# CLIENT CREATION #
###################

valid_client_vars = {'submit': 'register', 
                     'name': 'Tester App', 
                     'description': 'This is a test client app',
                     'callback_url': 'https://www.test.com'}


def test_create_client_app1(client, user4):
    ''' Minimal test that client is created.'''
    response = client.post('/api/clients',
                           data=valid_client_vars,
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'Client registered' in response.data and
            len(clients) == 1)


def test_create_client_redirect_log_in_page(client, user3):
    '''Client registration takes developer to main page if not logged in (as regular WYR user).'''
    response = client.post('/api/clients',
                           data=valid_client_vars,
                           follow_redirects=True)
    clients = models.Client.query.all()
    print(response.data)
    assert (b'Welcome!' in response.data and
            len(clients) == 0)


def test_create_client_cancelled(client, user4):
    ''' Test cancel client registration.'''
    response = client.post('/api/clients',
                           data=dict(submit='cancel',
                                     name='Test',
                                     description='This is a test client app',
                                     callback_url='https://www.test.com'),
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'Client registration canceled.' in response.data and
            len(clients) == 0)


@pytest.mark.parametrize('name, description, callback_url',
                         [('', 'a simple app', 'https://example.com'),
                          ('Mobile WYR', '', 'https://example.com'),
                          ('Mobile WYR', 'a simple app', ''),
                          ])
def test_create_client_error1(client, user4, name, description, callback_url):
    ''' Developer returned to registration page if any form data missing.'''
    response = client.post('/api/clients',
                           data=dict(submit='register',
                                     name=name,
                                     description=description,
                                     callback_url=callback_url),
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'Please complete all required fields.' in response.data and
            len(clients) == 0)


def test_create_client_app_error2(client, user4):
    ''' Callback_url must be HTTPS.'''
    response = client.post('/api/clients',
                           data=dict(submit='register',
                                     name='Test',
                                     description='This is a test client app',
                                     callback_url='http://www.test.com'),
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'The callback URL must use HTTPS.' in response.data and
            len(clients) == 0)


def test_developer_has_client(client, developer1):
    response = client.get('/api/clients')
    assert b'Tester App' in response.data


#############################
# USER AUTHORIZATION OF APP #
#############################


def test_create_token(user6, developer1):
    dev_client = models.Client.query.first()

    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = api.create_token(user6, dev_client.client_id, expiration)

    assert 1 == 2


def test_decode_token1(user6, developer1):
    dev_client = models.Client.query.first()

    code = api.create_token(user6, dev_client.client_id)

    decoded = jwt.decode(code, user6.salt)

    assert decoded['username'] == 'tester6'




def test_decode_token_raises_ex_with_bad_salt(user6, developer1):
    dev_client = models.Client.query.first()
    code = api.create_token(user6, dev_client.client_id)

    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        decoded = jwt.decode(code, 'bad_salt')


def test_authorization1(client, user6, developer1):
    ''' callback_url and code and state passed into redirect'''
    dev_client = models.Client.query.first()
    
    response = client.post('/api/authorize',
                           data=dict(submit="Yes",
                                     client_id=dev_client.client_id,
                                     state='xyz'),
                           follow_redirects=False)
    
    
    assert (dev_client.callback_url in response.headers['Location'] and
        'code' in response.headers['Location'] and 
        'state' in response.headers['Location'])


def test_get_token1(client, user6, developer1):
    ''' Testing getting a token, directly creating authorization code here.'''

    dev_client = models.Client.query.first()
    
    code = api.create_token(user6, dev_client.client_id)

    response = client.post('/api/token',
                           data=dict(client_id=dev_client.client_id, 
                                     grant_type='authorization_code',
                                     code=code),
                           follow_redirects=True)
                           
    # access_token = jwt.decode(response.get_json()['access_token'], user6.salt)
    print(response.status)
    print(response.status_code)
    print(response.headers)
    print(response.mimetype)
    print(response.get_json())
    # access_token = jwt.decode(response.get_json()['access_token'], user6.salt)
    # assert access_token['username'] == user6.username
    assert 1 == 2

def test_get_token_error1(client, user6, developer1):
    ''' grant_type has to be authorization_code '''

    dev_client = models.Client.query.first()
    
    code = api.create_token(user6, dev_client.client_id)

    response = client.post('/api/token',
                           data=dict(client_id=dev_client.client_id, 
                                     grant_type='authorizationcode',
                                     code=code),
                           follow_redirects=True)

    assert b'grant_type must be set to' in response.data


def test_get_token_error2(client, user6, developer1):
    ''' Code can't be manipulated.'''

    dev_client = models.Client.query.first()

    code = "this is a bad code"

    response = client.post('/api/token',
                            data=dict(client_id=dev_client.client_id, 
                                        grant_type='authorization_code',
                                        code=code),
                            follow_redirects=True)

    json = response.get_json()

    assert json['error'] == 94


def test_get_token_error4(client, user6, developer1):
    ''' Code cannot be expired '''
    # because I don't know how to get it from the redirect

    dev_client = models.Client.query.first()

    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=-2)
    code = api.create_token(user6, dev_client.client_id, expiration)

    response = client.post('/api/token',
                            data=dict(client_id=dev_client.client_id, 
                                        grant_type='authorization_code',
                                        code=code),
                            follow_redirects=True)

    json = response.get_json()

    assert json['error'] == 93
