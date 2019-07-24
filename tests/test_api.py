'''
    TODO:
        - disable email to WYR about client registration unless explicitly enabled? (to avoid
          emails while testing) (haven't set this up yet in api.py)
        - testing editing client info
'''


import datetime
import time

import jwt
import pytest

from app import models
from app import api


####################
# CREATING TOKENS #
####################

# not specific to authorization code or access token

def test_create_token1(user6):
    ''' Test code creation works, without verification. '''
    
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    code = api.create_token(user6, 1, expiration)
    
    decoded = jwt.decode(code, verify=False)

    assert decoded['username'] == 'tester6'


def test_create_token2(user6):
    ''' create_token creates default expiration if expiration not passed to it '''
    code = api.create_token(user6, 1)

    decoded = jwt.decode(code, verify=False)

    assert decoded['exp']


def test_decode_token_raises_ex_with_bad_salt(user6, dev_app):
    
    code = api.create_token(user6, dev_app.client_id)

    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        jwt.decode(code, 'bad_salt')


############################################################
# CHECKING TOKINS, INCLUDING THE @TOKEN_REQUIRED DECORATOR #
############################################################

# calling check_token here partly as a way to test @token_required

def test_check_token1(flask_client, user4, dev_app):
    ''' If valid token supplied, client receives message that the token works.'''
    
    token = api.create_token(user4, dev_app.client_id)

    response = flask_client.get('/api/check_token',
                                json={'token': token,
                                      'username': 'tester4'},
                                follow_redirects=True)

    json_data = response.get_json()
    
    assert (json_data['status'] == 'Ok' and
            json_data['message'] == 'Success! The token works.')


def test_check_token_returns_error1(flask_client):
    ''' If token not provided in call to check_token(), error provided to client. '''

    response = flask_client.get('/api/check_token',
                                json={'username': 'tester4'},
                                follow_redirects=True)

    json_data = response.get_json()
    
    assert json_data['error'] == 91


def test_check_token_returns_error2(flask_client):
    ''' If username not provided in call to check_token(), error provided to client. '''

    response = flask_client.get('/api/check_token',
                                json={'token': 'some token'},
                                follow_redirects=True)

    json_data = response.get_json()
    
    assert json_data['error'] == 95


def test_check_token_returns_error3(flask_client, user4, user1, dev_app):
    ''' 
    Username sent in request must match username in decoded token sent.
    '''

    user4_token = api.create_token(user4, dev_app.client_id)

    response = flask_client.get('/api/check_token',
                                json={'token': user4_token, 
                                      'username': 'tester1'},
                                follow_redirects=True)

    json_data = response.get_json()
    print(json_data)
    
    assert json_data['error'] == 96


def test_check_token_returns_error4(flask_client):
    ''' 
    Check that manipulated/incomplete token returns error resulting from DecodeError exception.
    '''

    response = flask_client.get('/api/check_token',
                                json={'token': 'this is not a valid token', 
                                              'username': 'tester4'},
                                follow_redirects=True)

    json_data = response.get_json()
    
    assert json_data['error'] == 94


# access token testing

def test_get_access_token1(flask_client, user6, dev_app):
    ''' Getting an access token works properly. '''
    
    # create authorization code, which the client would have received via authorize()
    code = api.create_token(user6, dev_app.client_id)

    response = flask_client.post('/api/token',
                           data=dict(client_id=dev_app.client_id, 
                                     grant_type='authorization_code',
                                     code=code),
                           follow_redirects=True)
                           
    # decode the access_token provided to client
    access_token = jwt.decode(response.get_json()['access_token'], user6.salt)

    assert (response.status_code == 200 and 
            response.headers['Cache-Control'] == 'no-store' and
            response.headers['Pragma'] == 'no-cache' and 
            response.is_json and 
            access_token['username'] == 'tester6') 


def test_get_access_token_error1(flask_client, user6, dev_app):
    ''' grant_type has to be authorization_code '''
    
    code = api.create_token(user6, dev_app.client_id)

    response = flask_client.post('/api/token',
                           data=dict(client_id=dev_app.client_id, 
                                     grant_type='authorizationcode',
                                     code=code),
                           follow_redirects=True)

    assert b'grant_type must be set to' in response.data


def test_get_access_token_error2(flask_client, user6, dev_app):
    ''' Code can't be manipulated.'''

    code = "this is a bad code"

    response = flask_client.post('/api/token',
                            data=dict(client_id=dev_app.client_id, 
                                        grant_type='authorization_code',
                                        code=code),
                            follow_redirects=True)

    json = response.get_json()

    assert json['error'] == 94


def test_get_access_token_error4(flask_client, user6, dev_app):
    ''' Code cannot be expired '''

    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=-2)
    code = api.create_token(user6, dev_app.client_id, expiration)

    response = flask_client.post('/api/token',
                            data=dict(client_id=dev_app.client_id, 
                                        grant_type='authorization_code',
                                        code=code),
                            follow_redirects=True)

    json = response.get_json()

    assert json['error'] == 93


###################
# CLIENT CREATION #
###################

# for ad-hoc creation of client app
valid_client_vars = {'submit': 'register', 
                     'name': 'Tester App Ad Hoc', 
                     'description': 'This is a test client app',
                     'callback_url': 'https://www.test.com'}

def test_dev_app_fixture_info(dev_app, developer1):
    ''' Test that the dev_app fixture was created properly. '''
    client = models.Client.query.first()
    assert (client.user_id == developer1.id and
            client.name == 'Tester App 1' and 
            client.description == 'Testing app development' and
            client.callback_url == 'https://www.whatyouveread.com/example')


def test_create_client_redirect_log_in_page(flask_client, user3):
    '''Client registration takes developer to main page if not logged in.'''
    response = flask_client.post('/api/clients',
                           data=valid_client_vars,
                           follow_redirects=True)
    clients = models.Client.query.all()
    print(response.data)
    assert (b'Welcome!' in response.data and
            len(clients) == 0)


def test_create_client_cancelled(flask_client, user4):
    ''' Test cancel client registration.'''
    response = flask_client.post('/api/clients',
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
def test_create_client_error1(flask_client, user4, name, description, callback_url):
    ''' Developer returned to registration page if any form data missing.'''
    response = flask_client.post('/api/clients',
                           data=dict(submit='register',
                                     name=name,
                                     description=description,
                                     callback_url=callback_url),
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'Please complete all required fields.' in response.data and
            len(clients) == 0)


def test_create_client_error2(flask_client, user4):
    ''' Callback_url must be HTTPS.'''
    response = flask_client.post('/api/clients',
                           data=dict(submit='register',
                                     name='Test',
                                     description='This is a test client app',
                                     callback_url='http://www.test.com'),
                           follow_redirects=True)
    clients = models.Client.query.all()
    assert (b'The callback URL must use HTTPS.' in response.data and
            len(clients) == 0)


def test_create_client_sucessful1(flask_client, developer1):
    ''' Created client shows in the database.'''
    flask_client.post('/api/clients',
                      data=valid_client_vars,
                      follow_redirects=True)
    clients = models.Client.query.all()
    assert len(clients) == 1


def test_create_client_sucessful2(flask_client, developer1):
    ''' Proper response is given after client created and is listed in apps. '''
    response = flask_client.post('/api/clients',
                           data=valid_client_vars,
                           follow_redirects=True)
    
    assert (b'Client registered' in response.data and
            b'Tester App Ad Hoc' in response.data)


def test_create_client_sucessful3(flask_client, developer1, dev_app):
    ''' A second created client shows in the database.'''
    flask_client.post('/api/clients',
                      data=valid_client_vars,
                      follow_redirects=True)
    clients = models.Client.query.all()
    assert len(clients) == 2


def test_create_client_sucessful4(flask_client, developer1, dev_app):
    ''' A second client created is listed in apps. '''
    response = flask_client.post('/api/clients',
                                 data=valid_client_vars,
                                 follow_redirects=True)

    assert (b'Tester App 1' in response.data and
            b'Tester App Ad Hoc' in response.data)


#############################
# USER AUTHORIZATION OF APP #
#############################

def test_app_authorization_get1(flask_client, user1):
    ''' User is redirected to login page if they are not logged in.'''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '1',
                                        'response_type': 'not_code'},
                          follow_redirects=True)

    assert b'Welcome!' in response.data


def test_app_authorization_get2(flask_client, user6):
    ''' **code** must be passed set to 'code' '''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '1',
                                        'response_type': 'not_code'},
                          follow_redirects=True)
    
    assert b'Query parameter response_type must be set to ' in response.data


def test_app_authorization_get3(flask_client, user6):
    ''' **code** must be passed set to 'code' '''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '1',
                                        'response_type': 'not_code'},
                          follow_redirects=True)
    
    assert b'Query parameter response_type must be set to ' in response.data


def test_app_authorization_get4(flask_client, user6):
    ''' **code** must be passed set to 'code' '''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '1',
                                        'response_type': ''},
                          follow_redirects=True)
    
    assert b'Query parameter response_type must be set to ' in response.data


def test_app_authorization_get5(flask_client, user6, dev_app):
    ''' 
    *client_id* must be id of a registered client.
     
    '''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '500',
                                        'response_type': 'code'},
                          follow_redirects=True)
    
    assert b'No third-party app found matching request. Authorization failed.' in response.data


def test_app_authorization_get6(flask_client, user6, dev_app):
    ''' 
    *client_id* must be id of a registered client.
     
    '''
    response = flask_client.get('/api/authorize',
                          query_string={'client_id': '',
                                        'response_type': 'code'},
                          follow_redirects=True)
    
    assert b'No third-party app found matching request. Authorization failed.' in response.data


# TODO: do the client_id and code have to match up? figure this out and test those cases if so

def test_app_authorization_get7(flask_client, user6, dev_app):
    ''' User presented with authorization form if all checks pass. '''
    assert False


def test_app_authorization_post1(flask_client, user6, dev_app):
    ''' callback_url and code and state passed into redirect'''
    
    response = flask_client.post('/api/authorize',
                           data=dict(submit="Yes",
                                     client_id=dev_app.client_id,
                                     state='xyz'),
                           follow_redirects=False)
    
    
    assert (dev_app.callback_url in response.headers['Location'] and
        'code' in response.headers['Location'] and 
        'state' in response.headers['Location'])


###############################
# GETTING PROTECTED RESOURCES #
###############################

def test_document_get1(flask_client, user4, dev_app):

    # get user's first document
    doc = user4.documents.first()

    token = api.create_token(user4, dev_app.client_id)

    response = flask_client.get('/api/documents/' + str(doc.id),
                                json={'token': token,
                                      'username': 'tester4'})
    
    json_data = response.get_json()
    
    assert (json_data['title'] == 'First user doc' and  
           json_data['url'] ==  'http://whatyouveread.com/1' and 
           json_data['year'] == '2018' and 
           'Smith, Joe' in json_data['authors'] and 
           'Smith, Jane' in json_data['authors'] and
           'tag0' in json_data['tags'] and
           'tag1' in json_data['tags'] and
           json_data['note'] == 'This is a note.')