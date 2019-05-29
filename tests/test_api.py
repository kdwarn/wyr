'''
    TODO:
        - test created clients in settings
        - disable email to WYR about client registration unless explicitly enabled? (to avoid
          emails while testing)
'''

import pytest

from app import models


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

