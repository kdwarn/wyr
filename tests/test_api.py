import uuid

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

def test_create_client_app1(client):
    ''' Minimal test that client is created.'''
    id = uuid.uuid4().hex
    response = client.post('/api/register_client',
                           data=dict(submit='register',
                                       client_id=id,
                                       client_type='public',
                                       name='Test',
                                       description='This is a test client app',
                                       callback_url='https://www.test.com'),
                           follow_redirects=True)
    clients = models.Client.query.all()
    one_client = models.Client.query.first()
    assert (b'Client registered' in response.data and
            len(clients) == 1)
