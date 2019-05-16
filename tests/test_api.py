import pytest


def get_user_token(client, user):
    '''Use API to get user's token for use in calls to API.'''
    
    response = client.get('/api/get_token')

    json_data = response.get_json()

    token = json_data['token']

    return token


def test_get_token_works(client, user4):
    token = get_user_token(client, user4)
    response = client.get('/api/check_token', 
                          query_string={'token': token},
                          data=dict(username='tester4'),
                          follow_redirects=True)

    json_data = response.get_json()
    assert (json_data['status'] == 'Ok' and 
            json_data['message'] == 'Success! The token works.')