import uuid

import pytest
from passlib.context import CryptContext

from app import datetimeformat, nl2br, generate_csrf_token
from app import create_app, models, db
from app import common

class TestConfig():
    TESTING = True
    SECRET_KEY = 'thisissecret'
    SECURITY_PASSWORD_SALT = 'alsosecret'
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

'''
User fixtures:
    - user0: no documents, not logged in
    - user1: 4 documents, not logged in
    - user2: 4 documents, not logged in
    - user3: 4 documents, hashed pass, not logged in
    - user4: 4 documents, hashed pass, logged in
    - user5: 5 documents, with 4 bunches, hashed pass, logged in,
    - user6: no documents, hashed pass, logged in
'''

@pytest.fixture
def client():
    test_app = create_app(TestConfig)
    client = test_app.test_client()

    with test_app.app_context():
        db.create_all()

        # needed for all templates (in route testing)
        test_app.jinja_env.globals['csrf_token'] = generate_csrf_token

        # needed for some templates (in route testing)
        test_app.jinja_env.filters['datetime'] = datetimeformat
        test_app.jinja_env.filters['nl2br'] = nl2br

        yield client

        db.session.remove()
        db.drop_all()


@pytest.fixture
def user0(client):
    '''Create a user with no documents.'''

    user0 = models.User('tester0', 'testing0', 'testing123', 'test0@whatyouveread.com')
    db.session.add(user0)
    db.session.commit()

    return user0


@pytest.fixture
def user1(client, four_items):
    '''Create a user with four documents.'''

    user1 = models.User('tester1', 'testing', 'testing123', 'test1@whatyouveread.com')
    db.session.add(user1)
    db.session.commit()

    for item in four_items:
        common.add_item(item, user1)

    return user1


@pytest.fixture
def user2(client, four_items):
    '''Create a separate user with four documents.'''

    user2 = models.User('tester2', 'testing2', 'testing1234', 'test2@whatyouveread.com')
    db.session.add(user2)
    db.session.commit()

    for item in four_items:
        common.add_item(item, user2)

    return user2


@pytest.fixture
def user3(client, four_items):
    '''
    Create a user with hashed password and salt, as in the registration
    process.
    '''

    myctx = CryptContext(schemes=['pbkdf2_sha256'])
    hashed_password = myctx.hash('testing3')

    user3 = models.User('tester3', hashed_password, 'testing123', 'test3@whatyouveread.com')
    db.session.add(user3)
    db.session.commit()

    for item in four_items:
        common.add_item(item, user3)

    return user3


@pytest.fixture
def user4(client, four_items):
    '''
    Create a user with hashed password and salt, as in the registration
    process, with four items, and log them in.
    '''

    myctx = CryptContext(schemes=['pbkdf2_sha256'])
    hashed_password = myctx.hash('testing4')

    user4 = models.User('tester4', hashed_password, 'testing123', 'test4@whatyouveread.com')
    db.session.add(user4)
    db.session.commit()

    for item in four_items:
        common.add_item(item, user4)

    client.post('/login', data=dict(
        wyr_username='tester4',
        wyr_password='testing4',
        remember='',
        next=''
    ), follow_redirects=True)

    return user4


@pytest.fixture
def user5(client, five_items):
    '''
    Create a user with hashed password and salt, as in the registration
    process, with five items and two bunches, and log them in.
    '''

    myctx = CryptContext(schemes=['pbkdf2_sha256'])
    hashed_password = myctx.hash('testing5')

    user5 = models.User('tester5', hashed_password, 'testing123', 'test5@whatyouveread.com')
    db.session.add(user5)
    db.session.commit()

    for item in five_items:
        common.add_item(item, user5)

    # create a bunch for this user, using "or" to combine tags
    # (four documents meet this criteria, 2 read and 2 to-read)
    selector = 'or'
    bunch_name = 'bunch 1'
    bunch_tags = [1, 3]  # tag4 and tag6

    new_bunch = models.Bunches(user5.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    for tag in bunch_tags:
        existing_tag = models.Tags.query.filter(models.Tags.id==tag).one()
        new_bunch.tags.append(existing_tag)    

    # create a second bunch, using "and" to combine tags
    # (2 documents meet this criteria, 1 read and 1 to-read)
    selector = 'and'
    bunch_name = 'bunch 2'
    bunch_tags = [1, 3]  # tag4 and tag6

    new_bunch = models.Bunches(user5.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    for tag in bunch_tags:
        existing_tag = models.Tags.query.filter(models.Tags.id==tag).one()
        new_bunch.tags.append(existing_tag)

    # create a third bunch, using "and" to combine tags
    # (1 unread document meets this criteria)
    selector = 'and'
    bunch_name = 'bunch 3'
    bunch_tags = [4, 5]  # tag7 and tag7

    new_bunch = models.Bunches(user5.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    for tag in bunch_tags:
        existing_tag = models.Tags.query.filter(models.Tags.id==tag).one()
        new_bunch.tags.append(existing_tag)

    # create a fourt bunch, using "and" to combine tags
    # (1 read document meets this criteria)
    selector = 'and'
    bunch_name = 'bunch 4'
    bunch_tags = [1, 2]  # tag4 and tag5

    new_bunch = models.Bunches(user5.id, selector, bunch_name)
    db.session.add(new_bunch)
    db.session.commit()

    for tag in bunch_tags:
        existing_tag = models.Tags.query.filter(models.Tags.id==tag).one()
        new_bunch.tags.append(existing_tag)

    # log user in
    client.post('/login', data=dict(
        wyr_username='tester5',
        wyr_password='testing5',
        remember='',
        next=''
    ), follow_redirects=True)

    return user5


@pytest.fixture
def user6(client):
    '''
    Create a user with hashed password and salt, as in the registration
    process, with no items, and log them in.
    '''

    myctx = CryptContext(schemes=['pbkdf2_sha256'])
    hashed_password = myctx.hash('testing6')

    user6 = models.User('tester6', hashed_password, 'testing123', 'test6@whatyouveread.com')
    db.session.add(user6)
    db.session.commit()

    client.post('/login', data=dict(
        wyr_username='tester6',
        wyr_password='testing6',
        remember='',
        next=''
    ), follow_redirects=True)

    return user6


@pytest.fixture
def developer1(client):
    '''
    Create a user with hashed password and salt, as in the registration
    process, with one third-party app, and log them in.
    '''

    myctx = CryptContext(schemes=['pbkdf2_sha256'])
    hashed_password = myctx.hash('developer123')

    developer1 = models.User('developer1', hashed_password, 'testing123', 'test6@whatyouveread.com')
    db.session.add(developer1)
    db.session.commit()

    client_id = uuid.uuid4().hex
    name = 'Tester App'
    description = 'Testing app development'
    callback_url = 'https://example.com'

    app_client = models.Client(client_id, developer1.id, name, description, callback_url)
    db.session.add(app_client)
    db.session.commit()

    # log user in
    client.post('/login', data=dict(
        wyr_username='developer1',
        wyr_password='developer123',
        remember='',
        next=''
    ), follow_redirects=True)

    return developer1


@pytest.fixture
def four_items():
    items = []
    items.append({'title': 'First user doc',
                    'link': 'http://whatyouveread.com/1',
                    'tags': ['tag0', 'tag1'],
                    'authors': [
                                {'last_name': 'Smith', 'first_name': 'Joe'},
                                {'last_name': 'Smith', 'first_name': 'Jane'}
                                ],
                    'year': '2018',
                    'notes': 'This is a note.',
                    'read': '1'})
    items.append({'title': 'Second user doc',
                    'link': 'http://whatyouveread.com/2',
                    'tags': ['tag2', 'tag3', 'tag4'],
                    'authors': [
                                {'last_name': 'Johnson', 'first_name': 'Joe'},
                                {'last_name': 'Johnson', 'first_name': 'Jane'}
                               ],
                    'year': '2017',
                    'notes': 'This is also a note.',
                    'read': '0'})
    items.append({'title': 'Third user doc',
                    'link': 'http://whatyouveread.com/3',
                    'tags': ['tag0', 'tag2'],
                    'authors': [
                                {'last_name': 'Smith', 'first_name': 'Jane'},
                                {'last_name': 'Johnson', 'first_name': 'Jane'}
                               ],
                    'year': '2019',
                    'notes': 'This is also a note.',
                    'read': '0'})
    items.append({'title': 'Fourth user doc',
                    'link': '',
                    'tags': [],
                    'authors': [],
                    'year': '',
                    'notes': '',
                    'read': '0'})
    return items


@pytest.fixture
def five_items():
    '''Only tag 4 overlaps with four_items.'''
    items = []
    items.append({'title': 'First user doc',
                    'link': 'http://whatyouveread.com/1',
                    'tags': ['tag4', 'tag5'],
                    'authors': [
                                {'last_name': 'Smith', 'first_name': 'Joe'},
                                {'last_name': 'Smith', 'first_name': 'Jane'},
                                {'last_name': 'Connolly', 'first_name': 'Nathan'}
                                ],
                    'year': '2018',
                    'notes': 'This is a note.',
                    'read': '1'})
    items.append({'title': 'Second user doc',
                    'link': 'http://whatyouveread.com/2',
                    'tags': ['tag6', 'tag7', 'tag8'],
                    'authors': [
                                {'last_name': 'Johnson', 'first_name': 'Joe'},
                                {'last_name': 'Johnson', 'first_name': 'Jane'}
                               ],
                    'year': '2017',
                    'notes': 'This is also a note.',
                    'read': '0'})
    items.append({'title': 'Third user doc',
                    'link': 'http://whatyouveread.com/3',
                    'tags': ['tag4', 'tag6'],
                    'authors': [
                                {'last_name': 'Smith', 'first_name': 'Jane'},
                                {'last_name': 'Johnson', 'first_name': 'Jane'}
                               ],
                    'year': '2019',
                    'notes': 'This is also a note.',
                    'read': '0'})
    items.append({'title': 'Fourth user doc',
                    'link': 'http://whatyouveread.com/4',
                    'tags': ['tag4', 'tag6', '7even'],
                    'authors': [
                                {'last_name': 'Smith', 'first_name': 'Jane'},
                                {'last_name': 'Johnson', 'first_name': 'Jane'}
                               ],
                    'year': '2019',
                    'notes': 'This is also a note.',
                    'read': '1'})
    items.append({'title': 'Fifth user doc',
                    'link': '',
                    'tags': [],
                    'authors': [],
                    'year': '',
                    'notes': '',
                    'read': '0'})
    return items


@pytest.fixture
def three_items_tags_only():
    items = []
    items.append({'title': 'Test',
                  'tags': ['tag0', 'tag1']})
    items.append({'title': 'Test',
                  'tags': ['tag2', 'tag3', 'tag4']})
    items.append({'title': 'Test'})
    return items


@pytest.fixture
def three_items_authors_only():
    items = []
    items.append({'title': 'Test',
                  'authors': [
                              {'last_name': 'Smith', 'first_name': 'Joe'},
                              {'last_name': 'Smith', 'first_name': 'Jane'}
                             ]
                 })
    items.append({'title': 'Test',
                  'authors': [
                              {'last_name': 'Johnson', 'first_name': 'Joe'},
                              {'last_name': 'Johnson', 'first_name': 'Jane'}
                             ]
                 })
    items.append({'title': 'Test'})
    return items


