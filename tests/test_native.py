import pytest
from flask import url_for

from app import native, models, db, common
from app import exceptions as ex
from sqlalchemy.orm.exc import NoResultFound

# Testing the functions in native.py

#####################################
# FIXTURES FOR THE HELPER FUNCTIONS #
#####################################


one_tag = ['test0',
           'test0,',
           'test0 ',
           ' test0 ',
           ' test0 , ',
           ' test0 , ,',
           ', test0, , ',
           ', test0 , ,']

# should evaluate to count of 3 and values test1, test2, test3
three_tags = ['test0, test1, test2',
              'test0, test1, test2 ',
              ' test0, test1, test2',
              'test0, test1, test2, ,',
              ', test0, test1, test2',
              ' , test0, test1, test2',
              ' , , test0, test1, test2',
              ' , , test0, , test1,  , test2, , , ',
              ' , , test0, ,, test1,  , , test2, , , ',
              'test0,test1,test2']


@pytest.fixture(params=one_tag)
def str_1_tag(request):
    return request.param


@pytest.fixture(params=three_tags)
def str_3_tags(request):
    return request.param


empty_author = ['',
                ',',
                ';',
                ',;',
                ' ,;',
                ' , ;',
                ' , ; ',
                ',;,;',
                ', ; , ;',
                ' , ; , ; ',
                '`~!@#$%^&*()-_=+[{]}"<>?/']

one_author = ['Smith, Jane;',
              'Smith, Jane',
              'Smith, Jane ;',
              'Smith, Jane ; ;',
              'Smith, Jane ; , ;',
              'Smith,  Jane',
              'Smith, Jane ',
              ' Smith, Jane',
              ' Smith,  Jane ',
              'Smith , Jane']

one_author_last_name = ['Smith',
                        'Smith;',
                        'Smith, ',
                        '; Smith , ; ']

one_author_first_name = [', Jane;',
                         ', Jane ',
                         '; , Jane ; ']

three_authors = ['Smith, Jane; Rodriguez, Jose; Johnson, Bill;',
                 '; Smith , Jane ;  , ; ;Rodriguez , Jose;Johnson , Bill ; ,']


@pytest.fixture(params=empty_author)
def empty_author(request):
    return request.param


@pytest.fixture(params=one_author)
def one_author(request):
    return request.param


@pytest.fixture(params=one_author_last_name)
def one_author_last_name(request):
    return request.param


@pytest.fixture(params=one_author_first_name)
def one_author_first_name(request):
    return request.param


@pytest.fixture(params=three_authors)
def three_authors(request):
    return request.param

####################
# HELPER FUNCTIONS #
####################

# str_tags_to_list()

def test_str_to_list_empty():
    empty_tags = ''
    tags = native.str_tags_to_list(empty_tags)
    assert not tags


def test_str_to_list_1_count(str_1_tag):
    tags = native.str_tags_to_list(str_1_tag)
    assert len(tags) == 1


def test_str_to_list_1_value(str_1_tag):
    tags = native.str_tags_to_list(str_1_tag)
    assert tags[0] == 'test0'


def test_str_to_list_3_count(str_3_tags):
    tags = native.str_tags_to_list(str_3_tags)
    assert len(tags) == 3


def test_str_to_list_3_values(str_3_tags):
    tags = native.str_tags_to_list(str_3_tags)
    assert (tags[0] == 'test0' and tags[1] == 'test1' and tags[2] == 'test2')


# format_authors()

def test_authors_empty(empty_author):
    '''Author string with no alphanumeric chars returns no authors.'''
    authors = native.format_authors(empty_author)
    assert not authors


def test_one_author(one_author):
    '''White space and empty authors stripped.'''
    authors = native.format_authors(one_author)

    assert (len(authors) == 1 and
            authors[0]['first_name'] == 'Jane' and
            authors[0]['last_name'] == 'Smith')


def test_one_author_last_name_only(one_author_last_name):
    '''Last name only.'''
    authors = native.format_authors(one_author_last_name)

    assert (len(authors) == 1 and
            authors[0]['last_name'] == 'Smith' and
            authors[0]['first_name'] == '')


def test_one_author_first_name_only(one_author_first_name):
    '''First name only.'''
    authors = native.format_authors(one_author_first_name)

    assert (len(authors) == 1 and
            authors[0]['last_name'] == '' and
            authors[0]['first_name'] == 'Jane')


def test_three_authors(three_authors):
    '''Three authors formatted correctly.'''
    authors = native.format_authors(three_authors)

    assert (len(authors) == 3 and
            authors[0]['last_name'] == 'Smith' and
            authors[0]['first_name'] == 'Jane' and
            authors[1]['last_name'] == 'Rodriguez' and
            authors[1]['first_name'] == 'Jose' and
            authors[2]['last_name'] == 'Johnson' and
            authors[2]['first_name'] == 'Bill')

##########
# ROUTES #
##########

# adding docs

def test_add1(flask_client, user4):
    '''Adding item with only a title works.'''

    content = {'title': 'Test'}

    response = flask_client.post('/add', data=content, follow_redirects=True)

    docs = common.get_docs(user4)

    assert (b'Item added.' in response.data and len(docs) == 5)

def test_add2(flask_client, user4):
    '''Adding item with all form variables works.'''

    content = {'title': 'Test',
               'link': 'https://example.com',
               'tags': 'tag1, tag2',
               'authors': 'Doe, Jane; Doe, John',
               'year': '2018',
               'notes': 'This is a note',
               'read': '1'}

    response = flask_client.post('/add', data=content, follow_redirects=True)

    docs = common.get_docs(user4)

    assert (b'Item added.' in response.data and len(docs) == 5)


def test_add3(flask_client, user4):
    '''Attempting to add item without title gives user error message.'''

    content = {'title': ''}

    response = flask_client.post('/add', data=content, follow_redirects=True)

    assert b'Title not submitted but is required.' in response.data


def test_add4(flask_client, user4):
    '''Attempting to add item with duplicate link gives user error message.'''

    content = {'title': 'Test',
               'link': 'http://whatyouveread.com/1'}

    response = flask_client.post('/add', data=content, follow_redirects=True)

    assert b'That link is already in your collection.' in response.data


# editing docs

def test_edit1(flask_client, user4):
    '''Editing every part of item works.'''

    content = {'id': 1,
               'title': 'Test',
               'link': 'http://whatyouveread.com/5',
               'tags': 'tag2, tag3',
               'authors': 'Rodriquez, Jose; Garcia, Juana',
               'year': '2019',
               'notes': 'This is an edited note.',
               'read': '0'}

    response = flask_client.post('/edit', data=content, follow_redirects=True)

    assert (b'Item edited.' in response.data)


def test_edit2(flask_client, user4):
    '''Not including title in edit gives user erorr message.'''

    content = {'id': '1',
               'title': ''}

    response = flask_client.post('/edit', data=content, follow_redirects=True)

    assert b'Title not submitted but is required.' in response.data


def test_edit3(flask_client, user4):
    '''Duplicate link in edit gives user erorr message.'''

    content = {'id': '1',
               'title': 'Test',
               'link': 'http://whatyouveread.com/2',
               }

    response = flask_client.post('/edit', data=content, follow_redirects=True)

    assert b'That link is already in your collection.' in response.data


def test_edit4(flask_client, user5, user4):
    '''Can't edit another user's doc.'''

    content = {'id': '3',
               'title': 'Test'}

    response = flask_client.post('/edit', data=content, follow_redirects=True)

    assert b'That document was not found in your collection.' in response.data





