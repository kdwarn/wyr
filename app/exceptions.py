# Base Exception
class WyrException(Exception):
    pass


# API exceptions?

# Login and authorization exceptions

class IncorrectPasswordException(WyrException):
    pass


# Doc-related exceptions

class NoDocsException(WyrException):
    pass


class NoTitleException(WyrException):
    def __init__(self, doc_id=''):
        self.message = 'Title not submitted but is required.'
        self.doc_id = doc_id
        self.error = 10
        self.http_status = 400


class DuplicateLinkException(WyrException):
    def __init__(self, doc_id=''):
        self.doc_id = doc_id
        self.message = "That link is already in your collection."
        self.error = 11
        self.http_status = 400


class NotUserDocException(WyrException):
    def __init__(self):
        self.message = 'That document was not found in your collection.'
        self.error = 13
        self.http_status = 400


# Tag- and Bunch-related Exceptions

class NoBunchException(WyrException):
    def __init__(self):
        self.message = 'No bunch with that name found.'
        self.error = 12
        self.http_status = 400


# Author-related Exceptions

