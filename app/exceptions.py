# Base Exception
class WyrException(Exception):
    pass


# API exceptions?


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

class BadReadValueError(WyrException, ValueError):
    def __init__(self):
        self.message = 'Value of <read> must be 0 (to-read) or 1 (read).'
        self.error = 12
        self.http_status = 400


# Tag- and Bunch-related Exceptions



# Author-related Exceptions

