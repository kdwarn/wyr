# Base Exception
class WyrException(Exception):
    pass


# API exceptions

class NoTokenException(WyrException):
    pass
    # TODO


# Doc-related exceptions

class NoDocsException(WyrException):
    pass


class NoTitleException(WyrException):
    def __init__(self):
        self.message = 'Title not submitted but is required.'
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

class NoTagsException(WyrException):
    pass


# Author-related Exceptions

class NoAuthorsException(WyrException):
    pass