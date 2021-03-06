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
    def __init__(self, doc_id=""):
        self.message = "Title not submitted but is required."
        self.doc_id = doc_id
        self.error = 62
        self.http_status = 400


class DuplicateLinkException(WyrException):
    def __init__(self, doc_id=""):
        self.doc_id = doc_id
        self.message = "That link is already in your collection."
        self.error = 63
        self.http_status = 400


class NotUserDocException(WyrException):
    def __init__(self):
        self.message = "That document was not found in your collection."
        self.error = 3
        self.http_status = 404


class NotEditableDocException(WyrException):
    def __init__(self):
        self.message = "Cannot edit non-WYR document."
        self.error = 64
        self.http_status = 403


class NotDeleteableDocException(WyrException):
    def __init__(self):
        self.message = "Cannot delete non-WYR document."
        self.error = 65
        self.http_status = 403


# Tag- and Bunch-related Exceptions


class NoBunchException(WyrException):
    def __init__(self):
        self.message = "No bunch with that name found."
        self.error = 66
        self.http_status = 404


# Author-related Exceptions
