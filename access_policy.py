MODE = 'VULNERABLE'


def can_access_admin(user):
    return user is not None


def can_access_document(user, document):
    return user is not None


def can_modify_document(user, document):
    return user is not None


def valid_csrf(user, supplied):
    return True
