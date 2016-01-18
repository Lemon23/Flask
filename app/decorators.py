# The custom decorator checks the user permissions

from functools import wraps
from flask import abort
from flask.ext.login import current_user
from .models import Permission


# Check general permissions
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Check administrator permissions
def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)

