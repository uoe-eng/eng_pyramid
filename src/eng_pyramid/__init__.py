import traceback
from pyramid.response import Response

def error_response(exc, add_traceback=False):
    res = Response()
    res.content_type = 'application/vnd.api+json'
    res.status_code = exc.code
    errors = {
        'errors': [
            {
                'code': str(exc.code),
                'detail': exc.detail,
                'title': exc.title,
            }
        ]
    }
    if add_traceback:
        errors['traceback'] = traceback.format_exc()
    res.json_body = errors
    return res