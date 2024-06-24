def options_view(self):  # pylint:disable=unused-argument
    return ''


def add_cors_headers_response_callback(event):
    def cors_headers(request, response):
        allow_url = request.registry.settings.get("cors_url")
        response.headers.update({
            'Access-Control-Allow-Origin': allow_url,
            'Access-Control-Allow-Methods': 'POST,GET,DELETE,PATCH,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Max-Age': '1728000',
        })
    event.request.add_response_callback(cors_headers)


class ProxyHeaders():
    """Update environ based on request headers."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        if (script_name := environ.get('HTTP_SCRIPTNAME', '')):
            environ["SCRIPT_NAME"] = script_name
        path_info = environ.get('PATH_INFO', '')
        if path_info.startswith(script_name):
            environ['PATH_INFO'] = path_info[len(script_name):]

        if (scheme := environ.get('HTTP_X_FORWARDED_PROTO', '')):
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)