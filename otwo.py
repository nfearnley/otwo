import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from oauth2client.client import OAuth2Credentials, Flow, flow_from_clientsecrets

class Login(object):
    def __init__(self, scopes,
            client_secret_path = "client_secret.json",
            credentials_path = "credentials.json"):
        self._cred = None
        self._scopes = scopes
        self._client_secret_path = client_secret_path
        self._credentials_path = credentials_path

    def get_token(self):
        if not self._cred:
            self._load()
        
        if self._cred:
            if self._cred.access_token_expired:
                self._cred.refresh()
                self._save()
        else:
            flow = flow_from_clientsecrets(
                self._client_secret_path,
                scope=" ".join(self._scopes),
                redirect_uri="http://127.0.0.1"
            )
            auth_uri = flow.step1_get_authorize_url()
            webbrowser.open(auth_uri)
            code = self._wait_for_code()
            print(code)
            self._cred = flow.step2_exchange(code)
            self._save()
         
        return self._cred.get_access_token().access_token

    def _load(self):
        try:
            with open(self._credentials_path, "r") as f:
                self._cred = OAuth2Credentials.from_json(f.read())
        except:
            pass

    def _save(self):
        with open(self._credentials_path, "w") as f:
            f.write(self._cred.to_json())

    def _wait_for_code(self):
        s = HTTPServer(('127.0.0.1', 80), _TokenHandler)
        s.timeout = 30
        s.error = None
        s.code = None
        s.handle_request()
        if s.error:
            raise RuntimeError("Code lookup failed: {}".format(s.error))
        return s.code
        
class _TokenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if "error" in query:
            self.server.error = query["error"][0]
        else:
            self.server.code = query["code"][0]
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'html')
        self.end_headers()
        self.wfile.write((
            "<html> <head><title> Authorization Complete </title> </head>"
            "<body> Thank you for authorizing this app with OAuth 2 </body> </html>"
            ).encode("utf-8"))
        self.wfile.close()
        
    def handle_timeout(self):
        query = parse_qs(urlparse(self.path).query)
        self.error = "Timeout"
            