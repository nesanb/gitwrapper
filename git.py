import sys
from urllib.request import build_opener, HTTPSHandler, HTTPError, Request
from urllib.parse import quote as urlquote
#from io import StringIO
#from shutil import copyfileobj
import logging
import re, os, time, hmac, base64, hashlib, urllib, mimetypes, json
from util import get_config
import datetime
import ssl


TIMEOUT = 60


ssl._create_default_https_context = ssl._create_unverified_context

ORG_NAME = 'nesanb'

str_tm = datetime.datetime.now().strftime("%Y%m%d")


_URL = 'https://api.github.com'
_METHOD_MAP = dict(
    GET=lambda: 'GET',
    PUT=lambda: 'PUT',
    POST=lambda: 'POST',
    PATCH=lambda: 'PATCH',
    DELETE=lambda: 'DELETE')

DEFAULT_SCOPE = None
RW_SCOPE = 'user,public_repo,repo,repo:status,gist'


def _encode_params(kw):

    args = []
    for k, v in kw.items():
        qv = v
        args.append('%s=%s' % (k, urlquote(qv)))
    return '&'.join(args)


def _encode_json(obj):

    def _dump_obj(obj):
        if isinstance(obj, dict):
            return obj
        d = dict()
        for k in dir(obj):
            if not k.startswith('_'):
                d[k] = getattr(obj, k)
        return d

    return json.dumps(obj, default=_dump_obj)


def _parse_json(jsonstr):
    def _obj_hook(pairs):
        o = JsonObject()
        for k, v in pairs.items():
            o[str(k)] = v
        return o

    return json.loads(jsonstr, object_hook=_obj_hook)


class _Executable(object):
    def __init__(self, _gh, _method, _path):
        self._gh = _gh
        self._method = _method
        self._path = _path

    def __call__(self, **kw):
        return self._gh._http(self._method, self._path, **kw)

    def __str__(self):
        return '_Executable (%s %s)' % (self._method, self._path)

    __repr__ = __str__


class _Callable(object):
    def __init__(self, _gh, _name):
        self._gh = _gh
        self._name = _name

    def __call__(self, *args):

        if len(args) == 0:
            return self
        name = '%s/%s' % (self._name, '/'.join([str(arg) for arg in args]))
        return _Callable(self._gh, name)

    def __getattr__(self, attr):
        if attr == 'get':
            return _Executable(self._gh, 'GET', self._name)
        if attr == 'put':
            return _Executable(self._gh, 'PUT', self._name)
        if attr == 'post':
            return _Executable(self._gh, 'POST', self._name)
        if attr == 'patch':
            return _Executable(self._gh, 'PATCH', self._name)
        if attr == 'delete':
            return _Executable(self._gh, 'DELETE', self._name)
        name = '%s/%s' % (self._name, attr)
        return _Callable(self._gh, name)

    def __str__(self):
        return '_Callable (%s)' % self._name

    __repr__ = __str__


class GitHub(object):

    if (get_config('GITHUB','PROXY_NEEDED')=='Y'):
        os.environ['http_proxy'] = get_config('GITHUB','PROXY')
        os.environ['https_proxy'] = get_config('GITHUB','PROXY')

    def __init__(self, username=None, password=None, access_token=None, client_id=None, client_secret=None,
                 redirect_uri=None, scope=None):
        self.x_ratelimit_remaining = (-1)
        self.x_ratelimit_limit = (-1)
        self.x_ratelimit_reset = (-1)
        self._authorization = None
        self._next_url= ''

        if username and password:
            # roundabout hack for Python 3
            userandpass = base64.b64encode(bytes('%s:%s' % (username, password), 'utf-8'))
            userandpass = userandpass.decode('ascii')
            self._authorization = 'Basic %s' % userandpass
        elif access_token:
            self._authorization = 'token %s' % access_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scope = scope

    def authorize_url(self, state=None):
        if not self._client_id:
            raise ApiAuthError('No client id.')
        kw = dict(client_id=self._client_id)
        if self._redirect_uri:
            kw['redirect_uri'] = self._redirect_uri
        if self._scope:
            kw['scope'] = self._scope
        if state:
            kw['state'] = state
 
        return 'https://github.com/login/oauth/authorize?%s' % _encode_params(kw)
    def get_access_token(self, code, state=None):
        '''
        In callback url: http://host/callback?code=123&state=xyz
        use code and state to get an access token.
        '''
        kw = dict(client_id=self._client_id, client_secret=self._client_secret, code=code)
        if self._redirect_uri:
            kw['redirect_uri'] = self._redirect_uri
        if state:
            kw['state'] = state
        opener = build_opener(HTTPSHandler)
        request = Request('https://github.com/login/oauth/access_token', data=_encode_params(kw))
        request.get_method = _METHOD_MAP['POST']
        request.add_header('Accept', 'application/json')
        try:
            # proxi = {'http': 'http://proxy.xx.corp:8080'}

            response = opener.open(request, timeout=TIMEOUT)
            r = _parse_json(response.read())
            if 'error' in r:
                raise ApiAuthError(str(r.error))
            return str(r.access_token)
        except HTTPError as e:
            raise ApiAuthError('HTTPError when get access token')

    def __getattr__(self, attr):
        return _Callable(self, '/%s' % attr)

    def _http(self, _method, _path, **kw):
        data = None
        params = None
        if _method == 'GET' and kw:
            _path = '%s?%s' % (_path, _encode_params(kw))
        if _method in ['POST', 'PATCH', 'PUT']:
            data = bytes(_encode_json(kw), 'utf-8')
        url = '%s%s' % (_URL, _path)
        opener = build_opener(HTTPSHandler)
        request = Request(url, data=data)
        request.get_method = _METHOD_MAP[_method]
        if self._authorization:
            request.add_header('Authorization', self._authorization)
        if _method in ['POST', 'PATCH', 'PUT']:
            if '/reviews' in url:
                request.add_header('Accept', 'application/vnd.github.black-cat-preview+json')

            request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            #print(url)
            # proxi = {'http': 'http://proxy.xxx.corp:8080'}
            response = opener.open(request, timeout=TIMEOUT)
            is_json = self._process_resp(response.headers)
            if is_json and not '/files' in url and   '/contents/' in url:
                #print(response.read().decode('utf-8'))
                return response.read().decode('utf-8')
            elif is_json and not '/files' in url:
                return _parse_json(response.read().decode('utf-8'))
            elif is_json and '/files' in url:
                obj=_parse_json(response.read().decode('utf-8'))
                page=self._next_url
                return page, obj
        except HTTPError as e:
            is_json = self._process_resp(e.headers)
            if is_json:
                json = _parse_json(e.read().decode('utf-8'))
            else:
                json = e.read().decode('utf-8')
            req = JsonObject(method=_method, url=url)
            resp = JsonObject(code=e.code, json=json)
            print(json['message'])
            if resp.code == 404:
                raise ApiNotFoundError(url, req, resp)
            if resp.code == 405:
                raise ApiNotFoundError(url, req, resp)
            raise ApiError(url, req, resp)

    def _process_resp(self, headers):
        is_json = False
        self._next_url=''
        if headers:
            for k in headers:
                h = k.lower()
                if h == 'x-ratelimit-remaining':
                    self.x_ratelimit_remaining = int(headers[k])
                elif h == 'x-ratelimit-limit':
                    self.x_ratelimit_limit = int(headers[k])
                elif h == 'x-ratelimit-reset':
                    self.x_ratelimit_reset = int(headers[k])
                elif h == 'link':
                    try:
                        st = headers[k].split(',')[0].split(';')[0]
                        reg=re.compile(r"page=\d+")
                        r=reg.search(st)
                        self._next_url=r.group(0)
                    except Exception as e:
                        print(str(e))

                elif h == 'content-type':
                    is_json = headers[k].startswith('application/json')
        return is_json




class JsonObject(dict):

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(r"'Dict' object has no attribute '%s'" % key)

    def __setattr__(self, attr, value):
        self[attr] = value


class ApiError(Exception):
    def __init__(self, url, request, response):
        super(ApiError, self).__init__(url)
        self.request = request
        self.response = response


class ApiAuthError(ApiError):
    def __init__(self, msg):
        super(ApiAuthError, self).__init__(msg, None, None)


class ApiNotFoundError(ApiError):
    pass


def get_pr_owner(repo, gh, pr):
    ls = gh.repos(ORG_NAME)(repo)('pulls')(pr).get()
    owner = ls['user']['login']
    return owner

    # val = ls['html_url'].replace('https://github.com/','').split('/')
    # print(ls.base['repo']['owner']['login'])
    # owner=str(ls.base['repo']['owner']['login'])
    # return val[0]


def get_prs(repo, gh, preq, loc,wlst):
    ls = gh.repos(ORG_NAME)(repo).pulls.get()
    logging.info('Downloading_PR ')
    for p in ls:
        val = p.url.split('/')
        pr = val[len(val) - 1]
        logging.info('Downloading started for ' + pr)
        # assignees=str(p.assignees)
        assignee = str(p.assignee)
        user=get_pr_owner(repo, gh, pr)

        if ((preq == pr) or (preq == '' and (assignee == 'None' or len(p.assignees)==0))):
            page, files = gh.repos(ORG_NAME)(repo)('pulls')(pr).files.get()
            for f in files:
                download_file(f.filename, f.raw_url, repo, pr, loc,user,wlst)
            while (not page == '' ):
                id=page.replace('page=','')
                if (id=='1'):
                    break
                page, files = gh.repos(ORG_NAME)(repo)('pulls')(pr).files.get(page=id)
                for f in files:
                    download_file(f.filename, f.raw_url, repo, pr,loc,user,wlst)
    logging.info('Downloaded PR')

def merge_pr(pr, repo, commit_msg, gh):
    logging.info('Merging Started PR')
    gh.repos(ORG_NAME)(repo)('pulls')(pr)('merge').put(commit_title=commit_msg)
    logging.info('Merged PR')


def review_pr(pr, repo, review_msg, gh):
    owner = get_pr_owner(repo, gh, pr)
    assign_pr(repo, gh, pr, owner)
    gh.repos(ORG_NAME)(repo)('pulls')(pr)('reviews').post(body=review_msg, event='REQUEST_CHANGES')


def assign_pr(repo, gh, pr, owner):
    data = [owner]
    gh.repos(ORG_NAME)(repo)('issues')(pr).patch(assignees=data)


def comment_pr(pr, repo, commit_msg, gh):
    gh.repos(ORG_NAME)(repo)('issues')(pr)('comments').post(body=commit_msg)


def download_file(filename, url, rep, pr, loc,user,wlst):
    file_name = loc + rep + '/' + pr + '/' + filename
    #print(url)
    url = url.replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/raw/', '/')
    opener = build_opener(HTTPSHandler)
    request = Request(url)
    request.get_method = _METHOD_MAP['GET']
    request.add_header('Authorization', 'token '+get_config('GITHUB','TOKEN'))
    request.add_header('Accept', 'application/vnd.github.v3.raw')

    response = opener.open(request, timeout=TIMEOUT)

    if not os.path.exists(os.path.dirname(file_name)):
        #print(os.path.dirname(file_name))
        os.makedirs(os.path.dirname(file_name))
    with  open(file_name, "wb") as f:
        f.write(response.read())



def delete_file(file_path,repo,gh,shav):
    try:
                x= gh.repos(ORG_NAME)(repo)('contents')(file_path).delete(sha=shav,message="deleted")
    except Exception as e:
        logging.error('Merged PR')(str(e))

def put_file(file_path,repo,gh,content):
    try:
        encodedm=base64.b64encode(bytes(content, "utf-8"))
        x= gh.repos(ORG_NAME)(repo)('contents')(file_path).put(content=encodedm.decode("utf-8"),message="test")
    except Exception as e:
        logging.error('Merged PR')(str(e))



        

def get_file(file_path,repo,gh):
    try:
        x= gh.repos(ORG_NAME)(repo)('contents')(file_path).get()
        pattern = r'"content"\:"[^"]*'
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)

        content = regex.findall(x)

        encodex = content[0].replace('"content":', "").replace('"', "")

        p = ''
        flag = True
        i = 0;
        j = 60
        while flag:
            p = p + encodex[i:i + j]

            if j<60:
                flag = False
            elif i + j > len(encodex):
                j = len(encodex) - i

            i = i + 62

        return base64.standard_b64decode(p).decode("utf-8")
    except Exception as e:
        logging.error('Merged PR')(str(e))
        return ''


def rename_file(old_file_path,new_file_path,repo,gh,content):
    try:
        x = gh.repos(ORG_NAME)(repo)('contents')(old_file_path).get()
        pattern = r'"sha"\:"[^"]*'
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    
        resp = regex.findall(x)
    
        shaval = resp[0].replace('"sha":', "").replace('"', "")
        if len(shaval)>0:
        
            if len(content)==0:
              fcontent=get_file(old_file_path,repo,gh)
            else:
              fcontent =content

            delete_file(old_file_path,repo,gh,shaval)

            put_file(new_file_path,repo,gh,fcontent)
    except Exception as e:
        logging.error('Merged PR')(str(e))
        

if __name__ == '__main__':
    gh = GitHub(username=get_config('GITHUB','USER'), access_token=get_config('GITHUB','TOKEN'))
    try:

        repo = ''
        method = ''
        pr = ''
        mesg = ''

        for arg in sys.argv:
            argin = arg.lower()
            if 'repo' in arg:
                pos = arg.find('=') + 1
                repo = arg[pos:]
            if 'method' in arg:
                pos = arg.find('=') + 1
                method = arg[pos:]
            if 'pr' in arg:
                pos = arg.find('=') + 1
                pr = arg[pos:]
            if 'message' in arg:
                pos = arg.find('=') + 1
                mesg = arg[pos:]

        if (method.lower() == 'download'):
            get_prs(repo, gh, str(pr))

        elif (method.lower() == 'comment'):
            comment_pr(pr, repo, mesg, gh)

        elif (method.lower() == 'review'):
            review_pr(pr, repo, mesg, gh)

        elif (method.lower() == 'merge'):
            merge_pr(pr, repo, mesg, gh)

        get_prs('pub', gh, '','D:/temp/')
        x=put_file('python/test1.py','vm',gh,"testing")
        # review_pr(5,'test_b','testyy',gh)
        # comment_pr(3, 'test', 'b test',gh)
        # merge_pr(3, 'test_b', 'b test',gh)
        # print('Success')
        # exit(0)
    except Exception as e:
        # print('Failed')
        # print(sys.exc_info()[0])
        exit(1)
