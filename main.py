import os
import webapp2
import jinja2
import logging
import random
import string
import re
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=%s; Path=/' % (cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie(str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    #Check the login Status
    def check_login(self):
        cookie_val = self.request.cookies.get('user_id')
        if cookie_val== '' or cookie_val == None:
             return None
        else:
            key_cookie = cookie_val.split('|')[0]
            key = db.Key.from_path('User', int(key_cookie), parent=users_key())
            user = db.get(key)
            return user

#making of user password hash

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw , salt= None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    s = h.split(',')
    return h==make_pw_hash(name,pw,s[1])


def render_str(s):
    if s:
        return s.replace('\n', '<br>')




#User database

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


secret = 'WiKi'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, str(val)).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#MainHandler
class MainHandler(Handler):

    def get(self):

        c = self.check_login()
        self.render("main.html" ,  user = c)







#Signup page


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            if  not User.by_name(username):
                u = User.register(username, password ,email)
                u.put()
                self.redirect('/')
                self.set_secure_cookie(u.key().id())
            else :
                error_signup =  "This is user already present"
                self.render('signup.html', error_signup=error_signup)



#Login Page

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class EditPage(Handler):
    def get(self):
        self.write("This is EditPage")




PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/' ,  MainHandler)
                               ('/_edit' + PAGE_RE, EditPage),
                               #(PAGE_RE, WikiPage),
                               ],
                              debug=True)
