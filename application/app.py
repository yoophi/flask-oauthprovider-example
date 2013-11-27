import logging
from flask import Flask, request, render_template, jsonify, redirect, url_for
from flask.ext.login import current_user, login_required, logout_user, login_user, LoginManager
from flask.ext.sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from sqlalchemy import Column, DateTime, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, synonym
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import Form, TextField, PasswordField
from wtforms.validators import required
from datetime import datetime, timedelta

app = Flask(__name__)
oauth = OAuth2Provider(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sched.db'
app.config['SECRET_KEY'] = 'enydM2ANhdcoKwdVa0jWvEsbPFuQpMjf'

db = SQLAlchemy(app)
db.Model = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)

logger = logging.getLogger('flask_oauthlib')
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler('oauth.log')
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

logger.addHandler(fh)

@login_manager.user_loader
def load_user(user_id):
    app.logger.debug('load_user({user_id})'.format(user_id=user_id))
    app.logger.debug(db.session.query(User).get(user_id))
    return db.session.query(User).get(user_id)


class LoginForm(Form):
    username = TextField('Username', [required()])
    password = PasswordField('Password', [required()])


class Client(db.Model):
    __tablename__ = 'client'
    # human readable name, not required
    name = db.Column(db.Unicode(40))

    # human readable description, not required
    description = db.Column(db.Unicode(400))

    # creator of the client, not required
    user_id = db.Column(db.ForeignKey('user.id'))
    # required if you need to support client credential
    user = relationship('User')

    client_id = db.Column(db.Unicode(40), primary_key=True)
    client_secret = db.Column(db.Unicode(55), unique=True, index=True,
                              nullable=False)

    # public or confidential
    is_confidential = db.Column(db.Boolean)

    _redirect_uris = db.Column(db.UnicodeText)
    _default_scopes = db.Column(db.UnicodeText)

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class User(db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    name = Column('name', String(200))
    email = Column(String(100), unique=True, nullable=False)
    active = Column(Boolean, default=True)
    _password = Column('password', String(100))

    def _get_password(self):
        return self._password

    def _set_password(self, password):
        if password:
            password = password.strip()
        self._password = generate_password_hash(password)

    password_descriptor = property(_get_password, _set_password)
    password = synonym('_password', descriptor=password_descriptor)

    def check_password(self, password):
        if self.password is None:
            return False
        password = password.strip()
        if not password:
            return False
        return check_password_hash(self.password, password)

    @classmethod
    def authenticate(cls, query, email, password):
        email = email.strip().lower()
        user = query(cls).filter(cls.email==email).first()
        if user is None:
            return None, False
        if not user.active:
            return user, False
        return user, user.check_password(password)

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

    def __repr__(self):
        return u'<{self.__class__.__name__}: {self.id}>'.format(self=self)


class Grant(db.Model):
    __tablename__ = 'grant'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    code = db.Column(db.Unicode(255), index=True, nullable=False)

    redirect_uri = db.Column(db.Unicode(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.UnicodeText)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    __tablename__ = 'token'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.Unicode(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.Unicode(40))

    access_token = db.Column(db.Unicode(255), unique=True)
    refresh_token = db.Column(db.Unicode(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.UnicodeText)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _get_scope(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _set_scope(self, scope):
        if scope:
            scope = scope
        self._scopes = scope

    scope_descriptor = property(_get_scope, _set_scope)
    scope = synonym('_scopes', descriptor=scope_descriptor)


@oauth.clientgetter
def load_client(client_id):
    app.logger.debug('load_client({client_id})'.format(client_id=client_id))
    return db.session.query(Client).filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    app.logger.debug('load_grant({client_id}, {code})'.format(
        client_id=client_id, code=code))
    return db.session.query(Grant).filter_by(
        client_id=client_id, code=code).first()


def get_current_user():
    app.logger.debug('get_current_user()')
    return db.session.query(User).get(current_user.id)


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    app.logger.debug(
        'save_grant({client_id}, {code}, {redirect_uri}, ...)'.format(
            client_id=client_id, code=code['code'],
            redirect_uri=request.redirect_uri))
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    app.logger.debug(get_current_user())
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    app.logger.debug('load_token')
    app.logger.debug(
        'access_token={access_token}'.format(access_token=access_token))
    if access_token:
        app.logger.debug(db.session.query(Token).filter_by(
            access_token=access_token).first())
        return db.session.query(Token).filter_by(
            access_token=access_token).first()
    elif refresh_token:
        return db.session.query(Token).filter_by(
            refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    app.logger.debug('save_token')
    #toks = db.session.query(Token).filter_by(client_id=request.client.client_id,
    #                             user_id=request.user.id).all()
    #app.logger.debug('client_id={client_id}, user_id={user_id}'.format(client_id=request.client.client_id, user_id=request.user.id))
    #app.logger.debug(toks)
    ## make sure that every client has only one token connected to a user
    #db.session.delete(toks)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    app.logger.debug(token)
    tok = Token(**token)
    tok.expires = expires
    tok.client_id = request.client.client_id
    tok.user_id = request.user.id
    db.session.add(tok)
    db.session.commit()
    return tok


@oauth.usergetter
def get_user(username, password, *args, **kwargs):
    app.logger.debug('get_user')
    user = User.query.filter_by(username=username).first()
    if user.check_password(password):
        return user
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    app.logger.debug('authorize')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        #client = Client.query.filter_by(client_id=client_id).first()
        client = db.session.query(Client).filter_by(client_id=client_id).first()
        kwargs['client'] = client
        app.logger.debug(kwargs)
        return render_template('oauthorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/oauth/token')
@oauth.token_handler
def access_token():
    app.logger.debug('access_token')
    return None


@app.route('/api/me')
@oauth.require_oauth('email')
def me(request):
    user = request.user
    return jsonify(email=user.email, name=user.name)


@app.route('/api/user/<username>')
@oauth.require_oauth('email')
def user(request, username):
    app.logger.debug('user')
    user = db.session.query(User).filter_by(name=username).first()
    #user = db.session.query(User).get(username)
    #q = db.session.query(User).filter(User.name==username)
    #user = db.session.query(q).first()
    app.logger.debug(user)
    return jsonify(email=user.email, username=user.name)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    app.logger.debug(request.form)
    error = None
    if request.method == 'POST' and form.validate():
        email = form.username.data.lower().strip()
        password = form.password.data.lower().strip()
        user, authenticated = User.authenticate(db.session.query, email, password)
        if authenticated:
            login_user(user)
            return redirect(url_for('authorize'))
        else:
            error = 'Incorrect username or password. Try again.'
    return render_template('user/login.html', form=form, error=error)


@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    from sqlalchemy import create_engine

    engine = create_engine('sqlite:///sched.db', echo=True)
    db.Model.metadata.create_all(engine)

    user = User(name='Pyunghyuk Yoo',
                email='yoophi@gmail.com',
                password='secret')

    db.session.add(user)
    db.session.commit()

    client = Client(name='foo',
                    description='',
                    user=user,
                    client_id='foo',
                    client_secret='secret',
                    _redirect_uris='http://yoophi.com/oauth/redirect')
    db.session.add(client)
    db.session.commit()
