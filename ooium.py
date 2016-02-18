from flask import Flask, render_template, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import current_user, login_required, RoleMixin, Security, \
    SQLAlchemyUserDatastore, UserMixin, utils
from flask_security.utils import encrypt_password
from flask_environments import Environments
from flask_mail import Mail
from flask.ext import login
from flask.ext.admin.base import MenuLink, Admin, BaseView, expose, AdminIndexView
from flask.ext.admin.contrib import sqla
from wtforms import PasswordField
import os
from collections import OrderedDict
from datetime import datetime
from redis import Redis
from flask.ext.admin.contrib import rediscli

# Create app
app = Flask(__name__)

# Import the config.yml or config_local.yml file and load it into the app environment
basedir = os.path.abspath(os.path.dirname(__file__))
env = Environments(app, default_env='PRODUCTION')

if os.path.exists(os.path.join(basedir, 'config_local.yml')):
    env.from_yaml(os.path.join(basedir, 'config_local.yml'))
else:
    env.from_yaml(os.path.join(basedir, 'config.yml'))

# Setup mail functionality
mail = Mail(app)

# Create database connection object
db = SQLAlchemy(app)


# These classes are from ooi-ui-services, slightly modified
# TODO: Figure out a way to keep these classes maintained with ooi-ui-services
class DictSerializableMixin(object):
    def serialize(self):
        return self._asdict()

    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = self._pytype(getattr(self, key))
        return result

    def _pytype(self, v):
        if isinstance(v, datetime):
            return v.isoformat()
        return v

# Define models
__schema__ = app.config['DB_SCHEMA']


class Organization(db.Model, DictSerializableMixin):
    __tablename__ = 'organizations'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.Text, nullable=False)
    organization_long_name = db.Column(db.Text)
    image_url = db.Column(db.Text)

    users = db.relationship(u'User')

    def __unicode__(self):
        return self.organization_name

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.organization_name)

    @staticmethod
    def insert_org():
        org = Organization.query.filter(Organization.organization_name == 'RPS ASA').first()
        if org is None:
            org = Organization(organization_name = 'RPS ASA')
            db.session.add(org)
            db.session.commit()


class RolesUsers(db.Model, RoleMixin):
    __tablename__ = 'roles_users'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey(u''+__schema__+'.users.id'))
    role_id = db.Column(db.Integer(), db.ForeignKey(u''+__schema__+'.roles.id'))

    roles = db.relationship(u'Role')
    users = db.relationship(u'User')


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    # __unicode__ is required by Flask-Admin, so we can have human-readable values for the Role when editing a User.
    def __unicode__(self):
        return self.name

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.name)


class UserScopeLink(db.Model):
    __tablename__ = 'user_scope_link'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey(u'' + __schema__ + '.users.id'), nullable=False)
    scope_id = db.Column(db.ForeignKey(u'' + __schema__ + '.user_scopes.id'), nullable=False)

    scope = db.relationship(u'UserScope')
    user = db.relationship(u'User')

    @staticmethod
    def insert_scope_link():
        usl = UserScopeLink(user_id='1')
        usl.scope_id='1'
        db.session.add(usl)
        db.session.commit()

    def to_json(self):
        json_scope_link = {
            'id' : self.id,
            'user_id' : self.user_id,
            'scope_id' : self.scope_id,
        }
        return json_scope_link

    def __repr__(self):
        return '<User %r, Scope %r>' % (self.user_id, self.scope_id)


class UserScope(db.Model, DictSerializableMixin):
    __tablename__ = 'user_scopes'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    scope_name = db.Column(db.Text, nullable=False, unique=True)
    scope_description = db.Column(db.Text)

    @staticmethod
    def insert_scopes():
        scopes = {
            'redmine',
            'asset_manager',
            'user_admin',
            'annotate',
            'command_control',
            'organization',
            'sys_admin',
            'data_manager'
            }
        for s in scopes:
            scope = UserScope.query.filter_by(scope_name=s).first()
            if scope is None:
                scope = UserScope(scope_name=s)
            db.session.add(scope)
        db.session.commit()

    def to_json(self):
        json_scope = {
            'id' : self.id,
            'scope_name' : self.scope_name,
            'scope_description' : self.scope_description,
        }
        return json_scope

    def __unicode__(self):
        return self.scope_name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Text, unique=True, nullable=False)

    email = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column(db.String(255), nullable=False)
    user_name = db.Column(db.Text, unique=True, nullable=False)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    first_name = db.Column(db.Text)
    last_name = db.Column(db.Text)
    phone_primary = db.Column(db.Text)
    phone_alternate = db.Column(db.Text)
    role = db.Column(db.Text)
    email_opt_in = db.Column(db.Boolean, nullable=False, server_default=db.text("true"))
    organization_id = db.Column(db.ForeignKey(u'' + __schema__ + '.organizations.id'), nullable=False)
    scopes = db.relationship(u'UserScope', secondary=UserScopeLink.__table__)
    organization = db.relationship(u'Organization')
    # watches = db.relationship(u'Watch')
    other_organization = db.Column(db.Text)
    vocation = db.Column(db.Text)
    country = db.Column(db.Text)
    state = db.Column(db.Text)
    roles = db.relationship(u'Role', secondary=RolesUsers.__table__, backref=db.backref('users', lazy='dynamic'))

    def __unicode__(self):
        return self.email

    from sqlalchemy.ext.hybrid import hybrid_property
    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext):
        self._password = encrypt_password(plaintext)


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

login_manager = login.LoginManager()
login_manager.init_app(app)


# Create user loader function
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


# Executes before the first request is processed.
@app.before_first_request
def before_first_request():

    # Create the Roles
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='marine-operator', description='Marine Operator')
    user_datastore.find_or_create_role(name='science-user', description='Science User')
    user_datastore.find_or_create_role(name='redis', description='Redis User')

    encrypted_password = utils.encrypt_password('password')
    toemail = app.config['TOEMAIL']

    if not user_datastore.get_user(toemail):
        user_datastore.create_user(email=toemail,
                                   _password='password',
                                   user_name=toemail,
                                   user_id=toemail,
                                   email_opt_in=True,
                                   organization_id=1,
                                   first_name='The',
                                   last_name='Admin')

    # Commit
    db.session.commit()

    # Add the default Roles
    user_datastore.add_role_to_user('admin@ooi.rutgers.edu', 'admin')
    user_datastore.add_role_to_user('admin@ooi.rutgers.edu', 'redis')

    # Commit
    db.session.commit()


# Displays the home page.
@app.route('/')
# @login_required
def index():
    #return redirect('admin')
    # return render_template('index.html')
    if not login.current_user.is_authenticated:
        return redirect(url_for('.login_view'))
    return redirect('admin/users')


@app.route('/admin/login')
def login_view():
    login.login_user(User())
    # return render_template('index.html')
    return redirect(url_for('.index'))


@app.route('/admin/logout/')
def logout_view():
    login.logout_user()
    if not login.current_user.is_authenticated:
        return redirect(url_for('.login_view'))
    return redirect(url_for('.index'))


@app.route('/admin/reset')
def reset_password():
    login.logout_user()
    if not login.current_user.is_authenticated:
        return redirect(url_for('.login_view'))
    return redirect(url_for('.index'))


# Customized User model for SQL-Admin
class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('_password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('_password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):

        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.
        form_class = super(UserAdmin, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')
        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):

        # If the password field isn't blank...
        if len(model.password2):

            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
            model._password = utils.encrypt_password(model.password2)


# Customized Role model for SQL-Admin
class RoleAdmin(sqla.ModelView):

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

# Initialize Flask-Admin
admin = Admin(app, name='OOI User Admin', url='/admin/users')

# Add Flask-Admin views for Users and Roles
admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))



# Create menu links classes with reloaded accessible
class AuthenticatedMenuLink(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated


class NotAuthenticatedMenuLink(MenuLink):
    def is_accessible(self):
        return not current_user.is_authenticated


class ResetMenuLink(MenuLink):
    def is_accessible(self):
        return not current_user.is_authenticated


class RedisView(rediscli.RedisCli):

    def is_accessible(self):
        return current_user.has_role('redis')


# Adds redis-cli view
redis_host = app.config['REDIS_URL'].split('://')[1].split(':')[0]
redis_port = app.config['REDIS_URL'].rsplit(':', 1)[1]
r = Redis(host=redis_host, port=redis_port)
admin.add_view(RedisView(r, name='Redis CLI'))

# Add login link
admin.add_link(NotAuthenticatedMenuLink(name='Login',
                                        endpoint='login_view'))

# Add logout link
admin.add_link(AuthenticatedMenuLink(name='Logout',
                                         endpoint='logout_view'))

# Add reset password
admin.add_link(ResetMenuLink(name='Reset Password',
                                         endpoint='reset_password'))

# Add OOI link
admin.add_link(MenuLink(name='OOI Home Page', category='Links', url='http://ooinet.oceanobservatories.org/'))

# Run the App
if __name__ == '__main__':
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )
