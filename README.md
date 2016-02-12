Ocean Observatories Initiative - User Management
===============

A stand-alone application that enables the management of users, groups, roles, Redis and password recovery.

### Setup

    pip install -r requirements.txt
### Configuration
    Copy config.yml to config_local.yml and edit as necessary to match ooi-ui-services
    
    SECRET_KEY: <Must match>
    DB_SCHEMA: <Must match, 'ooiui' by default>
    # flask security - email parameters
    SECURITY_EMAIL_SENDER : 'no-reply@ooi.rutgers.edu'
    MAIL_SERVER : 'localhost'
    MAIL_PORT : 465
    MAIL_USE_SSL : True
    MAIL_USERNAME : 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    MAIL_PASSWORD : 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    # flask security - main parameters
    SECURITY_CONFIRMABLE : False
    SECURITY_REGISTERABLE : False
    SECURITY_RECOVERABLE : True
    SECURITY_TRACKABLE : False
    SECURITY_PASSWORD_HASH : 'pbkdf2_sha512'
    SECURITY_PASSWORD_SALT : 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

### Launch

    python ooi-user-mgmt.py


