Ocean Observatories Initiative - User Management
===============

A stand-alone application that enables the management of users, groups, roles, Redis and password recovery.  

It is recommended to host this app on a separate ip address using https rewrite in nginx and limit access to the /admin/ route to
certain IP users while leaving the /reset route open to the world.

### Setup

    pip install -r requirements.txt
### Configuration
    Copy config.yml to config_local.yml and edit as necessary to match ooi-ui-services
    
    SECRET_KEY: <Must match>
    DB_SCHEMA: <Must match, 'ooiui' by default>
    # server dns/port config
    HOST: localhost
    PORT: 5001
    # redis
    REDIS_URL: 'redis://localhost:6379'
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

    python ooium.py
    
    OR
    
    uwsgi --ini app.ini


