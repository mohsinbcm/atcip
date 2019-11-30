
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy import func
from urllib.parse import quote, quote_plus
from base64 import b64encode

params = quote_plus("DRIVER={ODBC Driver 17 for SQL Server};SERVER=db-5zlghd-stc.database.windows.net;DATABASE=atcip-web-db;UID=dbadmin;PWD=Atcip@112019;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;")
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect={}".format(params)
s = URLSafeTimedSerializer('Thisisasecret!')

bootstrap = Bootstrap(app)


app.config.update(dict(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_USERNAME='mohsin.bcm.amu@gmail.com',
    MAIL_PASSWORD='gjfzrmdjjzoqwwwm',
    MAIL_PORT=465,
    MAIL_USE_SSL=True
))

mail = Mail(app)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

import base64


def str_encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def str_decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    verified = db.Column(db.Boolean(), default=False)
    verified_on = db.Column(db.DateTime)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=15, max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember-me')


class RegisterForm(FlaskForm):
    email = StringField('inputEmail', validators=[InputRequired('Email is required'),
                                                  Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('inputPassword', validators=[InputRequired('Password is required'), Length(min=8, max=80)])
    confirm = StringField('confirmPassword', validators=[InputRequired('Please confirm password'),
                                                         Length(min=8, max=80),
                                                         EqualTo('password', message='Passwords must match')])


class ReverifyForm(FlaskForm):
    email = StringField('email', validators=[InputRequired()])


class DashboardForm(FlaskForm):
    image = FileField()


@app.route("/", methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.verified:
                if check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('dashboard'))
                else:
                    form.password.errors = ['Invalid username or password']
            else:
                return redirect(url_for('verify', email=str_encode(app.config['SECRET_KEY'], form.email.data)))
        else:
            form.password.errors = ['Invalid username or password']
    return render_template("index.html", form=form)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        token = s.dumps(form.email.data, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm Email', sender='atcip@gmail.com', recipients=[form.email.data])
        msg.html = '<html><body>Kindly click <a href="{0}">here</a> to verify.</body</html>'.format(link)
        mail.send(msg)
        return redirect(url_for('verify', email=str_encode(app.config['SECRET_KEY'], form.email.data)))
    return render_template("signup.html", form=form)


@app.route('/verify/<email>')
def verify(email):
    email = str_decode(app.config['SECRET_KEY'], email)
    return render_template('signup_success.html', email=email)


@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    form = ReverifyForm()
    if form.validate_on_submit():
        #         try:
        email = s.loads(form.email.data, salt='email-reconfirm', max_age=300)
        user = User.query.filter_by(email=email).first()
        if user:
            token2 = s.dumps(email, salt='email-confirm')
            link = url_for('confirm_email', token=token2, _external=True)
            msg = Message('Confirm Email', sender='atcip@gmail.com', recipients=[email])
            msg.html = '<html><body>Kindly click <a href="{0}">here</a> to verify.</body</html>'.format(link)
            mail.send(msg)
            return redirect(url_for('verify', email=str_encode(app.config['SECRET_KEY'], email)))
        else:
            raise
#         except:  # @IgnorePep8
#             return redirect(url_for('index'))
    else:
        try:
            email = token
            email = s.loads(token, salt='email-confirm', max_age=3600)
            user = User.query.filter_by(email=email).first()
            if user:
                if user.verified:
                    return render_template('verification_success.html', verified=True)
                else:
                    user.verified = True
                    user.verified_on = func.now()
                    db.session.commit()
                    return render_template('verification_success.html', error=None)
            else:
                return render_template('verification_success.html', error='Verification token invalid!')
        except SignatureExpired:  # @IgnorePep8
            email = s.loads(token, salt='email-confirm')
            user = User.query.filter_by(email=email).first()
            if user:
                token2 = s.dumps(email, salt='email-reconfirm')
                print(token2)
                return render_template('verification_success.html', error='Verification token expired!',
                                       form=form, email=email, token=token2)
            else:
                return render_template('verification_success.html', error='Verification token invalid!')
        except:  # @IgnorePep8
            return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DashboardForm()
    if form.validate_on_submit():
        filename = secure_filename(form.image.data.filename)
        form.image.data.save('uploads/' + filename)
        return render_template('dashboard.html', name=current_user.email, data=open('uploads/' + filename, 'rb').read())
    else:
        image = b64encode(open('uploads\\c.jpg', 'rb').read()).decode('ascii')
        return render_template('dashboard.html', name=current_user.email, form=form, data=quote(image))


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0')
