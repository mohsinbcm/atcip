
import os
from flask import Flask, render_template, redirect, url_for
from flask import send_from_directory
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
from urllib.parse import quote, quote_plus, unquote
from base64 import b64encode
from visionapi import process
from datetime import datetime
import logging
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)
# logg = logging.getLogger()
params = quote_plus("DRIVER={ODBC Driver 17 for SQL Server};SERVER=db-5zlghd-stc.database.windows.net;DATABASE=atcip-web-db;UID=dbadmin;PWD=Atcip@112019;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;")
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect={}".format(params)
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.sqllite"
s = URLSafeTimedSerializer('Thisisasecret!')

bootstrap = Bootstrap(app)


app.config.update(dict(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_USERNAME='mohsin.bcm.amu@gmail.com',
    MAIL_PASSWORD='aoiiifgpcqnemain',
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
    policy = db.relationship('UserPolicies', backref='policy')


class UserPolicies(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0)
    user = db.Column(db.Integer, db.ForeignKey('user.id'))
    policy_doc = db.relationship('Policy', backref="policydetails" , uselist=False)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.String(50), nullable=False)
    start_dt = db.Column(db.DateTime, nullable=False)
    end_dt = db.Column(db.DateTime, nullable=False)
    sum_insured = db.Column(db.Numeric(10,2), nullable=False)
    interest_rate = db.Column(db.Numeric(10,2), nullable=False)
    premium = db.Column(db.Numeric(10,2), nullable=False)
    coordinates = db.Column(db.String(500), nullable=False)
    user_policy = db.Column(db.Integer, db.ForeignKey('user_policies.id'))




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


class PolicyForm(FlaskForm):
    policy_id=StringField('policy', validators=[InputRequired()])
    start_dt=StringField('startdate', validators=[InputRequired()])
    end_dt=StringField('enddate', validators=[InputRequired()])
    sum_insured=StringField('suminsured', validators=[InputRequired()])
    interest_rate=StringField('interest', validators=[InputRequired()])
    premium=StringField('premium', validators=[InputRequired()])
    coordinates=StringField('coordinates', validators=[InputRequired()])
    userpolicyid=StringField('userpolicyid', validators=[InputRequired()])

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
        # try:
        filename = secure_filename(form.image.data.filename)
        form.image.data.save('uploads/' + filename)
        userpolicy = UserPolicies(file_name=filename, status=0, user=current_user.id)
        
        values = process('uploads/' + filename)
        policy = Policy(policy_id=values['policy'],
                        start_dt=values['dates'][0],
                        end_dt=values['dates'][1],
                        sum_insured=values['sum_insured'],
                        interest_rate=values['interest'],
                        premium=values['premium'],
                        coordinates=quote(';'.join(values['coordinates'])),
                        user_policy = userpolicy.id)
        userpolicy.policy_doc=policy
        db.session.add(policy)
        db.session.add(userpolicy)
        db.session.commit()
        # return render_template('dashboard.html', name=current_user.email, data=open('uploads/' + filename, 'rb').read())
        return redirect(url_for('verifypolicy'))
        # except:
        #     form.image.errors = ['Failed to upload files']
        #     return render_template('dashboard.html', name=current_user.email, form=form)
    else:
        userpolicy = UserPolicies.query.filter_by(user=current_user.id).first()
        if userpolicy:
            return redirect(url_for('verifypolicy'))
        return render_template('dashboard.html', name=current_user.email, form=form)

@app.route("/verifypolicy", methods=['GET', 'POST'])
@login_required
def verifypolicy():
    form=PolicyForm()
    if form.validate_on_submit():
        userpolicy = UserPolicies.query.filter_by(id=form.userpolicyid.data).first()
        policy = Policy.query.filter_by(user_policy=form.userpolicyid.data).first()
        policy.policy_id = form.policy_id.data
        policy.start_date = datetime.strptime(form.start_dt.data,'%Y-%m-%d %H:%M:%S')
        policy.end_date = datetime.strptime(form.end_dt.data,'%Y-%m-%d %H:%M:%S')
        policy.sum_insured = float(form.sum_insured.data)
        policy.interest = float(form.interest_rate.data)
        policy.premium = float(form.premium.data)
        policy.coordinates = quote(';'.join([x.strip('\r') for x in form.coordinates.data.split('\n')]))
        userpolicy.status = 1
        db.session.commit()
    #     pass
    # else:
    userpolicy = UserPolicies.query.filter_by(user=current_user.id).first()
    policy = Policy.query.filter_by(user_policy=userpolicy.id).first()
    coordinates = '\n'.join([x for x in (unquote(policy.coordinates)).split(';')])
    status = userpolicy.status
    color= None if status<=2 else ('orange' if status==3 else ('green' if status==4 else 'red'))
    return render_template('verify.html', name=current_user.email, userpolicy=userpolicy, form=form,
                            policy=policy, coordinates=coordinates, status_color=color)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0')
