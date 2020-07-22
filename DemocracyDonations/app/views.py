import datetime
import json
import webbrowser
import os
import secrets
import uuid
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from app import bcrypt, db, login_manager
import requests
from flask import render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DecimalField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange, ValidationError
from flask_login import UserMixin, current_user, login_user, logout_user, login_required

from app import app

# The node with which our application interacts, there can be multiple
# such nodes as well.
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"

posts = []
donationsList = []
usersList = []

def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                 tx["index"] = block["index"]
                 tx["hash"] = block["previous_hash"]
                 content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)


def findDonations():
    fetch_posts()
    donationList = []
    for post in posts:
        if post["id"] == "donation":
            donationList.append(post)

    global donationsList
    donationsList = sorted(donationList, key=lambda k: k['timestamp'],
                       reverse=True)


def findUsers():
    fetch_posts()
    userList = []
    for post in posts:
        if post["id"] == "user":
            userList.append(post)

    global usersList
    usersList = sorted(userList, key=lambda k: k['timestamp'],
                       reverse=True)

def totalDonations():
    findDonations()
    Donations = []
    for d in donationsList:
        Donations.append(float(d["donation"]))
    totalDonations = sum(Donations)
    print(totalDonations)



class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class CampaignDonationForm(FlaskForm):
    donorEmail = StringField('Email', validators=[DataRequired(), Email()])
    post_content = StringField('Message to the Campaign', validators=[DataRequired()])
    firstName = StringField('First Name', validators=[DataRequired()])
    lastName = StringField('Last Name', validators=[DataRequired()])
    donorAddress = StringField('Donor Address', validators=[DataRequired()])
    donorZip = StringField('Donor Zip', validators=[DataRequired()])
    donorPhone = StringField('Donor Phone', validators=[DataRequired()])
    donation = StringField('Donation', validators=[DataRequired()])
    submit = SubmitField('Send Campaign Donation')


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        fetch_posts()
        for i in posts:
            if i["username"] == username.data:
                raise ValueError('That username is taken. Please choose a different one.', 'danger')

    def validate_email(self, email):
        fetch_posts()
        for i in posts:
            if i["email"] == email.data:
                raise ValueError('That email is taken. Please try logging in.', 'danger')



class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


@app.route('/')
def index():
    fetch_posts()
    return render_template('index.html',
                           title='Democracy Donations: Transparent politics',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)


@app.route('/donations')
def donations():
    fetch_posts()
    return render_template('donations.html',
                           title='All donations made to Democracy Dollars',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string )

@app.route('/BlockchainData')
def BlockchainData():
    #webbrowser.open_new_tab("{}/chain".format(CONNECTED_NODE_ADDRESS))
    return redirect("{}/chain".format(CONNECTED_NODE_ADDRESS))


@app.route("/register", methods=['GET', 'POST'])
def register():
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    form = RegistrationForm()
    if form.validate_on_submit():
        

        post_object = {
            'id' : 'user',
            'email': form.email.data,
            'username': form.username.data,
            'password': bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            'IP': ip
        }

        # Submit a transaction
        new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)


        requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})

        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.create_all()
        db.session.add(user)
        db.session.commit()          

        #webbrowser.open_new_tab("{}/mine".format(CONNECTED_NODE_ADDRESS))

        flash(f'Account created for {form.username.data}!', 'success')
        return redirect("{}/mine".format(CONNECTED_NODE_ADDRESS))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        fetch_posts()
        try:
            for i in posts:
                if i["id"] == "user":
                    user = (i["email"] == form.email.data)
                    usersql = User.query.filter_by(email=form.email.data).first()
                    if user and bcrypt.check_password_hash(i["password"], form.password.data):
                        login_user(usersql, remember=form.remember.data)
                        flash('You have been logged in!', 'success')
                        return redirect(url_for('index'))
        except KeyError:
            flash('Login Unsuccessful. Please check email and password.', 'danger') 
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')    
            
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()

        post_object = {
                    'id' : 'user',
                    'email': form.email.data,
                    'username': form.username.data,
                    'password': bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
                    'IP': ip
                }

                # Submit a transaction
        new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)


        requests.post(new_tx_address, json=post_object, headers={'Content-type': 'application/json'})


        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route("/campaignDonation", methods=['GET', 'POST'])
def campaignDonation():
    form = CampaignDonationForm()
    if form.validate_on_submit():
        

        post_object = {
            'id' : 'donation',
            'post_content': form.post_content.data,
            'firstName': form.firstName.data,
            'lastName': form.lastName.data,
            'donorEmail': form.donorEmail.data,
            'donorAddress': form.donorAddress.data,
            'donorZip': form.donorZip.data,
            'donorPhone': form.donorPhone.data,
            'donation': form.donation.data,
            #'fund': fund,
            #'campaign': campaign
        }

        # Submit a transaction
        new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)


        requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})

        #webbrowser.open_new_tab("{}/mine".format(CONNECTED_NODE_ADDRESS))
        flash(f'Donation sent by {form.firstName.data}!', 'success')
        return redirect("{}/mine".format(CONNECTED_NODE_ADDRESS))
    return render_template('campaignDonation.html', title='Donation', form=form)


def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))