from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import boto3
import datetime
import sys
from wtforms import Form, StringField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

#  Session timeout
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    session.modified = True

@app.route('/home')
@is_logged_in
def home():
    return render_template('index.html')

@app.route('/')
@is_logged_in
def index():
    return render_template('index.html')

class RegisterCollection(Form):
    collection = StringField('Enter new collection name', [validators.length(min=4, max=50)])

@app.route('/transcribe', methods=['GET', 'POST'])
@is_logged_in
def collections():
    form = RegisterCollection(request.form)
    ddb = boto3.client('dynamodb')
    email = session['username']
    try:
        response = ddb.get_item(
            Key={
                'email': {
                    'S': email,
                },
            },
            TableName='users_transcribe',
        )

        collections = response['Item']['collections']['L']

    except:
        collections = []

    if request.method == 'POST' and request.form['btn'] == 'create' and form.validate():
        collection = form.collection.data
        for collectionexist in collections:
            if collection == collectionexist['S']:
                flash('Collection already defined', 'danger')
                return redirect(url_for('collections'))
        try:
            response = ddb.update_item(
                UpdateExpression="SET collections = list_append(collections, :col)",
                ExpressionAttributeValues={
                    ':col': {
                        "L": [
                            {"S": collection}
                        ]
                    },
                },
                Key={
                    'email': {
                        'S': email,
                    },
                },
                TableName='users_transcribe',
            )
            return redirect(url_for('collections'))
        except:
            flash('Could not create new collection', 'danger')
            return redirect(url_for('collections'))

    elif request.method == 'POST':
        collectiondelete = request.form['btn']
        i = 0
        for collection in collections:
            if collectiondelete == collection['S']:
                try:
                    response = ddb.update_item(
                        UpdateExpression="REMOVE collections[%(collection)d]" % {'collection': i},
                        Key={
                            'email': {
                                'S': email,
                            },
                        },
                        TableName='users_transcribe',
                    )
                    return redirect(url_for('collections'))
                except:
                    flash('Could not delete collection', 'danger')
                    return redirect(url_for('collections'))
            i = i+1
        return render_template('collections.html', form=form, collections=collections)

    else:
        return render_template('collections.html', form=form, collections=collections)


@app.route('/files')
@is_logged_in
def files():
    return render_template('files.html', collection=id)


class RegisterForm(Form):
    email = StringField('Email', [validators.length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
@is_logged_in
def register():
    form = RegisterForm(request.form)
    ddb = boto3.client('dynamodb')
    email = form.email.data
    emailexist = ''
    try:
        response = ddb.get_item(
            Key={
                'email': {
                    'S': email,
                },
            },
            TableName='users_transcribe',
        )
        emailexist = response['Item']['email']['S']
    except:
        emailexist = ''

    if request.method == 'POST' and form.validate():
        if emailexist != '':
            flash('email address already registered', 'danger')
            return redirect(url_for('register'))
        else:
            password = sha256_crypt.encrypt(str(form.password.data))

            response = ddb.put_item(
                Item={
                    'email': {
                        'S': email,
                    },
                    'password': {
                        'S': password,
                    },
                },
                TableName='users_transcribe',
            )
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form fields
        email = request.form['email']
        password_candidate = request.form['password']
        ddb = boto3.client('dynamodb')
        try:
            response = ddb.get_item(
                Key={
                    'email': {
                        'S': email,
                    },
                },
                TableName='users_transcribe',
            )

            password = response['Item']['password']['S']

            # compare pwd
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = email

                flash('you are logged in', 'success')
                return redirect(url_for('home'))
            else:
                error = 'Invalid credentials'
                return render_template('login.html', error=error)

        except KeyError:
            error = 'Invalid credentials!'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('you are logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key='TheSecretKey!'
    app.run(host='0.0.0.0', debug=True)