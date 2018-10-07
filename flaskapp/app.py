from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import boto3
import datetime
import sys, os
from wtforms import Form, StringField, PasswordField, validators, SelectField, SubmitField
from passlib.hash import sha256_crypt
from functools import wraps
import google.cloud.storage as storage

app = Flask(__name__)

credential_path = "C:\\Users\\mtryhoen\\OneDrive\\OneDrive - Agilent Technologies\\google\\Speech-1f9b664683c4.json"
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path

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

class TranscriptionForm(Form):
    transcription = StringField('Enter new transcription name', [validators.length(min=4, max=50)])
    template = SelectField(
        'Template',
        coerce=int
    )

@app.route('/transcribe', methods=['GET', 'POST'])
@is_logged_in
def transcription():
    ddb = boto3.client('dynamodb')
    s3 = boto3.client('s3')
    email = session['username']
    form = TranscriptionForm(request.form)
    try:
        objectKey=email.replace('@', '-')
        response = s3.list_objects_v2(
            Bucket="transcribe-template-files",
            Prefix=objectKey
        )
        templates = response['Contents']
    except:
        templates = []
    templateList = []
    for i in range(len(templates)):
        crap, object = str(templates[i]['Key']).split('/')
        data = (str(i), object)
        templateList.append(data)
    form.template.choices = templateList

    try:
        response = ddb.get_item(
            Key={
                'email': {
                    'S': email,
                },
            },
            TableName='users_transcribe',
        )
        transcriptions = response['Item']['transcriptions']['L']
        app.logger.info('Transcriptions: %s', transcriptions)
    except:
        transcriptions = []
    app.logger.info(form.validate())
    if request.method == 'POST' and request.form['btn'] == 'create': #and form.validate():
        transcription = form.transcription.data
        template = form.template.choices[form.template.data]
        app.logger.info('Template: %s', template[1])
        for transcriptionexist in transcriptions:
            if transcription == transcriptionexist['M']['Transcription']['S']:
                flash('transcription already defined', 'danger')
                return redirect(url_for('transcription'))
        try:
            objectKey = email.replace('@', '-')
            url = upload_source_file(request.files.get('sound'), objectKey)
            audiofile = request.files.get('sound').filename
            gcs_uri="gs://transcribe-sounds/" + objectKey + "/" + audiofile
            app.logger.info('URL: %s', url)
            #return redirect(url_for('transcription'))
        except:
            flash('Could not upload the file', 'danger')
            audiofile = "NA"
            url = "NA"
            #return redirect(url_for('transcription'))
        try:
            response = ddb.update_item(
                UpdateExpression="SET transcriptions = list_append(transcriptions, :col)",
                ExpressionAttributeValues={
                    ':col': {
                        "L": [
                            {"M": {"Transcription": {"S": transcription}, "File": {"S": url},
                                               "Template": {"S": template[1]}, "Audiofile": {"S": audiofile}}}
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
            app.logger.info('Create Transcriptions: %s', response)
            app.logger.info('URI: %s', gcs_uri)
            transcribe_gcs(gcs_uri)
            return redirect(url_for('transcription'))
        except :
            try:
                response = ddb.update_item(
                    UpdateExpression="SET transcriptions = :col",
                    ExpressionAttributeValues={
                        ':col': {
                            "L": [
                                {"M": {"Transcription": {"S": transcription}, "File": {"S": url},
                                       "Template": {"S": template[1]}, "Audiofile": {"S": audiofile}}}
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
                #transcribe_gcs(url)
                return redirect(url_for('transcription'))
            except:
                app.logger.info('Error: %s', sys.exc_info()[0])
                flash('Could not create new transcription', 'danger')
                return redirect(url_for('transcription'))

    elif request.method == 'POST':
        transcriptiondelete = request.form['btn']
        i = 0
        for transcription in transcriptions:
            if transcriptiondelete == transcription['M']['Transcription']['S']:
                try:
                    response = ddb.update_item(
                        UpdateExpression= "REMOVE transcriptions[%(transcription)d]" % {'transcription': i},
                        Key={
                            'email': {
                                'S': email,
                            },
                        },
                        TableName='users_transcribe',
                    )
                    return redirect(url_for('transcription'))
                except:
                    flash('Could not delete transcription', 'danger')
                    return redirect(url_for('transcription'))
            i = i+1
        return render_template('transcriptions.html', form=form, transcriptions=transcriptions)
    else:
        return render_template('transcriptions.html', form=form, transcriptions=transcriptions)

def upload_source_file(file, username):
    """
    Upload the user-uploaded file to Google Cloud Storage and retrieve its
    publicly-accessible URL.
    """
    app.logger.info("file: %s", file)
    if not file:
        app.logger.info("No file")
        return None

    public_url = upload_file(
        file.read(),
        file.filename,
        file.content_type,
        username
    )

    app.logger.info("Uploaded file %s as %s.", file.filename, public_url)

    return public_url

def upload_file(file_stream, filename, content_type, username):
    """
    Uploads a file to a given Cloud Storage bucket and returns the public url
    to the new object.
    """
    app.logger.info("uploading")
    #client = storage.Client(project='speech-210613')
    client = storage.Client.from_service_account_json(
        'service_account.json')
    bucket = client.bucket('transcribe-sounds')
    blob = bucket.blob(username + "/" + filename)
    app.logger.info("%s - %s - %s", client, bucket, blob)

    blob.upload_from_string(
        file_stream,
        content_type=content_type,
        client=client
    )

    url = blob.public_url
    app.logger.info("URL %s.", url)

    # if isinstance(url, six.binary_type):
    #     url = url.decode('utf-8')

    return url

def transcribe_gcs(gcs_uri):
    """Asynchronously transcribes the audio file specified by the gcs_uri."""
    from google.cloud import speech
    from google.cloud.speech import enums
    from google.cloud.speech import types
    try:
        app.logger.info("Speech: %s", "YES")
        client = speech.SpeechClient()
        app.logger.info("Client Speech: %s", client)
        audio = types.RecognitionAudio(uri=gcs_uri)
        config = types.RecognitionConfig(
            encoding=enums.RecognitionConfig.AudioEncoding.FLAC,
            sample_rate_hertz=8000,
            language_code='fr-FR')

        operation = client.long_running_recognize(config, audio)

        print('Waiting for operation to complete...')
        response = operation.result(timeout=90)

        # Each result is for a consecutive portion of the audio. Iterate through
        # them to get the transcripts for the entire audio file.
        for result in response.results:
            # The first alternative is the most likely one for this portion.
            print(u'Transcript: {}'.format(result.alternatives[0].transcript))
            print('Confidence: {}'.format(result.alternatives[0].confidence))

    except:
        app.logger.info('Error: %s', sys.exc_info()[0])

@app.route('/files')
@is_logged_in
def files():
    return render_template('files.html')


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