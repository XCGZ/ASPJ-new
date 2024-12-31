
# * imports
import ast
import base64
import collections
import copy
import csv
import datetime
import hashlib
import io
import json
import logging
import os
import random
import secrets
import shelve
import string
import time
import unittest
import uuid
import warnings
from base64 import b64decode, b64encode
from collections import defaultdict, deque
from datetime import timedelta
from functools import wraps
from threading import Lock
from unittest.mock import patch

import nest_asyncio
import plotly.express as px
import pymysql
import pyotp
import requests
import stripe
import virustotal_python
import vt
from colorlog import ColoredFormatter
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (Blueprint, Flask, flash, g, jsonify, make_response,
                   redirect, render_template, request, session, url_for)
from flask_bcrypt import Bcrypt, bcrypt
from flask_cors import CORS
from flask_ipban import IpBan
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_mail import Mail, Message
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from itsdangerous.url_safe import URLSafeTimedSerializer
from PIL import Image
from twilio.rest import Client
from werkzeug.exceptions import Forbidden, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import (BooleanField, PasswordField, StringField, SubmitField,
                     TextAreaField, EmailField)
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                ValidationError)

import Customer
import Products
from Forms import (CreateCardForm, CreateCustomerForm, CreateProductsForm,
                   ForgotPasswordForm, LoginForm, OtpForm, ResetPasswordForm,
                   SearchForm, SelectCardForm, SignUpForm, UpdateCustomerForm,
                   UpdateProfileForm, ChangePasswordForm)
from login_forms import Loginform
from model import Contact
from staff_management import CreateStaffform, SMsearch
from waitress import serve

import re

import MySQLdb.cursors
from flask_mysqldb import MySQL

nest_asyncio.apply()

# * loads the environment variables from .env file
load_dotenv()


# Zak and general imports END
# general logging


# General app config
app = Flask(__name__,
            static_url_path='',
            static_folder='static',)

app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  #1MB 
# General app config END

# * Cross origin resource sharing
CORS(app)

# * Mail Config
app.config['SECRET_KEY'] = os.getenv('GENERAL_SECRET_KEY')

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'

mail_port = int(os.getenv('MAIL_PORT'))
app.config['MAIL_PORT'] = mail_port

app.config['MAIL_USE_TLS'] = True

app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')

app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')


# MYSQL
mysql_port = int(os.getenv('MYSQL_PORT'))
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_PORT'] = mysql_port
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')


mysql = MySQL(app)

# MYSQL END

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
mail = Mail(app)
# Zak app config END

# Flask ReCaptcha

app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')

# Andrew config
# Flask Login Config

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# CSRF Key Config

secret_key = os.urandom(24)
secret_key_hex = secret_key.hex()
app.config['SECRET_KEY'] = secret_key_hex

# virustotal api key
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_API_KEY_2 = os.getenv('VIRUSTOTAL_API_KEY_2')

# stripe api keys
stripe.api_key = os.getenv('STRIPE_API_KEY')
# This is your Stripe CLI webhook secret for testing your endpoint locally. change very 90d
endpoint_secret = os.getenv('STRIPE_ENDPOINT_SECRET')
# andrew config end
# Flask Limiter

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# * error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    # Check if the rate limit was exceeded on the login page
    if request.endpoint == 'login':
        # Custom error page for login rate limit
        customer_info_adapter.warning(f'ip: {request.remote_addr} has too many failed login attempts.')
        return render_template('customError.html', error_message="Too many failed login attempts.")
    else:
        # General rate limit error message
        return render_template('customError.html', error_code=429, error_message="Too many requests. Please try again later.")

# * error requesteneitytoolarge upload limit
@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    if request.endpoint == 'update_products':
        product_id = request.view_args.get('id')
        flash('File size exceeds the maximum limit of 1 MB')
        return redirect(url_for('update_products', id=product_id))
    elif request.endpoint == 'create_products':
        flash('File size exceeds the maximum limit of 1 MB')
        return redirect(url_for('create_products'))


# session configs
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_FILE_THRESHOLD'] = 8
Session(app)
# Zj app configs end

# twilio 
staff_numbers = ['90180526','81853858']
account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)

# twilio end

# logging class
class IncrementingIdAdapter(logging.LoggerAdapter):
    _global_counter = 0
    _lock = Lock()

    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})

    def process(self, msg, kwargs):
        with self._lock:
            IncrementingIdAdapter._global_counter += 1
            current_id = IncrementingIdAdapter._global_counter

        extra = kwargs.get('extra', {})
        extra['incrementing_id'] = current_id
        kwargs['extra'] = extra
        return msg, kwargs

    @classmethod
    def reset_counter(cls):
        with cls._lock:
            cls._global_counter = 0

# Reset the counter to 0
# IncrementingIdAdapter.reset_counter()
# logging class END

# * logging config
# general logger
class ANSIStripper(logging.Formatter):
    def format(self, record):
        message = super().format(record)
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', message)

general_logger = logging.getLogger()
consoleHandler = logging.FileHandler('../../logs/general.log', 'a', encoding='utf-8')
formatter = ANSIStripper('{asctime} {levelname} {filename} : {message}', style='{')
consoleHandler.setFormatter(formatter)
general_logger.addHandler(consoleHandler)

# product_db logger
db_logger = logging.getLogger('database')
db_logger.setLevel(logging.DEBUG)
db_handler = logging.FileHandler('../../logs/db.log', 'a', encoding='utf-8')
db_handler.setFormatter(logging.Formatter('{asctime} Log_ID: [{incrementing_id}] {levelname} {filename} : {message}', style='{'))
db_logger.addHandler(db_handler)
db_logger_adapter = IncrementingIdAdapter(db_logger)

# purchase_result logger
customer_purchase_logger = logging.getLogger('customer_purchase')
customer_purchase_logger.setLevel(logging.DEBUG)
customer_purchase_handler = logging.FileHandler('../../logs/customer_purchase.log', 'a', encoding='utf-8')
customer_purchase_handler.setFormatter(logging.Formatter('{asctime} Log_ID: [{incrementing_id}] {levelname} {filename} : {message}', style='{'))
customer_purchase_logger.addHandler(customer_purchase_handler)
customer_purchase_adapter = IncrementingIdAdapter(customer_purchase_logger)

# customer info logger
customer_info_logger = logging.getLogger('customer_info')
customer_info_logger.setLevel(logging.DEBUG)
customer_info_handler = logging.FileHandler('../../logs/customer_info.log', 'a', encoding='utf-8')
customer_info_handler.setFormatter(logging.Formatter('{asctime} Log_ID: [{incrementing_id}] {levelname} {filename} : {message}', style='{'))
customer_info_logger.addHandler(customer_info_handler)
customer_info_adapter = IncrementingIdAdapter(customer_info_logger)

# login logging
login_logger = logging.getLogger('login')
login_logger.setLevel(logging.DEBUG)
login_handler = logging.FileHandler('../../logs/login.log', 'a', encoding='utf-8')
login_handler.setFormatter(logging.Formatter('{asctime} Log_ID: [{incrementing_id}] {levelname} {filename} : {message}', style='{'))
login_logger.addHandler(login_handler)
login_adapter = IncrementingIdAdapter(login_logger)

# system logging
system_logger = logging.getLogger('system')
system_logger.setLevel(logging.DEBUG)
system_handler = logging.FileHandler('../../logs/system.log', 'a', encoding='utf-8')
system_handler.setFormatter(logging.Formatter('{asctime} {levelname} {filename} : {message}', style='{'))
system_logger.addHandler(system_handler)
system_adapter = IncrementingIdAdapter(system_logger)

db_logger.propagate = True
customer_purchase_logger.propagate = True
customer_info_logger.propagate = True
login_logger.propagate = True
system_logger.propagate = True








#! testing system outage
# class TestCriticalErrors(unittest.TestCase):
#     @patch('logging.Logger.critical')
#     def test_critical_error_logging(self, mock_critical):
#         # Simulate a critical error
#         try:
#             raise SystemExit("Simulated system outage")
#         except SystemExit as e:
#             system_adapter.critical(f"Critical error: {str(e)}")
#             system_adapter.exception(f'{str(e)}')
#             for num in staff_numbers:
#                 message = client.messages.create(
#                         from_='whatsapp:+14155238886',
#                         body=f'Critical Error has Occurred! Sytem has crashed. Reason: {str(e)}',
#                         to='whatsapp:+65' + num
#                         )
#             print(message.sid)
# unittest.main()
#! testing system outage end

# logging config

# virustotal functions
def scan_file_with_virustotal(file,file_stream, api_key):
    client = vt.Client(api_key)
    
    try:
        # Read the entire file content from the stream
        file_content = file_stream.read()

        # Create a BytesIO object from the file content for scanning
        file_like_object_for_scan = io.BytesIO(file_content)
        # Upload and scan the file
        analysis = client.scan_file(file_like_object_for_scan)

        # Wait for the analysis to complete
        while True:
            analysis = client.get_object("/analyses/{}", analysis.id)
            print(f"Analysis status: {analysis.status}")
            
            if analysis.status == "completed":
                break
            
            time.sleep(30)  # Wait for 30 seconds before checking again

        # Get the analysis stats
        stats = analysis.stats

        print(f"Scan complete. Analysis stats: {stats}")


        # Consider the file malicious if any engine detected it as malicious
        if stats['malicious'] == 0:
            filename = secure_filename(file.filename)
            print(filename)
            filepath = os.path.join('static', 'Images', filename)
            path_to_store = os.path.join('Images', filename)
            path_to_store_formatted = path_to_store.replace("\\","/")
            print(filepath)
            file_like_object_for_save = io.BytesIO(file_content)
            with open(filepath, 'wb') as f:
                f.write(file_like_object_for_save.read())
            print("File is safe and has been stored.")
            return {'name': filename,'status': 'Safe', 'results': stats, 'path': path_to_store_formatted}
        else:
            filename = secure_filename(file.filename)
            path_to_store = os.path.join('Images', filename)
            path_to_store_formatted = path_to_store.replace("\\","/")
            return {'name': filename,'status': 'Unsafe', 'results': stats, 'path': path_to_store_formatted}

    except vt.error.APIError as e:
        print(f"VirusTotal API error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
    finally:
        client.close()

# virustotal functions end

# banned ips
banned_ips = []

#! banned ips simulation uncomment
def check_for_banned_ips():
    #! uncomment to discard
    discard_ip()
    ip = request.remote_addr
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM banned_ips')
    data = cur.fetchall()
    for i in data:
        banned_ips.append(i[1])
    if ip in banned_ips:
        raise Forbidden("Your IP has been blocked due to malicious activity.")
    print(ip)
def discard_ip():
    ip = request.remote_addr
    cur = mysql.connection.cursor()
    query = ('delete from banned_ips where ip = %s')
    params = (ip,)
    cur.execute(query, params)
    mysql.connection.commit()
    print(banned_ips)
#! banned ips simulation uncomment



# @app.route('/home')
# def home():
#     return render_template('home.html')


# Andrew routes
def hash_password(password):
    pepper = os.getenv('PEPPER')
    add_password = password[:3] + pepper[:3] + password[3:6] + pepper[3:5] + password[6:] + pepper[5:]
    salt = bcrypt.gensalt()
    hash_pw = bcrypt.hashpw(bytes(add_password, 'utf-8'), salt)
    return hash_pw


def verify_password(password, stored_hash_pw):
    pepper = os.getenv('PEPPER')
    sn1 = int(os.getenv('SN1'))
    sn2 = int(os.getenv('SN2'))
    sn3 = int(os.getenv('SN3'))
    peppered_PTV = password[:sn1] + pepper[:sn1] + password[sn1:sn2] + pepper[sn1:sn3] + password[sn2:] + pepper[sn3:]
    return bcrypt.checkpw(peppered_PTV.encode('utf-8'), stored_hash_pw.encode('utf-8'))

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    return session['csrf_token']

def scan_file_with_virustotals(filepath):

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
    response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        result = response.json()
        if result.get('response_code') == 1:
            # File detected as malicious if any engine detects it
            if result.get('positives', 0) > 0:
                return 'malicious'
            else:
                return 'clean'
        else:
            return 'unknown'  # Handle unknown response code
    else:
        return 'error'  # Handle API error
    
# Homepage route/login route
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def login():
    ip = request.remote_addr
    login_user_form = LoginForm(request.form)

    def generate_session_id(length):  # Define the function with the parameter ‘length’
        letters = string.ascii_letters + string.digits  # stores upper and lower
        # character and digit in ‘letters’ variable
        session_id = ''.join(random.choice(letters) for _ in range(length))
        return session_id

    if session.get('session_id') is None:
        session['session_id'] = generate_session_id(8)

    if request.method == 'POST' and login_user_form.validate():
        csrf_token = session.get('csrf_token')
        if csrf_token and request.form.get('csrf_token') == csrf_token:

            email = login_user_form.LoginEmail.data
            password = login_user_form.LoginPassword.data

            c = mysql.connection.cursor()

            select_email = "SELECT * FROM Customers WHERE email = %s"

            c.execute(select_email, (email,))
            login_customer = c.fetchone()
            c.close()

            if not login_customer:
                customer_info_adapter.warning(f'ip: {ip} has failed to login')
                flash('Invalid username or password', 'danger')
            elif not verify_password(password, login_customer[2]):
                customer_info_adapter.warning(f'ip: {ip} has failed to login')
                flash('Invalid username or password', 'danger')
            else:
                session['failed_attempts'] = 0
                customer = Customer.Customer(
                    username=login_customer[1],
                    password=login_customer[2],
                    name=login_customer[3],
                    email=login_customer[4],
                    gender=login_customer[5],
                    country_code=login_customer[6],
                    phone_no=login_customer[7],
                    date_of_birth=login_customer[8],
                    profile_picture=login_customer[9],
                    remarks=login_customer[10]
                )
                customer.set_user_id(login_customer[0])
                login_user(customer)
                customer_info_adapter.info(f'Email: {login_customer[4]} | Username: {login_customer[1]} | has logged in.')
                return redirect(url_for('index'))
        else:
            return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('login.html', form=login_user_form, csrf_token=csrf_token)

# Homepage route end

@app.route('/createCustomer', methods=['GET', 'POST'])

def create_customer():
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    create_customer_form = CreateCustomerForm(request.form)

    if request.method == 'POST':
        create_customer_form.profile_picture.data = request.files['profile_picture']
        if create_customer_form.validate():
            csrf_token = session.get('csrf_token')
            if csrf_token and request.form.get('csrf_token') == csrf_token:

                username = create_customer_form.username.data
                email = create_customer_form.email.data
                password = create_customer_form.password.data

                c = mysql.connection.cursor()
                username_select = "SELECT * FROM Customers WHERE username = %s"
                c.execute(username_select, (username,))
                login_username = c.fetchall()

                email_select = "SELECT * FROM Customers WHERE email = %s"
                c.execute(email_select, (email,))
                login_email = c.fetchall()

                strong = True

                if not re.search("[A-Z]", password) or not re.search("[!@#$%^&*()_+={}:;<>,.?/`~0123456789]", password) or not re.search("[0-9]", password):
                    strong = False

                if login_username or login_email or not strong:
                    if login_username:
                        flash('This Username already exist. Please create a new one.', 'username_error')
                    if login_email:
                        flash('This Email already has an Account. Please use a new one.', 'email_error')
                    if not strong:
                        flash('Please have password with at least 1 Uppercase, 1 Number and 1 Special Character',
                              'password_error')
                else:


                    # Profile Picture
                    if 'profile_picture' in request.files:
                        f = request.files['profile_picture']
                        if f:
                            filename = secure_filename(f.filename)
                            filepath = os.path.join('static', 'profile_pictures', filename)
                            print("Saving file to:", filepath)
                            f.save(filepath)

                            virus_scan_result = scan_file_with_virustotals(filepath)
                            if virus_scan_result == 'malicious':
                                # Delete the file if it's malicious
                                os.remove(filepath)
                                return "Error: Profile picture is detected as malicious!"
                            else:
                                create_customer_form.profile_picture.data = filename

                    else:
                        print("No file uploaded")
                        create_customer_form.profile_picture.data = None

                    # Password Hashing
                    password = create_customer_form.password.data
                    create_customer_form.password.data = hash_password(password)


                    c = mysql.connection.cursor()

                    customer = Customer.Customer(
                        create_customer_form.username.data,
                        create_customer_form.password.data,
                        create_customer_form.name.data,
                        create_customer_form.email.data,
                        create_customer_form.gender.data,
                        create_customer_form.country_code.data,
                        create_customer_form.phone_no.data,
                        create_customer_form.date_of_birth.data,
                        create_customer_form.profile_picture.data,
                        create_customer_form.remarks.data,
                    )

                    update_command = '''INSERT INTO customers (username, password, name, email, gender, country_code, phone_no, date_of_birth, profile_picture, remarks)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

                    update_value = (
                        customer.get_username(),
                        customer.get_password(),
                        customer.get_name(),
                        customer.get_email(),
                        customer.get_gender(),
                        customer.get_country_code(),
                        customer.get_phone_no(),
                        customer.get_date_of_birth(),
                        customer.get_profile_picture(),
                        customer.get_remarks()
                    )

                    c.execute(update_command, update_value)

                    mysql.connection.commit()
                    c.close()

                    return redirect(url_for('retrieve_customers'))

            else:
                return "CSRF Token Validation Failed"

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('createCustomer.html', form=create_customer_form, csrf_token=csrf_token)

@app.route('/retrieveCustomers', methods=['GET', 'POST'])

def retrieve_customers():
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    c = mysql.connection.cursor()

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').lower()

        if search_query:
            print(search_query)

            customers_list = []

            c = mysql.connection.cursor()

            search_command = "SELECT * FROM customers WHERE LOWER(username) LIKE %s OR LOWER(email) LIKE %s"
            search_value = ('%' + search_query + '%', '%' + search_query + '%')

            c.execute(search_command, search_value)

            all_customer = c.fetchall()

            for i in all_customer:
                customer = Customer.Customer(i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9], i[10])
                customer.set_user_id(i[0])
                customers_list.append(customer)

            return render_template('retrieveCustomers.html', count=len(customers_list), customers_list=customers_list, search_query=search_query)

        else:

            customers_list = []

            c = mysql.connection.cursor()

            c.execute('SELECT * FROM customers')
            all_customer = c.fetchall()


            for i in all_customer:
                customer = Customer.Customer(i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9], i[10])
                customer.set_user_id(i[0])
                customers_list.append(customer)

            csrf_token = generate_csrf_token()
            session['csrf_token'] = csrf_token
            return render_template('retrieveCustomers.html', count=len(customers_list), customers_list=customers_list)

    else:

        customers_list = []

        c = mysql.connection.cursor()

        c.execute('SELECT * FROM customers')
        all_customer = c.fetchall()

        for i in all_customer:
            customer = Customer.Customer(i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9], i[10])
            customer.set_user_id(i[0])
            customers_list.append(customer)

        csrf_token = generate_csrf_token()
        session['csrf_token'] = csrf_token
        return render_template('retrieveCustomers.html', count=len(customers_list), customers_list=customers_list)


@app.route('/updateCustomer/<int:id>/', methods=['GET', 'POST'])

def update_customer(id):
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    update_customer_form = UpdateCustomerForm(request.form)

    csrf_token = session.get('csrf_token')

    if request.method == 'POST':
        update_customer_form.profile_picture.data = request.files['profile_picture']
        if update_customer_form.validate():
            print(csrf_token)
            print(request.form.get('csrf_token'))

            if not csrf_token or request.form.get('csrf_token') != csrf_token:
                return 'Bad Request'
            else:

                c = mysql.connection.cursor()
                select_command = "SELECT * FROM customers WHERE user_id = %s"
                c.execute(select_command, (id,))
                selected_customer = c.fetchone()

                entered_username = update_customer_form.username.data
                entered_email = update_customer_form.email.data

                existing_username = None
                existing_email = None



                if entered_username != selected_customer[1]:

                    username_select = "SELECT * FROM customers WHERE username = %s"

                    c.execute(username_select, (entered_username,))
                    existing_username = c.fetchall()

                if entered_email != selected_customer[4]:

                    email_select = "SELECT * FROM customers WHERE email = %s"

                    c.execute(email_select, (existing_email,))
                    existing_email = c.fetchall()

                if existing_username or existing_email:
                    if existing_username:
                        flash('This Username already exist. Please create a new one.', 'username_error')
                    if existing_email:
                        flash('This Email already has an Account. Please use a new one.', 'email_error')
                else:

                    customer = Customer.Customer(selected_customer[1], selected_customer[2], selected_customer[3],
                                                 selected_customer[4], selected_customer[5], selected_customer[6],
                                                 selected_customer[7], selected_customer[8], selected_customer[9],
                                                 selected_customer[10])

                    if update_customer_form.validate():

                        if 'profile_picture' in request.files:
                            f = request.files['profile_picture']
                            if f:
                                filename = secure_filename(f.filename)
                                filepath = os.path.join('static', 'profile_pictures', filename)
                                print("Saving file to:", filepath)
                                f.save(filepath)
                                update_customer_form.profile_picture.data = filename


                        customer.set_username(update_customer_form.username.data)
                        customer.set_name(update_customer_form.name.data)
                        customer.set_email(update_customer_form.email.data)
                        customer.set_gender(update_customer_form.gender.data)
                        customer.set_country_code(update_customer_form.country_code.data)
                        customer.set_phone_no(update_customer_form.phone_no.data)
                        customer.set_date_of_birth(update_customer_form.date_of_birth.data)
                        customer.set_profile_picture(update_customer_form.profile_picture.data)
                        customer.set_remarks(update_customer_form.remarks.data)

                        update_command = '''
                                UPDATE customers
                                SET username = %s, name = %s, email = %s, gender = %s, country_code = %s, phone_no = %s, date_of_birth = %s, profile_picture = %s, remarks = %s
                                WHERE user_id = %s
                            '''

                        update_value = (
                            customer.get_username(),
                            customer.get_name(),
                            customer.get_email(),
                            customer.get_gender(),
                            customer.get_country_code(),
                            customer.get_phone_no(),
                            customer.get_date_of_birth(),
                            customer.get_profile_picture(),
                            customer.get_remarks(),
                            id
                        )

                        c.execute(update_command, update_value)

                        mysql.connection.commit()
                        c.close()
                        return redirect(url_for('retrieve_customers'))

    else:

        c = mysql.connection.cursor()

        select_id = "SELECT * FROM customers WHERE user_id = %s"
        c.execute(select_id, (id,))
        selected_customer = c.fetchone()

        customer = Customer.Customer(selected_customer[1], selected_customer[2], selected_customer[3],
                                     selected_customer[4], selected_customer[5], selected_customer[6],
                                     selected_customer[7], selected_customer[8], selected_customer[9],
                                     selected_customer[10])

        update_customer_form.username.data = customer.get_username()
        update_customer_form.name.data = customer.get_name()
        update_customer_form.email.data = customer.get_email()
        update_customer_form.gender.data = customer.get_gender()
        update_customer_form.country_code.data = customer.get_country_code()
        update_customer_form.phone_no.data = customer.get_phone_no()
        update_customer_form.date_of_birth.data = customer.get_date_of_birth()
        update_customer_form.profile_picture.data = customer.get_profile_picture()
        update_customer_form.remarks.data = customer.get_remarks()



    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('updateCustomer.html', form=update_customer_form, csrf_token=csrf_token)

@app.route('/deleteCustomer/<int:id>', methods=['POST'])
def delete_customer(id):
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    # Establish a connection to the SQLite database
    c = mysql.connection.cursor()
    # Delete the user with the given id
    query = 'select email from customers where user_id = %s'
    params = (id,)
    c.execute(query, params)
    data = c.fetchone()
    
    query = 'delete from stripe_customer_address where email = %s'
    params = (data[0],)
    c.execute(query, params)

    query = 'delete from stripe_customer_card where email = %s'
    params = (data[0],)
    c.execute(query, params) 

    delete_command = 'DELETE FROM Customers WHERE user_id = %s'
    c.execute(delete_command, (id,))

    # Commit the transaction and close the connection
    mysql.connection.commit()
    customer_info_adapter.warning(f'Email: {data[0]} | Customer account deleted from customers database.')
    c.close()


    return redirect(url_for('retrieve_customers'))


# Login & Signup


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_form = SignUpForm(request.form)

    if request.method == 'POST':
        signup_form.profile_picture.data = request.files['profile_picture']
        if signup_form.validate():
            csrf_token = session.get('csrf_token')
            if csrf_token and request.form.get('csrf_token') == csrf_token:

                username = signup_form.username.data
                email = signup_form.email.data
                password = signup_form.password.data

                c = mysql.connection.cursor()

                select_username = "SELECT * FROM Customers WHERE username = %s"
                c.execute(select_username, (username,))
                login_username = c.fetchall()

                select_email = "SELECT * FROM Customers WHERE email = %s"
                c.execute(select_email, (email,))
                login_email = c.fetchall()

                strong = True

                if not re.search("[A-Z]", password) or not re.search("[!@#$%^&*()_+={}:;<>,.?/`~0123456789]",password) or not re.search("[0-9]", password):
                    strong = False

                if login_username or login_email or not strong:
                    if login_username:
                        flash('This Username already exist. Please create a new one.', 'username_error')
                    if login_email:
                        flash('This Email already has an Account. Please use a new one.', 'email_error')
                    if not strong:
                        flash('Please have password with at least 1 Uppercase, 1 Number and 1 Special Character', 'password_error')
                else:

                    # Profile Picture
                    if 'profile_picture' in request.files:
                        f = request.files['profile_picture']
                        if f:
                            filename = secure_filename(f.filename)
                            filepath = os.path.join('static', 'profile_pictures', filename)
                            print("Saving file to:", filepath)
                            f.save(filepath)

                            virus_scan_result = scan_file_with_virustotals(filepath)
                            if virus_scan_result == 'malicious':
                                # Delete the file if it's malicious
                                os.remove(filepath)
                                return "Error: Profile picture is detected as malicious!"
                            else:
                                signup_form.profile_picture.data = filename

                    else:
                        print("No file uploaded")
                        signup_form.profile_picture.data = None

                    # Password Hashing
                    password = signup_form.password.data
                    signup_form.password.data = hash_password(password)

                    customer = Customer.Customer(
                        signup_form.username.data,
                        signup_form.password.data,
                        signup_form.name.data,
                        signup_form.email.data,
                        signup_form.gender.data,
                        signup_form.country_code.data,
                        signup_form.phone_no.data,
                        signup_form.date_of_birth.data,
                        signup_form.profile_picture.data,
                        signup_form.remarks.data,
                    )

                    # Insert the customer into the database

                    insert_command = '''INSERT INTO Customers (username, password, name, email, gender, country_code, phone_no, date_of_birth, profile_picture, remarks)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

                    insert_value = (
                        customer.get_username(),
                        customer.get_password(),
                        customer.get_name(),
                        customer.get_email(),
                        customer.get_gender(),
                        customer.get_country_code(),
                        customer.get_phone_no(),
                        customer.get_date_of_birth(),
                        customer.get_profile_picture(),
                        customer.get_remarks()
                    )

                    c.execute(insert_command, insert_value)

                    mysql.connection.commit()
                    c.close()
                    customer_info_adapter.info(f'Email: {customer.get_email()} | Username: {customer.get_username()} | New Customer account created and added to customers database.')
                    return redirect(url_for('login'))
            else:
                return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('signup.html', form=signup_form, csrf_token=csrf_token)


@login_manager.user_loader
def load_user(user_id):
    c = mysql.connection.cursor()
    select_id = "SELECT * FROM customers WHERE user_id = %s"
    c.execute(select_id, (user_id,))
    selected_customer = c.fetchone()
    c.close()
    if selected_customer:

        return Customer.Customer(
            username=selected_customer[1],
            password=selected_customer[2],
            name=selected_customer[3],
            email=selected_customer[4],
            gender=selected_customer[5],
            country_code=selected_customer[6],
            phone_no=selected_customer[7],
            date_of_birth=selected_customer[8],
            profile_picture=selected_customer[9],
            remarks=selected_customer[10]
        )
    return None

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if "cart_products" not in session:
        session["cart_products"] = {}

    if "cart_products" in session:
        session["cart_products"].clear()

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('delete from db_session_id')
    mysql.connection.commit()
    cur.close()


    return redirect(url_for('login'))

def send_email(subject, body, sender, recipient):
    msg = Message(subject, sender=sender, recipients=recipient)
    msg.body = body
    mail.send(msg)




@app.route('/forgotPassword', methods=['GET', 'POST'])
def forgot_password():
    forgot_password_form = ForgotPasswordForm(request.form)
    if request.method == 'POST' and forgot_password_form.validate():
        csrf_token = session.get('csrf_token')
        if csrf_token and request.form.get('csrf_token') == csrf_token:
            email = forgot_password_form.email.data

            c = mysql.connection.cursor()

            select_email = "SELECT * FROM customers WHERE email = %s"
            c.execute(select_email, (email,))
            selected_customer = c.fetchone()

            c.close()


            if selected_customer:

                otp_secret = pyotp.random_base32()
                session['otp_secret'] = otp_secret
                session['otp_email'] = email

                def generate_otp():  # Define the function with the parameter ‘length’
                    totp = pyotp.TOTP(otp_secret, interval=600)
                    return totp.now()

                otp = generate_otp()

                email_recipient = [email]
                email_subject = 'Password Reset'
                email_body = f"Here is the OTP(One Time Password): {otp}"
                sender = 'renewifysg@gmail.com'

                send_email(email_subject, email_body, sender, email_recipient)
                return redirect(url_for('otp'))
            else:
                return redirect(url_for('otp'))

        else:
            return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('forgetPassword.html', form=forgot_password_form, csrf_token=csrf_token)


@app.route('/otp', methods=['GET', 'POST'])
def otp():
    otp_form = OtpForm(request.form)
    if request.method == 'POST' and otp_form.validate():
        csrf_token = session.get('csrf_token')

        if csrf_token and request.form.get('csrf_token') == csrf_token:

            entered_otp = otp_form.entered_otp.data
            otp_secret = session.get('otp_secret')

            def validate_otp(otp):

                totp = pyotp.TOTP(otp_secret, interval=600)
                return totp.verify(otp)

            if not validate_otp(entered_otp):
                flash('Incorrect One Time Password, Please Check your Email again.', 'OTP_Error')
            else:
                return redirect(url_for('reset_password'))

        else:
            return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('otp.html', form=otp_form, csrf_token=csrf_token)


@app.route('/resetPassword', methods=['GET', 'POST'])
def reset_password():
    reset_password_form = ResetPasswordForm(request.form)
    if request.method == 'POST' and reset_password_form.validate():
        csrf_token = session.get('csrf_token')
        if csrf_token and request.form.get('csrf_token') == csrf_token:

            password = reset_password_form.password.data
            confirm_password = reset_password_form.confirm_password.data

            if not re.search("[A-Z]", password) or not re.search("[!@#$%^&*()_+={}:;<>,.?/`~0123456789]", password) or not re.search("[0-9]", password):
                flash('Please have password with at least 1 Uppercase, 1 Number and 1 Special Character', 'password_error')
            elif confirm_password != password:
                flash('Password and Confirm password do not match, please ensure that they are the same', 'confirm_error')
            else:

                email = session.get('otp_email')
                print(email)
                c = mysql.connection.cursor()
                new_password = reset_password_form.confirm_password.data

                update_command = "UPDATE customers SET password = %s WHERE email = %s"

                c.execute(update_command, (hash_password(new_password), email))
                mysql.connection.commit()
                c.close()

                session.pop('otp_secret', None)
                session.pop('otp_email', None)

                return redirect(url_for('login'))
        else:
            return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('resetPassword.html', form=reset_password_form, csrf_token=csrf_token)
# Profile
@app.context_processor
def profile():
    profile_picture = None
    username = None
    profile = None
    c = mysql.connection.cursor()
    try:
        print(current_user.get_username())
        profile = current_user.get_username()
        c.close()
        if profile:

            c = mysql.connection.cursor()

            select_command = "SELECT * FROM Customers WHERE username = %s"

            c.execute(select_command, (profile,))
            customer = c.fetchone()

            try:
                username = customer[1]
                profile_picture = customer[9]
            except TypeError:
                username = None
                profile_picture = None
    except:
        profile = None

    return dict(profile_picture=profile_picture, username=username)


@app.route('/retrieveProfile', methods=['GET', 'POST'])
@login_required
def retrieve_profile():
    c = mysql.connection.cursor()
    selected_profile = current_user.get_username()
    c.close()


    c = mysql.connection.cursor()

    select_command = "SELECT * FROM Customers WHERE username = %s"

    c.execute(select_command, (selected_profile,))
    profile = c.fetchone()

    customer = Customer.Customer(profile[1], profile[2], profile[3], profile[4], profile[5], profile[6], profile[7], profile[8], profile[9], profile[10])

    profile_picture = customer.get_profile_picture()
    username = customer.get_username()
    name = customer.get_name()
    email = customer.get_email()
    gender = customer.get_gender()
    phonecode = customer.get_country_code()
    phoneno = customer.get_phone_no()
    dateofbirth = customer.get_date_of_birth()

    return render_template('retrieveProfile.html', username=username, profile_picture=profile_picture, name=name,
                           email=email, gender=gender, phonecode=phonecode, phoneno=phoneno, dateofbirth=dateofbirth)

@app.route('/changePassword', methods=['GET', 'POST'])
@login_required
def change_password():
    change_password_form = ChangePasswordForm(request.form)
    if request.method == 'POST' and change_password_form.validate():
        csrf_token = session.get('csrf_token')
        if csrf_token and request.form.get('csrf_token') == csrf_token:

            old_password = change_password_form.old_password.data
            new_password = change_password_form.new_password.data
            confirm_password = change_password_form.confirm_password.data

            password = current_user.get_password()

            if not verify_password(old_password, password):
                flash('Your Original Password is incorrect, please try again', 'old_password_error')
            elif not re.search("[A-Z]", new_password) or not re.search("[!@#$%^&*()+={}:;<>,.?/`~0123456789]", new_password) or not re.search("[0-9]", new_password):
                flash('Please have password with at least 1 Uppercase, 1 Number and 1 Special Character', 'password_error')
            elif confirm_password != new_password:
                flash('Password and Confirm password do not match, please ensure that they are the same', 'confirm_error')
            else:

                c = mysql.connection.cursor()
                changed_password = change_password_form.confirm_password.data

                email = current_user.get_email()

                update_command = "UPDATE customers SET password = %s WHERE email = %s"

                c.execute(update_command, (hash_password(changed_password), email))
                mysql.connection.commit()
                c.close()

                return redirect(url_for('retrieve_profile'))
        else:
            return 'Bad Request'

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('changePassword.html', form=change_password_form, csrf_token=csrf_token)


@app.route('/updateProfile', methods=['GET', 'POST'])
@login_required
def update_profile():
    update_profile_form = UpdateProfileForm(request.form)

    if request.method == 'POST':
        update_profile_form.profile_picture.data = request.files['profile_picture']
        if update_profile_form.validate():
            csrf_token = session.get('csrf_token')
            if not csrf_token or request.form.get('csrf_token') != csrf_token:
                return 'Bad Request'
            else:

                c = mysql.connection.cursor()
                login_customer = current_user.get_username()
                c.close()

                c = mysql.connection.cursor()
                select_customers = "SELECT * FROM customers WHERE username = %s"

                c.execute(select_customers, (login_customer,))
                selected_customer = c.fetchone()

                entered_username = update_profile_form.username.data
                entered_email = update_profile_form.email.data

                existing_username = None
                existing_email = None

                if entered_username != current_user.get_username():
                    select_entered_username = "SELECT * FROM customers WHERE username = %s"
                    c.execute(select_entered_username, (entered_username,))
                    existing_username = c.fetchall()

                if entered_email != current_user.get_email():
                    select_entered_email = "SELECT * FROM customers WHERE email = %s"
                    c.execute(select_entered_email, (entered_email,))
                    existing_email = c.fetchall()

                if existing_username or existing_email:
                    if existing_username:
                        flash('This Username already exist. Please create a new one.', 'username_error')
                    if existing_email:
                        flash('This Email already has an Account. Please use a new one.', 'email_error')
                else:

                    customer = Customer.Customer(selected_customer[1], selected_customer[2], selected_customer[3], selected_customer[4], selected_customer[5], selected_customer[6], selected_customer[7], selected_customer[8], selected_customer[9], selected_customer[10])

                    if request.method == 'POST' and update_profile_form.validate():
                        csrf_token = session.get('csrf_token')
                        if csrf_token and request.form.get('csrf_token') == csrf_token:
                            customer.set_username(update_profile_form.username.data)
                            customer.set_name(update_profile_form.name.data)
                            customer.set_gender(update_profile_form.gender.data)
                            customer.set_email(update_profile_form.email.data)
                            customer.set_country_code(update_profile_form.country_code.data)
                            customer.set_phone_no(update_profile_form.phone_no.data)
                            customer.set_date_of_birth(update_profile_form.date_of_birth.data)

                            if 'profile_picture' in request.files:
                                f = request.files['profile_picture']
                                if f.filename != '':
                                    filename = secure_filename(f.filename)
                                    filepath = os.path.join('static', 'profile_pictures', filename)  # Choose a directory to store uploads
                                    print("Saving file to:", filepath)
                                    f.save(filepath)
                                    customer.set_profile_picture(filename)



                            update_command = '''
                                    UPDATE customers
                                    SET username = %s, password = %s, name = %s, email = %s, gender = %s, country_code = %s, phone_no = %s, date_of_birth = %s, profile_picture = %s
                                    WHERE user_id = %s
                                '''

                            update_value = (
                                customer.get_username(),
                                customer.get_password(),
                                customer.get_name(),
                                customer.get_email(),
                                customer.get_gender(),
                                customer.get_country_code(),
                                customer.get_phone_no(),
                                customer.get_date_of_birth(),
                                customer.get_profile_picture(),
                                selected_customer[0]
                            )

                            c.execute(update_command, update_value)

                            mysql.connection.commit()
                            c.close()

                            return redirect(url_for('retrieve_profile'))
    else:
        c = mysql.connection.cursor()
        login_customer = current_user.get_username()

        c.close()

        c = mysql.connection.cursor()
        select_customer = "SELECT * FROM customers WHERE username = %s"
        c.execute(select_customer, (login_customer,))
        selected_customer = c.fetchone()

        customer = Customer.Customer(selected_customer[1], selected_customer[2], selected_customer[3],
                                      selected_customer[4], selected_customer[5], selected_customer[6],
                                      selected_customer[7], selected_customer[8], selected_customer[9],
                                      selected_customer[10])

        update_profile_form.username.data = customer.get_username()
        update_profile_form.name.data = customer.get_name()
        update_profile_form.email.data = customer.get_email()
        update_profile_form.gender.data = customer.get_gender()
        update_profile_form.country_code.data = customer.get_country_code()
        update_profile_form.phone_no.data = customer.get_phone_no()
        update_profile_form.date_of_birth.data = customer.get_date_of_birth()
        update_profile_form.profile_picture.data = customer.get_profile_picture()

    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('updateProfile.html', form=update_profile_form, csrf_token=csrf_token)
# andrew end

# xavier routes
def create_connection():
    connection = None
    try:
        connection = pymysql.connect(
            host=os.getenv('MYSQL_HOST'),
            user=os.getenv('MYSQL_USER'),
            password=os.getenv('MYSQL_PASSWORD'),
            database=os.getenv('MYSQL_DB'),
            port = int(os.getenv('MYSQL_PORT'))
        )
        if connection:
            print("Connection to MySQL DB successful")
            # get cursor object
            cursor = connection.cursor()

            # execute your query
            cursor.execute("SELECT * FROM account")

            # fetch all the matching rows
            result = cursor.fetchall()

    except EOFError as e:
        print(f"The error '{e}' occurred")
    return connection


@app.route('/dash', methods=["GET", "POST"])
def dash():
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    return render_template('admin_dashboard.html')


@app.route("/customer-login", methods=["GET", "POST"])
def customer_login():
    ip = request.remote_addr
    create_connection()
    form = Loginform(request.form)
    if request.method == 'POST':
        # change salt & pepper to (pepper , salt, pepper salt, pepper)
        password_to_verify = form.password.data
        pepper = os.getenv('PEPPER')
        sn1 = os.getenv('SN1')
        sn2 = os.getenv('SN2')
        sn3 = os.getenv('SN3')
        peppered_PTV = password_to_verify[:int(sn1)] + pepper[:int(sn1)] + password_to_verify[int(sn1):int(sn2)] + \
                       pepper[int(sn1):int(sn3)] + password_to_verify[int(sn2):] + pepper[int(sn3):]

        connection = create_connection()
        cursor = connection.cursor()

        try:
            # Getting staff side
            txtPass = form.email.data
            txtSQL = "SELECT password, role FROM account WHERE email = %s"
            cursor.execute(txtSQL, txtPass)

            # fetch all the matching rows for staff
            staff_result = cursor.fetchone()


            if staff_result:
                stored_hash = staff_result[0]  # Extract the hash from the tuple
                stored_role = staff_result[1]
                
                    

                if bcrypt.checkpw(peppered_PTV.encode('utf-8'), stored_hash.encode('utf-8')):
                    otp_secret = pyotp.random_base32()
                    session['otp_customer_login_secret'] = otp_secret
                    # Generate OTP
                    def generate_otp():  # Define the function with the parameter ‘length’
                        totp = pyotp.TOTP(otp_secret, interval=600)
                        return totp.now()
                    otp = generate_otp()

                    # Here you would send the OTP via email using your send_email function
                    email_recipient = [form.email.data]
                    email_subject = 'Staff Login OTP'
                    email_body = f"Here is the OTP(One Time Password): {otp}"
                    sender = 'renewifysg@gmail.com'
                    send_email(email_subject, email_body, sender, email_recipient)

                    session['user_email'] = form.email.data
                    session['staff'] = True
                    session['role'] = stored_role
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Invalid username or password', 'danger')
                    login_adapter.warning(f'Staff | Email: {txtPass} | role: {stored_role} | Has failed to login')
            elif customer_result:
                stored_hash = customer_result[0]

                if bcrypt.checkpw(peppered_PTV.encode('utf-8'), stored_hash.encode('utf-8')):
                    session['logged_in'] = True
                    session['user_email'] = form.email.data
                    session['staff'] = False
                    return redirect(url_for('main'))
                else:
                    flash('Invalid username or password', 'danger')
            else:
                flash('Invalid username or password', 'danger')
        except:
            login_adapter.warning(f'ip: {ip} has just tried and failed to login without using a valid email in the database.')

            print("error")
        finally:
            cursor.close()
            connection.close()
            print('connection close')

    return render_template('login_page.html', form=form)


@app.route("/customer-logout")
def customer_logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    return redirect(url_for('customer_login'))



@app.route("/createStaff", methods=['GET', 'POST'])
def createstaff():
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    
    else:
        if session['role'] != 'Admin':
            return redirect(url_for('dash'))
        else:
            sm_form = CreateStaffform(request.form)

            connection = create_connection()
            cursor = connection.cursor()
            cursor.execute('select max(id) from account')
            result = cursor.fetchone()
            id_no = result[0] + 1

            unique_id = uuid.uuid4().hex[:8]

            # Generate a random string for the email prefix
            random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

            # Combine the unique identifier and random prefix to form the email
            random_email = f"{random_prefix}{unique_id}@renewify.com"


            if request.method == 'POST' or sm_form.validate_on_submit():
                connection = create_connection()
                cursor = connection.cursor()

                pepper = os.getenv('PEPPER')
                password = sm_form.staff_password.data
                sn1 = os.getenv('SN1')
                sn2 = os.getenv('SN2')
                sn3 = os.getenv('SN3')
                add_password = password[:int(sn1)] + pepper[:int(sn1)] + password[int(sn1):int(sn2)] + \
                               pepper[int(sn1):int(sn3)] + password[int(sn2):] + pepper[int(sn3):]
                salt = bcrypt.gensalt()
                hash_pw = bcrypt.hashpw(bytes(add_password, 'utf-8'), salt)
                organization = ' '

                # execute your query
                txtSql = "INSERT INTO account (id, username, password, email, phone_number, organization, address" \
                         ", city, state, country, postalcode, role) VALUES (%s, %s, %s, %s, %s, %s, %s," \
                         " %s, %s, %s, %s, %s)"
                txtValue = (id_no, sm_form.staff_username.data, hash_pw, random_email, sm_form.phone_no.data,
                            organization, sm_form.address.data, sm_form.city.data,
                            sm_form.state.data, sm_form.country.data, sm_form.postalcode.data, "Staff")
                cursor.execute(txtSql, txtValue)
                connection.commit()
                cursor.close()
                connection.close()
                print('Data inserted successfully')

                return redirect(url_for('dash'))
            return render_template('Create_page_for_admin.html', form=sm_form)


@app.route("/deleteStaff/<int:id>", methods=['GET', 'POST'])
def deletestaff(id):
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    else:
        if session['role'] != 'Admin':
            return redirect(url_for('dash'))
        else:
            connection = create_connection()
            cursor = connection.cursor()
            txtSQL = 'delete from account where id = %s'
            cursor.execute(txtSQL, (id,))
            connection.commit()
            cursor.close()
            connection.close()
            return render_template('admin_dashboard.html')


@app.route("/editStaff/<int:id>", methods=['GET', 'POST'])
def edit_staff(id):
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    else:
        if session['role'] != 'Admin':
            return redirect(url_for('dash'))
        else:
            update_form = CreateStaffform(request.form)
            if request.method == 'POST':
                connection = create_connection()
                cursor = connection.cursor()
                organization = ' '
                txtSQL = 'update account set username = %s, email = %s, phone_number = %s, organization = %s, ' \
                         'address = %s, city = %s, state = %s, country = %s, postalcode = %s, role = %s where id = %s'
                txtVals = (update_form.staff_username.data,
                           update_form.email.data,
                           update_form.phone_no.data,
                           organization,
                           update_form.address.data,
                           update_form.city.data,
                           update_form.state.data,
                           update_form.country.data,
                           int(update_form.postalcode.data),
                           update_form.role.data,
                           id)
                cursor.execute(txtSQL, txtVals)
                connection.commit()
                cursor.close()
                connection.close()
                return redirect('/staff_account_table')
            else:
                lisst = []

                connection = create_connection()
                cursor = connection.cursor()
                txtSQL = 'select * from account where id = %s'
                cursor.execute(txtSQL, (id,))
                r = cursor.fetchone()
                for i in r:
                    lisst.append(i)
                result = lisst
                update_form.staff_username.data = result[1]
                update_form.email.data = result[3]
                update_form.phone_no.data = result[4]
                update_form.organisation.data = result[5]
                update_form.address.data = result[6]
                update_form.city.data = result[7]
                update_form.state.data = result[8]
                update_form.country.data = result[9]
                update_form.postalcode.data = result[10]
                update_form.role.data = result[11]
                cursor.close()
                connection.close()
                return render_template('edit_staff_page.html', form=update_form)


@app.route('/staff_account_table', methods=['GET', 'POST'])
def account_table():
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    else:
        connection = create_connection()
        cursor = connection.cursor()

        txtSQL = 'select id, username, email, phone_number, organization, address, city, state, country, ' \
                 'postalcode, role from account'
        cursor.execute(txtSQL)
        results = cursor.fetchall()
        staffs = list(results)
        cursor.close()
        connection.close()

        # Get the 'start' index from query parameters, defaulting to 0 if not present
        start = int(request.args.get('start', 0))

        # Calculate the 'end' index for pagination (exclusive)
        end = start + 10

        try:
            start = int(start)
            end = int(end)
        except ValueError:
            start = 0
            end = 10

        # Prevent negative start index
        start = max(start, 0)  # This line handles the negative start index

        # Slice the orders list to retrieve the appropriate subset
        staff_to_display = staffs[start:end]
        searchform = SMsearch(request.form)
        return render_template('Staff_table.html', staffs=staff_to_display, start=start, end=end, form=searchform)


@app.route('/staff_account_table/search', methods=['GET', 'POST'])
def search_name():
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    else:
        searchform = SMsearch(request.form)

        if request.method == 'POST' and searchform.validate():
            connection = create_connection()
            cursor = connection.cursor()
            txtSql = 'select id, username, email, phone_number, organization, address, city, state, country, ' \
                     'postalcode, role from account where username like %s'
            txtvalue = f'%{searchform.search.data}%'
            cursor.execute(txtSql, (txtvalue,))
            results = cursor.fetchall()
            staffs = list(results)
            cursor.close()
            connection.close()

            start = int(request.args.get('start', 0))
            end = start + 10

            # Convert to integers and handle NaN case
            try:
                start = int(start)
                end = int(end)
            except ValueError:
                start = 0
                end = 10

            # Prevent negative start index
            start = max(start, 0)

            return render_template('Staff_table.html', staffs=staffs, start=start, end=end, form=searchform)

        return render_template('Staff_table.html', form=searchform, staffs=[])

# entered_otp = otp_form.entered_otp.data
#             otp_secret = session.get('otp_secret')

#             def validate_otp(otp):

#                 totp = pyotp.TOTP(otp_secret, interval=600)
#                 return totp.verify(otp)

#             if not validate_otp(entered_otp):
#                 flash('Incorrect One Time Password, Please Check your Email again.', 'OTP_Error')
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_provided = request.form['otp']
        # print(otp_provided)
        otp_secret = session.get('otp_customer_login_secret')
        # print(otp_secret)

        if otp_secret:  # Ensure that otp_secret is available in session
            totp = pyotp.TOTP(otp_secret, interval=600)

            if totp.verify(otp_provided):
                # OTP is valid
                session['logged_in'] = True
                return redirect(url_for('dash'))
            else:
                # OTP is invalid
                flash('Invalid OTP. Please try again.', 'warning')
        else:
            flash('Session expired. Please login again.', 'danger')
            return redirect(url_for('login'))

    return render_template('verify_otp.html')

# xavier end

# ryan
class ContactForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')
@app.route('/index')
@limiter.limit("5 per minute")  # Limits to 5 refreshes per minute
@login_required
def index():
    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item
    return render_template('index.html', products_dict = products_dict)

@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    form = ContactForm(request.form)
    if request.method == 'POST':
        fname = form.fname.data
        lname = form.lname.data
        email = form.email.data
        message = form.message.data

        new_contact = Contact(fname, lname, email, message)
        new_contact.save()

        # You might want to do something with the form data here, like saving it to a database
        msg = Message(
        subject=f"confirmation of inquiry", sender = 'renewifysg@gmail.com', recipients=[email] #e['payment_method']['billing_details']['email']
        )  # Replace with recipient(s)
        try:
            msg.body=f"""
                Details:
                {fname} {lname}

                Message:
                {message}

            """
        except:
            print('error')

        mail.send(msg)
        return redirect(url_for('thankyou'))

    return render_template('contact.html', form = form)

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')
# ryan end


@app.errorhandler(404)
def invalid_route(e):
    return render_template('customError.html', error_code = 404, error_message = 'Page Not Found')









# @app.route("/logout")
# def logout():
#     logout_user()

#     if "cart_products" not in session:
#         session["cart_products"] = {}

#     if "cart_products" in session:
#         session["cart_products"].clear()

#     db_session_id = shelve.open('session_id.db', 'c')
#     session_id_dict = {}
#     try:
#         if 'session_id' in db_session_id:
#             session_id_dict = db_session_id['session_id']
#         else:
#             db_session_id['session_id'] = session_id_dict
#     except:
#         print('Error in retrieving products from products.db.')

#     db_session_id.clear()


#     return redirect(url_for('home'))



# Products_listing route. This page lists all the products on the website. It is the main page
@app.route('/Products', methods=['GET', 'POST'])
@login_required
def products():


    # app.logger.debug("debug log info")
    # app.logger.info("Info log information")
    # app.logger.warning("Warning log info")
    # app.logger.error("Error log info")
    # app.logger.critical("Critical log info")

    # if not current_user.is_authenticated:
    #     return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item


    if "cart_products" not in session:
        session["cart_products"] = {}

    if "cart_products" in session:
        cart_session = session["cart_products"]

    if "cart_products" in session:
        cart_session = session["cart_products"]

    # try:
    #     form = UpdateAccountForm()
    #     if form.validate_on_submit():
    #         current_user.email = form.email.data
    #         print(current_user.email)
    #     elif request.method == 'GET':
    #         form.email.data = current_user.email
    #         print(form.email.data)
    # except:
    #     print('error')
    # try:
    #     cart_session_key = []
    #     for key in cart_session:
    #         if form.email.data in cart_session:
    #             print(key)
    #         else:
    #             cart_session_key.append(form.email.data)
    #             cart_session[cart_session_key[0]] = cart_session.pop('2')
    #             session["cart_products"] = cart_session
    #             break
    # except:
    #     print('error')


    country_value = []
    dietary_value = []
    type_value = []
    search_form = SearchForm(request.form)
    # product filters on this page
    if request.method == 'POST':
        csrf_token = session.get('csrf_token')
        if not csrf_token or request.form.get('csrf_token') != csrf_token:
            return 'Bad Request'
        else:
            country_value = request.form.getlist('country')
            dietary_value = request.form.getlist('dietary')
            type_value = request.form.getlist('type')
            filtered_products = {}


            if country_value == [] and dietary_value == [] and type_value == []:
                filtered_products = products_dict

            # Country Only
            elif country_value != [] and dietary_value == [] and type_value == []:

                country_values_to_check = ['Singapore','Japan', 'China', 'India']
                for country_value_to_check in country_values_to_check:
                    if country_value_to_check in country_value:
                        country_products = {key: value for key, value in products_dict.items() if value.get_country() == country_value_to_check}
                        filtered_products.update(country_products)

            # Dietary Only
            elif country_value == [] and dietary_value != [] and type_value == []:

                dietary_values_to_check = ['Upcycled', 'Recycled']
                for dietary_value_to_check in dietary_values_to_check:
                    if dietary_value_to_check in dietary_value:
                        dietary_products = {key: value for key, value in products_dict.items() if value.get_dietary() == dietary_value_to_check}
                        filtered_products.update(dietary_products)

            # type Only
            elif country_value == [] and dietary_value == [] and type_value != []:
                type_values_to_check = ['Shoes','Tees']
                for type_value_to_check in type_values_to_check:
                    if type_value_to_check in type_value:
                        type_products = {key: value for key, value in products_dict.items() if value.get_type() == type_value_to_check}
                        filtered_products.update(type_products)

            # Country and Dietary
            # elif country_value == [] and dietary_value == [] and type_value != []:

            elif country_value != [] and dietary_value != [] and type_value == []:
                dietary_values_to_check = ['Upcycled', 'Recycled']
                country_values_to_check = ['Singapore', 'Japan', 'China', 'India']

                for country_value_to_check in country_values_to_check:
                    for dietary_value_to_check in dietary_values_to_check:
                        if country_value_to_check in country_value and dietary_value_to_check in dietary_value:
                            country_dietary_products = {key: value for key, value in products_dict.items() if value.get_country() == country_value_to_check and value.get_dietary() == dietary_value_to_check}
                            filtered_products.update(country_dietary_products)

            # Country and type

            elif country_value != [] and dietary_value == [] and type_value != []:
                country_values_to_check = ['Singapore', 'Japan', 'China', 'India']
                type_values_to_check = ['Shoes','Tees']

                for country_value_to_check in country_values_to_check:
                    for type_value_to_check in type_values_to_check:
                        if country_value_to_check in country_value and type_value_to_check in type_value:
                            country_type_products = {key: value for key, value in products_dict.items() if value.get_country() == country_value_to_check and value.get_type() == type_value_to_check}
                            filtered_products.update(country_type_products)

            # type and Dietary

            elif country_value == [] and dietary_value != [] and type_value != []:
                dietary_values_to_check = ['Upcycled', 'Recycled']
                type_values_to_check = ['Shoes','Tees']

                for dietary_value_to_check in dietary_values_to_check:
                    for type_value_to_check in type_values_to_check:
                        if dietary_value_to_check in dietary_value and type_value_to_check in type_value:
                            dietary_type_products = {key: value for key, value in products_dict.items() if value.get_dietary() == dietary_value_to_check and value.get_type() == type_value_to_check}
                            filtered_products.update(dietary_type_products)

            # Country and type and Dietary

            elif country_value != [] and dietary_value != [] and type_value != []:
                country_values_to_check = ['Singapore', 'Japan', 'China', 'India']
                dietary_values_to_check = ['Upcycled', 'Recycled']
                type_values_to_check =['Shoes','Tees']
                for country_value_to_check in country_values_to_check:
                    for dietary_value_to_check in dietary_values_to_check:
                        for type_value_to_check in type_values_to_check:
                            if country_value_to_check in country_value and dietary_value_to_check in dietary_value and type_value_to_check in type_value:
                                country_dietary_type_products = {key: value for key, value in products_dict.items() if value.get_country() == country_value_to_check and value.get_dietary() == dietary_value_to_check and value.get_type() == type_value_to_check}
                                filtered_products.update(country_dietary_type_products)

            products_list = []
            for key in filtered_products:
                product = filtered_products.get(key)
                products_list.append(product)
            count = len(products_list)
            print(count)

            cur.close()

            return render_template('products_list.html',csrf_token=csrf_token, form = search_form, products_dict=filtered_products, country_value = country_value, dietary_value = dietary_value, type_value = type_value, cart_session=cart_session, count = count)

    # product filters on this page ends
    products_list = []
    for key in products_dict:
        product = products_dict.get(key)
        products_list.append(product)
    count = len(products_list)

    cur.close()
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('products_list.html', form = search_form, products_dict=products_dict, cart_session = cart_session, count = count, csrf_token=csrf_token)

# Products_listing route. This page lists all the products on the website. It is the main page end

@app.route("/product/<name>")
def specific_product(name):
    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item

    random_keys = random.choices(list(products_dict.keys()), k=12)  # Convert to list
    random_products_list = []
    for key in products_dict:
        if key in random_keys:
            random_products_list.append(products_dict[key])

    for key in products_dict:
        if name == products_dict[key].get_name():
            cur.close()
            return render_template("specific_product.html", product=products_dict[key], products_list=random_products_list)


# Adding a product from products_listing to the cart
@app.route('/addProductCart', methods=['GET','POST'])
def add_product_cart():
    if request.method == 'POST':
        # Get the product id (id of the product) from submit button(Add to cart button) on the products_listing page
        product_id = request.form.get("id")

        # Get the product id from submit button(Add to cart button) on the products_listing page end

        cart_products_dict = {}

        # Open the db that stores all the products from products list page/createproducts from employees
        cur = mysql.connection.cursor()
        cur.execute('select * from product_inventory')
        data = cur.fetchall()
        products_dict = {}
        for row in data:
            product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
            product_item.set_id(row[0])
            product_item.set_url(row[7])
            products_dict[row[0]] = product_item

        # Open the db that stores all the products from products list page/createproducts from employees end

        # Check if the product id is stored in the session. if it is not, it adds the product id to the session as well as the data (type, quantity, etc)
        if product_id not in session["cart_products"]:


            intproduct_id = int(product_id)
            cart_products_dict[product_id] = products_dict[intproduct_id].__dict__

        # check if key "cart_products" in session. if not inside, initialize the session to a dict."
            if "cart_products" not in session:
                session["cart_products"] = {}
            session["cart_products"].update(cart_products_dict)
            session.permanent = True
            session.modified = True
            if "cart_products" in session:
                cart_session = session["cart_products"]
            print(cart_session)

        if "cart_products" in session:
            cart_session = session["cart_products"]

         # cart_quantity stores the quantity that is selected by user in the cartproducts page.
        # (Example, customer wants to buy 10 of product1. quantity of 10 with key of product 1 will be stored in cart quantity)
        cart_quantity_dict = {}
        # check if key "cart_quantity" in session. if not inside, initialize the session to a dict."
        if "cart_quantity" not in session:
            session["cart_quantity"] = {}
        if "cart_quantity" in session:
            cart_quantity_dict = session["cart_quantity"]

        # check if product (key ) in cart_session can be found in cart_quantity_dict. if product cannot be found, enter the details into cart_quantity_dict.
        # Without this line of code, if cart_quantity_dict is empty, there will be an error generated because the html cannot find the key since the dictionary has nothing.
        # So this ensures theres default values stored in the cart_quantity_dict
        for key in cart_session:
            if key not in cart_quantity_dict:
                cart_items = Products.Cart(1, key)
                cart_quantity_dict[key] = cart_items.__dict__

        cur.close()
        return redirect(url_for('cart_Products'))


# This route, when customer adds a product, they will be directed here, with the product in the cart.
@app.route('/cartProducts', methods=['GET','POST'])
@login_required
def cart_Products():
    # if not current_user.is_authenticated:
    #     return redirect(url_for('login'))
    email = current_user.get_email()
    # Open the db that stores all the products from products list page/createproducts from employees

    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item



    # Open the db that stores all the products from products list page/createproducts from employees ends
    cart_session = {}
    if "cart_products" not in session:
        session["cart_products"] = cart_session
    if "cart_products" in session:
        cart_session = session["cart_products"]


    cart_qauntity_session = {}
    if "cart_quantity" not in session:
        session["cart_quantity"] = cart_qauntity_session
    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]
    
    print(cart_session)
    print(cart_quantity_session)

    







    # try:
    #     form = UpdateAccountForm()
    #     if form.validate_on_submit():
    #         current_user.email = form.email.data
    #         print(current_user.email)
    #     elif request.method == 'GET':
    #         form.email.data = current_user.email
    #         print(form.email.data)
    # except:
    #     print('error')

    # cart_session_keys = []
    # try:
    #     for key in cart_session:
    #         if form.email.data in cart_session:
    #             print(key)
    #         else:
    #             cart_session_keys.append(form.email.data)
    #             print('no')
    # except:
    #     print('error')

    # try:
    #     cart_session = {cart_session_keys[0]:cart_session}
    #     cart_quantity_session = {cart_session_keys[0]:cart_quantity_session}
    # except:
    #     pass

    # session["cart_products"] = cart_session
    # session["cart_quantity"] = cart_quantity_session


    print(cart_quantity_session)




    # checks whether the product in "cart_products" session has the same quantity as the quantity of the product in products_dict.
    # There is a possiblity when customer checks out and buys the item and the quantity of the product decreases in products_dict but does not decrease the quantity of the session.
    # Because of this, it will mess up the max a customer can select of a product because the quantity does not decrease.
    for key in products_dict:
        if str(key) in session["cart_products"]:
            if session["cart_products"][str(key)]['_Products__quantity'] !=  products_dict[key].get_quantity():
                session["cart_products"][str(key)]['_Products__quantity'] = products_dict[key].get_quantity()
                session["cart_quantity"][str(key)]['_Cart__cart_quantity'] = 1

    # This checks if product in products_dict is in "cart_products"
    # After that, it checks if the product in the databse has  a quantity of 0. if it does have a quantity of 0, remove the item from the cart as the customer should not be able to checkout an item with no quantity  (out of stock)
        if str(key) in session["cart_products"]:
            if products_dict[key].get_quantity() <= 0:
                session["cart_quantity"].pop(str(key))
                session["cart_products"].pop(str(key))

    if "cart_products" in session:
        cart_session = session["cart_products"]
    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]


    # stripe_products_dict = {}

    # db_stripe = shelve.open('stripeproducts.db', 'c')
    # try:
    #     if 'stripeProducts' in db_stripe:
    #         stripe_products_dict = db_stripe['stripeProducts']
    #     else:
    #         db_stripe['stripeProducts'] = stripe_products_dict
    # except:
    #     print('Error in retrieving products from products.db.')


    cur.close()


    cards_dict = {}
    cur = mysql.connection.cursor()
    query = ("SELECT * FROM stripe_customer_card WHERE email = %s")
    params = (email,)
    cur.execute(query, params)
    data = cur.fetchall()
    for item in data:
        cards_dict.update({item[0]: {
            'email': item[1],
            'last_4': item[6],
            'cus_id': item[7]
    }})
    print(cards_dict)
    query = ("SELECT * FROM stripe_customer_address where email = %s")
    params = (email,)
    cur.execute(query, params)
    address_data = cur.fetchall()
    cur.close()

    address_dict = {}
    for item in address_data:
        address_dict.update({
            item[0]: {
                'email': item[1],
                'name': item[2],
                'phone': item[3],
                'line1': item[4],
                'line2': item[5],
                'city': item[6],
                'country': item[7],
                'pos_code': item[8],
                'state': item[9],
            }
        })



    return render_template('cartProducts.html', cart_session=cart_session, cart_quantity_session = cart_quantity_session, address_dict = address_dict, cards_dict = cards_dict)



# might not need this route anymore
@app.route('/cartQuantity', methods=['GET','POST'])
def cart_quantity():

    cart_quantity_session = {}
    if request.method == 'POST':
        if "cart_products" in session:
            cart_session = session["cart_products"]
        cart_quantity_dict = {}
        quantity = request.form.getlist("quantity")
        product_id = request.form.getlist("key")

        for item_id, item_quantity in zip(product_id, quantity):
            cart_items = Products.Cart(item_quantity, item_id)
            cart_quantity_dict[cart_items.get_cart_id()] = cart_items.__dict__

        if "cart_quantity" not in session:
            session["cart_quantity"] = {}

        session["cart_quantity"] = cart_quantity_dict
        # session["cart_quantity"].update(cart_quantity_dict)
        session.permanent = True
        session.modified = True
        if "cart_quantity" in session:
            cart_quantity_session = session["cart_quantity"]
    return cart_quantity_session

@app.route('/cart-checkout', methods=['GET','POST'])
@login_required
def cart_checkout():
    email = current_user.get_email()
    order_reference = ''

    if "cart_products" not in session:
        session["cart_products"] = {}
    if "cart_quantity" not in session:
        session["cart_quantity"] = {}

    if "cart_products" in session:
        cart_session = session["cart_products"]

    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]
    
    if cart_session == {}:
        return redirect(url_for('cart_Products'))
    remove_id = request.form.get("remove_id")
    if remove_id != None:
        if remove_id in session["cart_products"]:
            session["cart_products"].pop(remove_id)
            if "cart_products" in session:
                cart_session = session["cart_products"]

        if "cart_quantity" not in session:
            session["cart_quantity"] = {}

        if remove_id in session["cart_quantity"]:
            session["cart_quantity"].pop(remove_id)
            if "cart_quantity" in session:
                cart_quantity_session = session["cart_quantity"]


        return redirect(url_for('cart_Products'))
    
    if "cart_products" in session:
        cart_session = session["cart_products"]

    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]
    
    if request.method == 'POST':
        quantity = request.form.getlist("quantity")
        product_id = request.form.getlist("key")
        if quantity and product_id != '':
            if "cart_products" in session:
                cart_session = session["cart_products"]
            cart_quantity_dict = {}

            for item_id, item_quantity in zip(product_id, quantity):
                cart_items = Products.Cart(item_quantity, item_id)
                cart_quantity_dict[cart_items.get_cart_id()] = cart_items.__dict__

            if "cart_quantity" not in session:
                session["cart_quantity"] = {}

            session["cart_quantity"] = cart_quantity_dict
            # session["cart_quantity"].update(cart_quantity_dict)
            session.permanent = True
            session.modified = True
            if "cart_quantity" in session:
                cart_quantity_session = session["cart_quantity"]
    total_amount = 0
    for key, product in cart_session.items():
        total_amount += int(cart_quantity_session[key]['_Cart__cart_quantity']) * cart_session[key]['_Products__price']
    total_amount += 5
    
    cards_dict = {}
    cur = mysql.connection.cursor()

    query = ("SELECT * FROM stripe_customer_card WHERE email = %s")
    params = (email,)
    cur.execute(query, params)
    data = cur.fetchall()
    for item in data:
        cards_dict.update({item[0]: {
            'email': item[1],
            'last_4': item[6],
            'cus_id': item[7]
    }})
    print(cards_dict)
    query = ("SELECT * FROM stripe_customer_address where email = %s")
    params = (email,)
    cur.execute(query, params)
    address_data = cur.fetchall()
    cur.close()

    address_dict = {}
    for item in address_data:
        address_dict.update({
            item[0]: {
                'email': item[1],
                'name': item[2],
                'phone': item[3],
                'line1': item[4],
                'line2': item[5],
                'city': item[6],
                'country': item[7],
                'pos_code': item[8],
                'state': item[9],
            }
        })
    selected_address = ''

    selected_card = ''

    if 'selected_card' not in session:
        session['selected_card'] = ''

    else:
        selected_card = session['selected_card']


    selected_card_form_value = request.form.get('card_option')
    if selected_card_form_value != None:
        if selected_card == '':
            selected_card = selected_card_form_value
        else:
            if selected_card != selected_card_form_value:
                selected_card = selected_card_form_value
    session['selected_card'] = selected_card
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    
    return render_template('cartCheckout.html', cards_dict = cards_dict, selected_card = selected_card, address_dict = address_dict, selected_address = selected_address, cart_session = cart_session, cart_quantity_session = cart_quantity_session, email = email, total_amount = total_amount, csrf_token = csrf_token)

@app.route('/otp-checkout', methods=['GET','POST'])
@login_required
def otp_checkout():
    session['otp_secret_checkout'] = ''
    email = current_user.get_email()
    if request.method=='POST':
        csrf_token = session.get('csrf_token')
        print(csrf_token)
        if not csrf_token or request.form.get('csrf_token') != csrf_token:
            return 'Bad Request'
        else:
            if request.form.get("submit") == 'Submit':
                if session['otp_secret_checkout'] == '':
                    otp_secret = pyotp.random_base32()
                    def generate_otp():  # Define the function with the parameter ‘length’
                        totp = pyotp.TOTP(otp_secret, interval=600)
                        return totp.now()

                    otp = generate_otp()
                    session['otp_secret_checkout'] = otp
                    email_recipient = [email]
                    email_subject = 'Checkout OTP'
                    email_body = f"Here is the OTP(One Time Password): {otp}. It will expire in 600seconds"
                    sender = 'renewifysg@gmail.com'
                    send_email(email_subject, email_body, sender, email_recipient)
                else:
                    otp = session['otp_secret_checkout']

                otp_form = OtpForm(request.form)
                print(otp)
                key = request.form.get('key')
                quantity = request.form.get('quantity')
                selected_card = request.form.get('card_option')
                selected_address = request.form.get('address_option')
            
            return render_template('otp_checkout.html', key=key, quantity=quantity, selected_card=selected_card, selected_address=selected_address, form = otp_form, otp_secret = otp)
    else:
        return redirect(url_for('cart_checkout'))




#     return render_template('cartCheckout.html', cart_quantity_session = cart_quantity_session, cart_session=cart_session)

# @app.route('/displayProduct', methods=['GET','POST'])
# def display_product():
#     db_cart = shelve.open('cart_products.db', 'c')
#     cart_products_dict = {}
#     try:
#         if 'cart_products' in db_cart:
#             cart_products_dict = db_cart['cart_products']
#         else:
#             db_cart['cart_products'] = cart_products_dict
#     except:
#         print('Error in retrieving products from cart_products.db.')
#     cart_products_list = []
#     for key in cart_products_dict:
#         cart_products = cart_products_dict.get(key)
#         cart_products_list.append(cart_products)

#     return render_template('products_list.html', cart_products_list = cart_products_list)


@app.route('/createProducts', methods=['GET', 'POST'])
def create_products():
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    create_products_form = CreateProductsForm(request.form)
    duplicate_name = ''
    check_for_banned_ips()


    
    if request.method == 'POST':
        # if request.content_length > 1 * 1024 * 1024:
        #     flash('File size exceeds the maximum limit of 2 MB')
        #     return redirect(url_for('create_products'))
        # try:
        create_products_form.product_image.data = request.files['product_image']
        # except:
        #     flash('File size exceeds the maximum limit of 2 MB')
        #     return redirect(url_for('create_products'))
            

        if create_products_form.validate():
            csrf_token = session.get('csrf_token')
            if not csrf_token or request.form.get('csrf_token') != csrf_token:
                return 'Bad Request'
            else:
                duplicate_name = ''
                #! drop table check
                if 'DROP TABLE' in create_products_form.product_name.data.upper():
                    ip = request.remote_addr
                    cur = mysql.connection.cursor()
                    query = ('insert into banned_ips (ip) values (%s)')
                    params = (ip,)
                    cur.execute(query,params)
                    mysql.connection.commit()
                    db_logger_adapter.critical(f'Critical security alert! Attempt to drop database detected from IP: {ip}')
                    for num in staff_numbers:
                        message = client.messages.create(
                                from_='whatsapp:+14155238886',
                                body=f'Critical security alert! Attempt to drop database detected from IP: {ip}',
                                to='whatsapp:+65' + num
                                )
                        print(message.sid)
                    raise Forbidden("Your IP has been blocked due to malicious activity.")

                # products_dict = {}
                # db = shelve.open('products.db', 'c')

                # try:
                #     products_dict = db['Products']

                # except:
                #     print('Error in retrieving products from products.db.')
                # sql:
                cur = mysql.connection.cursor()
                cur.execute('select * from product_inventory')
                data = cur.fetchall()
                products_dict = {}
                for row in data:
                    product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
                    product_item.set_id(row[0])
                    products_dict[row[0]] = product_item


                for key in products_dict:
                    if create_products_form.product_name.data.capitalize() == products_dict[key].get_name():
                        duplicate_name = products_dict[key].get_name()
                if duplicate_name:
                    create_products_form = CreateProductsForm()
                    return render_template('createProducts.html' ,duplicate_name =duplicate_name, form=create_products_form, csrf_token = csrf_token)
                
                # checking the file uploaded with virustotal
                # 92afacac69a7cbeb2ca0de2dc200dcb926a293a97911d8260e63d22d5fb264ed
                api_key = VIRUSTOTAL_API_KEY_2
                file = request.files['product_image']
                if file:
                    scan_result = scan_file_with_virustotal(file,file.stream, api_key)
                if scan_result['status'] == 'Safe':
                    print("File is safe and has been stored.")
                    print(scan_result['path'])

                    product = Products.Products(create_products_form.product_name.data.capitalize(), create_products_form.product_price.data, create_products_form.product_quantity.data, create_products_form.product_country.data.capitalize(), create_products_form.product_type.data.capitalize(), create_products_form.product_dietary.data.capitalize())

                    product.set_type(product.get_type().replace(' ','_'))
                    product.set_url(f'{scan_result["path"]}')
                    product.set_id(len(products_dict) + 1)
                    products_dict[product.get_id()] = product
                    print(product.get_id())
                    # Insert new record
                    query = ('insert into product_inventory (product_id, product_name, product_price, product_quantity, product_country, product_type, product_dietary, product_url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)')
                    params = (product.get_id(), product.get_name(), product.get_price(), product.get_quantity(), product.get_country(), product.get_type(), product.get_dietary(), product.get_url())
                    cur.execute(query,params)
                    db_logger_adapter.info(f"Status: Safe | Results {scan_result['results']} | Product ID: ({product.get_id()}) | has been scanned and is safe and has been created and added to product_inventory database")
                    mysql.connection.commit()
                    cur.close()


                    return redirect(url_for('retrieve_products'))
                else:
                    print("File is potentially malicious or couldn't be scanned, and was not stored.")
                    db_logger_adapter.critical(f"Status: Potentially Malicious | Results {scan_result['results']} | Product Image has been identified as malicious and {create_products_form.product_name.data} has not been added to the product_inventory database")
                    for num in staff_numbers:
                        message = client.messages.create(
                                from_='whatsapp:+14155238886',
                                body=f"Status: Potentially Malicious | Results {scan_result['results']} | Product Image has been identified as malicious and {create_products_form.product_name.data} has not been added to the product_inventory database",
                                to='whatsapp:+65' + num
                                )
                    malicious = True


                    print(message.sid)
                    return render_template('createProducts.html', form=create_products_form, duplicate_name = duplicate_name, malicious = malicious, csrf_token = csrf_token)
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('createProducts.html', form=create_products_form, duplicate_name = duplicate_name, csrf_token= csrf_token)



@app.route('/retrieveProducts', methods=['GET', 'POST'])
def retrieve_products():
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    search_form = SearchForm(request.form)
    check_for_banned_ips()



    # attempt to extract and put into sql
    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item
    cur.close()
    # for item in sql_products_dict:
    #     sql_id = sql_products_dict[item].get_id()
    #     if sql_id not in existing_product_ids:
    #         sql_name = sql_products_dict[item].get_name()
    #         sql_price = sql_products_dict[item].get_price()
    #         sql_quantity = sql_products_dict[item].get_quantity()
    #         sql_country = sql_products_dict[item].get_country()
    #         sql_type = sql_products_dict[item].get_type()
    #         sql_dietary = sql_products_dict[item].get_dietary()
    #         sql_url = sql_products_dict[item].get_url()
    #         cur.execute('insert into product_inventory (product_id, product_name, product_price, product_quantity, product_country, product_type, product_dietary, product_url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
    #                     (sql_id, sql_name, sql_price, sql_quantity, sql_country, sql_type, sql_dietary, sql_url))
    #     else:
    #         continue
    # mysql.connection.commit()



    # db_stripe = shelve.open('stripeproducts.db', 'c')
    # try:
    #     if 'stripeProducts' in db_stripe:
    #         stripe_products_dict = db_stripe['stripeProducts']
    #     else:
    #         db_stripe['stripeProducts'] = stripe_products_dict
    # except:
    #     print('Error in retrieving products from products.db.')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select data from stripe_products')
    data = cur.fetchall()

    stripe_products_dict = {}
    for item in data:
        json_data = item['data']
        stripe_products_data = json.loads(json_data)  # Convert JSON string to dictionary
        stripe_products_dict = stripe_products_data
    cur.close()
    stripe_products_dict = {int(key): value for key, value in stripe_products_dict.items()}
    print(stripe_products_dict)




    # Stripe products creation
    for key in products_dict:
        if key not in stripe_products_dict:
            product_id = products_dict[key].get_id()
            product_name = products_dict[key].get_name()
            product_price_cents = products_dict[key].get_price()
            product_price_dollars = int(product_price_cents * 100)
            product_image_url = products_dict[key].get_url()
            # Example: Creating a product with the Stripe API
            product = stripe.Product.create(
                name = product_name,
                type='service',
                # Add more details like description, images, etc.
            )

            price = stripe.Price.create(
                currency = "sgd",
                unit_amount = product_price_dollars,
                product = product.id,
            )

            product_dict = product.to_dict()
            price_dict = price.to_dict()
            stripe_products_dict[product_id] = {'product': product_dict, 'price': price_dict}
        else:
            continue
    remove_keys = []
    for key in stripe_products_dict:
        if key not in products_dict:
            remove_keys.append(key)
    for key in remove_keys:
        stripe_products_dict.pop(key)
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select id from stripe_products')
    data = cur.fetchall()
    existing_ids = [row['id'] for row in data]
    for item_id in stripe_products_dict:

        try:
            json_data = json.dumps(stripe_products_dict)
            if item_id in existing_ids:
                query = ('update stripe_products set id = %s, data = %s')
                params = (item_id, json_data)
                cur.execute(query, params)
            else:
                query = ('insert into stripe_products (id, data) values (%s, %s)')
                params = (item_id, json_data)
                cur.execute(query, params)
        except:
            print('error')
    print(stripe_products_dict)
    mysql.connection.commit()
    cur.close()

    # db_stripe['stripeProducts'] = stripe_products_dict

    # Stripe products creation ends
    if "cart_products" not in session:
        session["cart_products"] = {}

    if "cart_quantity" not in session:
        session["cart_quantity"] = {}

    for key in products_dict:
        index = list(products_dict).index(key)
        for item in list(session["cart_products"]):
            if int(item) not in products_dict:
                session["cart_products"].pop(item)

        for item in list(session["cart_quantity"]):
            if int(item) not in products_dict:
                session["cart_quantity"].pop(item)

    cur = mysql.connection.cursor()
    for key in products_dict:
        products_dict[key].set_id(key)
        products_dict[key].set_url(f'{products_dict[key].get_url()}')
    for key in products_dict:
        query = ("SELECT * FROM product_inventory WHERE product_id = %s")
        params = (products_dict[key].get_id(),)
        cur.execute(query, params)
        existing_product = cur.fetchone()
        if existing_product:
            # Update existing record
            query = ("UPDATE product_inventory SET product_name = %s, product_price = %s, product_quantity = %s, product_country = %s, product_type = %s, product_dietary = %s, product_url = %s WHERE product_id = %s")
            params = (products_dict[key].get_name(), products_dict[key].get_price(), products_dict[key].get_quantity(), products_dict[key].get_country(), products_dict[key].get_type(), products_dict[key].get_dietary(), products_dict[key].get_url(), products_dict[key].get_id())
            cur.execute(query, params)
        else:
            # Insert new record
            query = ('insert into product_inventory (product_id, product_name, product_price, product_quantity, product_country, product_type, product_dietary, product_url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)')
            params = (products_dict[key].get_id(), products_dict[key].get_name(), products_dict[key].get_price(), products_dict[key].get_quantity(), products_dict[key].get_country(), products_dict[key].get_type(), products_dict[key].get_dietary(), products_dict[key].get_url())
            cur.execute(query, params)
    mysql.connection.commit()
    cur.close()

    enumerated_dict = products_dict
    for key in products_dict:
        index = list(products_dict).index(key)
        if index != key:
            enumerated_dict = {index: products_dict[key_inner] for index, key_inner in enumerate(products_dict, start=1)}


    products_list = []
    for key in products_dict:
        product = products_dict.get(key)
        products_list.append(product)

    if "cart_products" in session:
        cart_session = session["cart_products"]



    # for key in products_dict:
    #     index = list(products_dict).index(key)
    #     for item in list(session["cart_products"]):
    #         if int(item) not in products_dict:
    #             session["cart_products"].pop(item)

    #     for item in list(session["cart_quantity"]):
    #         if int(item) not in products_dict:
    #             session["cart_quantity"].pop(item)


    # for key in products_dict:
    #     products_dict[key].set_id(key)
    #     products_dict[key].set_url(f'Images/{products_dict[key].get_name().replace(" ","_").replace("/","_").lower()}.jpg')
    # db['Products'] = products_dict


    # enumerated_dict = products_dict
    # for key in products_dict:
    #     index = list(products_dict).index(key)
    #     if index != key:
    #         enumerated_dict = {index: products_dict[key_inner] for index, key_inner in enumerate(products_dict, start=1)}


    # products_list = []
    # for key in products_dict:
    #     product = products_dict.get(key)
    #     products_list.append(product)

    # if "cart_products" in session:
    #     cart_session = session["cart_products"]

    # # attempt to use sql database instead of shelve.
    # products_dict_test = {}
    # for row in data:
    #     product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
    #     product_item.set_id(row[0])
    #     products_dict_test[row[0]] = product_item

    # for key in products_dict_test:
    #     index = list(products_dict_test).index(key)
    #     for item in list(session["cart_products"]):
    #         if int(item) not in products_dict_test:
    #             session["cart_products"].pop(item)

    #     for item in list(session["cart_quantity"]):
    #         if int(item) not in products_dict_test:
    #             session["cart_quantity"].pop(item)


    # for key in products_dict_test:
    #     products_dict_test[key].set_id(key)
    #     products_dict_test[key].set_url(f'Images/{products_dict_test[key].get_name().replace(" ","_").replace("/","_").lower()}.jpg')
    # db['Products'] = products_dict_test


    # enumerated_dict = products_dict_test
    # for key in products_dict_test:
    #     index = list(products_dict_test).index(key)
    #     if index != key:
    #         enumerated_dict = {index: products_dict_test[key_inner] for index, key_inner in enumerate(products_dict_test, start=1)}


    # products_list = []
    # for key in products_dict_test:
    #     product = products_dict_test.get(key)
    #     products_list.append(product)

    # product_id_list = []
    # for row in data:
    #     product_id_list.append(row[0])

    # for item in list(session["cart_products"]):
    #     if int(item) not in product_id_list:
    #         session["cart_products"].pop(item)


    #     for item in list(session["cart_quantity"]):
    #         if int(item) not in product_id_list:
    #             session["cart_quantity"].pop(item)




    # for key in products_dict:
    #     products_dict[key].set_id(key)
    #     products_dict[key].set_url(f'Images/{products_dict[key].get_name().replace(" ","_").replace("/","_").lower()}.jpg')
    #     print(row[0].get_id())
    # db['Products'] = products_dict


    # enumerated_dict = products_dict
    # for key in products_dict:
    #     index = list(products_dict).index(key)
    #     if index != key:
    #         enumerated_dict = {index: products_dict[key_inner] for index, key_inner in enumerate(products_dict, start=1)}


    # products_list = []
    # for key in products_dict:
    #     product = products_dict.get(key)
    #     products_list.append(product)




    cur.close()



    # Create a Pagination object



    return render_template('retrieveProducts.html', form=search_form, count=len(products_list), products_list=products_list)


@app.route('/updateProducts/<int:id>/', methods=['GET', 'POST'])
def update_products(id):
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    update_products_form = CreateProductsForm(request.form)
    duplicate_name = ''

    cur = mysql.connection.cursor()
    cur.execute('select * from product_inventory')
    data = cur.fetchall()
    products_dict = {}
    for row in data:
        product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
        product_item.set_id(row[0])
        product_item.set_url(row[7])
        products_dict[row[0]] = product_item
    if request.method == 'POST':
        update_products_form.product_image.data = request.files['product_image']
        if update_products_form.validate():
            csrf_token = session.get('csrf_token')
            if not csrf_token or request.form.get('csrf_token') != csrf_token:
                return 'Bad Request'
            else:
                file = update_products_form.product_image.data
                api_key = VIRUSTOTAL_API_KEY_2
                filename = secure_filename(file.filename)
                duplicate_name = ''
                for key, product in products_dict.items():
                    if (update_products_form.product_name.data.capitalize() == product.get_name() and key != id):
                        duplicate_name = update_products_form.product_name.data.capitalize()
                        break
                    else:
                        print('not inside')
                if duplicate_name:
                    cur.close()
                    return render_template('createProducts.html' ,duplicate_name = duplicate_name, form=update_products_form, csrf_token=csrf_token)

                product = products_dict.get(id)
                product.set_name(update_products_form.product_name.data.capitalize())
                product.set_country(update_products_form.product_country.data)
                product.set_type(update_products_form.product_type.data)
                product.set_type(product.get_type().replace(' ','_').capitalize())
                product.set_dietary(update_products_form.product_dietary.data)
                product.set_price(update_products_form.product_price.data)
                product.set_quantity(update_products_form.product_quantity.data)
                if filename != '':
                    scan_result = scan_file_with_virustotal(file,file.stream, api_key)
                    if scan_result['status'] == 'Safe':
                        print("File is safe and has been stored.")
                        print(scan_result['path'])
                        product.set_url(scan_result['path'])
                    else:
                        for num in staff_numbers:
                            message = client.messages.create(
                                    from_='whatsapp:+14155238886',
                                    body=f"Status: Potentially Malicious | Results {scan_result['results']} | Product Image has been identified as malicious and {update_products_form.product_name.data} has not been added to the product_inventory database",
                                    to='whatsapp:+65' + num
                                    )
                        print(message.sid)
                        product.set_url(None)
                        query = 'SELECT * FROM product_inventory WHERE product_id = %s'
                        params = (product.get_id(),)
                        cur.execute(query, params)
                        existing_product = cur.fetchone()
                        print(existing_product[0])
                        for key in products_dict:
                            if key == existing_product[0]:
                                # Update existing record
                                query = 'UPDATE product_inventory SET product_name = %s, product_price = %s, product_quantity = %s, product_country = %s, product_type = %s, product_dietary = %s, product_url = %s WHERE product_id = %s'
                                params = (products_dict[key].get_name(), products_dict[key].get_price(), products_dict[key].get_quantity(), products_dict[key].get_country(), products_dict[key].get_type(), products_dict[key].get_dietary(), products_dict[key].get_url(), products_dict[key].get_id())
                                cur.execute(query, params)
                                break
                        db_logger_adapter.critical(f"Status: Potentially Malicious | Results {scan_result['results']} | Product Image has been identified as malicious and {update_products_form.product_name.data} has not been added to the product_inventory database")                                
                        mysql.connection.commit()
                        cur.close()
                        return redirect(url_for('retrieve_products'))
            
                query = 'SELECT * FROM product_inventory WHERE product_id = %s'
                params = (product.get_id(),)
                cur.execute(query, params)
                existing_product = cur.fetchone()
                print(existing_product[0])
                for key in products_dict:
                    if key == existing_product[0]:
                        # Update existing record
                        query = 'UPDATE product_inventory SET product_name = %s, product_price = %s, product_quantity = %s, product_country = %s, product_type = %s, product_dietary = %s, product_url = %s WHERE product_id = %s'
                        params = (products_dict[key].get_name(), products_dict[key].get_price(), products_dict[key].get_quantity(), products_dict[key].get_country(), products_dict[key].get_type(), products_dict[key].get_dietary(), products_dict[key].get_url(), products_dict[key].get_id())
                        cur.execute(query, params)
                        db_logger_adapter.info(f"Status: Safe | Results {scan_result['results']} | Product ID: ({product.get_id()}) | has been updated in the product_inventory database")
                        break
                mysql.connection.commit()
                cur.close()
                return redirect(url_for('retrieve_products'))
        else:
            product = products_dict.get(id)
            update_products_form.product_name.data = product.get_name()
            update_products_form.product_country.data = product.get_country()
            update_products_form.product_type.data = product.get_type()
            update_products_form.product_dietary.data = product.get_dietary()
            update_products_form.product_price.data = product.get_price()
            update_products_form.product_quantity.data = product.get_quantity()
            update_products_form.product_url.data = product.get_url()
            cur.close()
            csrf_token = generate_csrf_token()
            session['csrf_token'] = csrf_token
            return render_template('updateProducts.html', form=update_products_form, duplicate_name = duplicate_name,csrf_token=csrf_token)
    else:
        product = products_dict.get(id)
        update_products_form.product_name.data = product.get_name()
        update_products_form.product_country.data = product.get_country()
        update_products_form.product_type.data = product.get_type()
        update_products_form.product_dietary.data = product.get_dietary()
        update_products_form.product_price.data = product.get_price()
        update_products_form.product_quantity.data = product.get_quantity()
        update_products_form.product_url.data = product.get_url()
        cur.close()
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('updateProducts.html', form=update_products_form, duplicate_name = duplicate_name, csrf_token=csrf_token, id=id)



@app.route('/deleteProducts/<int:id>', methods=['GET','POST'])
def delete_products(id):
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    cur = mysql.connection.cursor()
    try:
        query = 'select * from product_inventory'
        cur.execute(query)
        data = cur.fetchall()
        products_dict = {}
        for row in data:
            product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
            product_item.set_id(row[0])
            product_item.set_url(row[7])
            products_dict[row[0]] = product_item
        for key in products_dict:
            if key == id:
                db_logger_adapter.info(f"Product ID: ({id}) has been deleted from product_inventory database")
                query = 'DELETE FROM product_inventory WHERE product_id = %s'
                params = (id,)
                cur.execute(query,params)
        
        #! SIMULATING AN ERROR uncomment to simulate an error:
        # ids = 9999
        # if ids not in products_dict:
        #     db_logger_adapter.warning(f"Attempted to delete non-existent Product ID: ({ids})")
        #! SIMULATING AN ERROR uncomment to simulate an error:

        mysql.connection.commit()
    except Exception as e:
        db_logger_adapter.error(f'Error occurred while deleting Product ID: ({id}) | Error: {str(e)}')
        mysql.connection.rollback()
    finally:
        cur.close()
    return redirect(url_for('retrieve_products'))



@app.route('/Base')
def base():
    return render_template('base.html')


YOUR_DOMAIN = 'https://localhost:3306'




@app.route('/test')
def testing():
    remove_id = request.args.get("remove_id")

    if remove_id != None:
        if remove_id in session["cart_products"]:
            session["cart_products"].pop(remove_id)
            if "cart_products" in session:
                cart_session = session["cart_products"]

        if "cart_quantity" not in session:
            session["cart_quantity"] = {}

        if remove_id in session["cart_quantity"]:
            session["cart_quantity"].pop(remove_id)
            if "cart_quantity" in session:
                cart_quantity_session = session["cart_quantity"]


        return redirect(url_for('cart_Products'))
    
    cart_quantity_session = {}
    if request.method == 'GET':
        if "cart_products" in session:
            cart_session = session["cart_products"]
        cart_quantity_dict = {}
        quantity = request.args.getlist("quantity")
        product_id = request.args.getlist("key")

        for item_id, item_quantity in zip(product_id, quantity):
            cart_items = Products.Cart(item_quantity, item_id)
            cart_quantity_dict[cart_items.get_cart_id()] = cart_items.__dict__

        if "cart_quantity" not in session:
            session["cart_quantity"] = {}

        session["cart_quantity"] = cart_quantity_dict
        # session["cart_quantity"].update(cart_quantity_dict)
        session.permanent = True
        session.modified = True
        if "cart_quantity" in session:
            cart_quantity_session = session["cart_quantity"]

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM stripe_customer_card")
    data = cur.fetchall()
    for row in data:
        customer_id = row[7]

    return render_template('checkout.html')


@app.route('/return_test')
def return_tests():
    return render_template('return.html')

# @app.route('/create-payment-intent', methods=['POST'])
# def create_payment_intent():
#     print('dwad')
#     data = request.json
#     payment_method_id = data.get('payment_method_id')
#     print(payment_method_id)
    
#     # Create a PaymentIntent with the order amount and currency
#     payment_intent = stripe.PaymentIntent.create(
#         amount=1000,  # Amount in cents
#         currency='usd',
#         payment_method=payment_method_id,
#         confirmation_method='manual',
#         confirm=True,
#         return_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
#     )
#     print(payment_intent)
#     return jsonify(client_secret=payment_intent.client_secret)

# NEW STRIPE
@app.route('/create-address', methods=['POST','GET'])
@login_required
def create_address():
    email = current_user.get_email()

    if request.method == 'POST':
        request_data = request.form.get('address')
        data = json.loads(request_data)
        address = data['address']
        print(address)
        cur = mysql.connection.cursor()
        query = 'SELECT * FROM stripe_customer_address WHERE email = %s and pos_code = %s'
        params = (email, address['postal_code'])
        cur.execute(query, params)
        existing_entry = cur.fetchone()
        if existing_entry:
            print('email and card already exist')
        else:
            if address['city'] == '' and address['state'] == '':
                address['city'] = 'Singapore'
                address['state'] = 'Singapore'
            print(address['city'])
            query = 'insert into stripe_customer_address (email, name, phone, line1, line2, city, country, pos_code, state) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)'
            params = (email, data['name'], data['phone'], address['line1'], address['line2'], address['city'], address['country'], address['postal_code'], address['state'])
            cur.execute(query, params)
            mysql.connection.commit()
            customer_info_adapter.info(f'Email: {email} | Has created a new address.')
            print('new token/card added')

        cur.close()
        print(data)
    return render_template('create_address.html')

# Functions


# Example usage
# * Encrypting and decrypting card details
def generate_aes_key():
    return get_random_bytes(32)

def encrypt_card_func(data):
    key = generate_aes_key()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    encrypted_card_details_dict = {'iv': iv, 'ciphertext': ct}
    encrypted_secret_key_dict = encrypt_secret_key(key)
    return {'encrypted_card_details_dict' : encrypted_card_details_dict, 'encrypted_secret_key_dict' : encrypted_secret_key_dict}

def decrypt_card_func(encrypted_card_details, encrypted_secret_key):
    try:
        b64 = encrypted_card_details
        key = decrypt_secret_key(encrypted_secret_key)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")

# Encrypting & decrypting the secret key used to encrypt card
def encrypt_secret_key(secret_key):
    master_key = decrypt_master_key_file()
    cipher = AES.new(master_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(secret_key, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    encrypted_secret_key_dict = {'iv': iv, 'ciphertext': ct}
    return encrypted_secret_key_dict

def decrypt_secret_key(encrypted_secret_key_dict):
    try:
        master_key = decrypt_master_key_file()
        b64 = encrypted_secret_key_dict
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(master_key, AES.MODE_CBC, iv)
        decrypted_key = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", decrypted_key)
        return decrypted_key
    except (ValueError, KeyError):
        print("Incorrect decryption")

def decrypt_master_key_file():
    # opening the key
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    # using the generated key
    fernet = Fernet(key)
    with open('nothing.key', 'rb') as ef:
        encrypted_file_master_key_file = ef.read()

    original_master_key_file = fernet.decrypt(encrypted_file_master_key_file)
    return original_master_key_file


@app.route('/create-card', methods=['POST','GET'])
@login_required
def create_card():
    email = current_user.get_email()
    create_card_form = CreateCardForm()
    cur = mysql.connection.cursor()
    query = ('SELECT * FROM stripe_customer_card WHERE email = %s')
    params = email,
    cur.execute(query, params)
    data = cur.fetchall()
    existing_last_4 = []
    for item in data:
        existing_last_4.append(item[6])
    print(existing_last_4)
    cur.close()

    if request.method == 'POST':
        form = CreateCardForm(request.form)
        card_num = form.card_number.data
        exp_month = form.month.data
        exp_year = form.year.data
        last_4 = card_num[-4::]
        cvc = form.cvc.data
        card_details_str = f'{card_num}|{exp_month}|{exp_year}|{cvc}'
        card_details_bytes = bytes(card_details_str, encoding='utf-8')
        encrypted_card_details = encrypt_card_func(card_details_bytes)
        encrypted_card_details_iv = encrypted_card_details['encrypted_card_details_dict']['iv']
        encrypted_card_details_ct = encrypted_card_details['encrypted_card_details_dict']['ciphertext']
        encrypted_secret_key_iv = encrypted_card_details['encrypted_secret_key_dict']['iv']
        encrypted_secret_key_ct = encrypted_card_details['encrypted_secret_key_dict']['ciphertext']
    #     tokentest = stripe.Token.create(
    #     card={
    #         'number': str(card_num),
    #         'exp_month': exp_month,
    #         'exp_year': exp_year,
    #         'cvc': str(cvc),
    #     },
    # )
    #     print(tokentest)
        customer = stripe.Customer.create(
        # source = token,
        email=email,
    )

        cur = mysql.connection.cursor()
        query = ('SELECT * FROM stripe_customer_card WHERE email = %s and last_4 = %s')
        params = customer.email, last_4
        cur.execute(query, params)
        existing_entry = cur.fetchone()
        if existing_entry:
            print('email and card already exist')
            customer_info_adapter.warning(f'Email: {customer.email} | Last 4 Digits ({last_4}) Has tried to create a card that already exists.')
        else:
            query = ('insert into stripe_customer_card (email, card_details_iv, card_details_ct, secret_key_iv, secret_key_ct, last_4, cus_id) values (%s, %s, %s, %s, %s, %s, %s)')
            params = customer.email, encrypted_card_details_iv, encrypted_card_details_ct, encrypted_secret_key_iv, encrypted_secret_key_ct, last_4, customer.id
            cur.execute(query,params)
            mysql.connection.commit()
            customer_info_adapter.info(f'Email: {customer.email} | Last 4 Digits ({last_4}) Has created a new card.')
            print('new token/card added')
        
        cur.close()

        return render_template('create_card.html', existing_entry = existing_entry, method = request.method, form = create_card_form)
    return render_template('create_card.html', form = create_card_form, existing_last_4 = existing_last_4)



@app.route('/create-checkout-session', methods=['POST','GET'])
def create_checkout_session():

    # if request.method == 'POST':
    #     if "cart_products" in session:
    #         cart_session = session["cart_products"]
    #     cart_quantity_dict = {}
    #     quantity = request.form.getlist("quantity")
    #     product_id = request.form.getlist("key")
    #     for item_id, item_quantity in zip(product_id, quantity):
    #         cart_items = Products.Cart(item_quantity, item_id)
    #     cart_quantity_dict[cart_items.get_cart_id()] = cart_items.__dict__

    #     if "cart_quantity" not in session:
    #         session["cart_quantity"] = {}

    #     session["cart_quantity"] = cart_quantity_dict
    #     # session["cart_quantity"].update(cart_quantity_dict)
    #     session.permanent = True
    #     session.modified = True
    #     if "cart_quantity" in session:
    #         cart_quantity_session = session["cart_quantity"]

    #     print(cart_quantity_session)
    if "cart_products" not in session:
        session["cart_products"] = {}

    if "cart_products" in session:
        cart_session = session["cart_products"]

    if "cart_quantity" not in session:
        session["cart_quantity"] = {}
        
    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]
    stripe_products_dict = {}

    db = shelve.open('stripeproducts.db', 'c')
    try:
        if 'stripeProducts' in db:
            stripe_products_dict = db['stripeProducts']
        else:
            db['stripeProducts'] = stripe_products_dict
    except:
        print('Error in retrieving products from products.db.')
        

    print(cart_quantity_session)


    line_items = []
    metadata = {}
    images = {}
    for key in stripe_products_dict:
        if str(key) in cart_session:
            metadata[key] = cart_quantity_session[str(key)]['_Cart__cart_quantity']
            line_items.append({'price': stripe_products_dict[key]['price']['id'], 'quantity' : cart_quantity_session[str(key)]['_Cart__cart_quantity'], })
    try:
        checkout_session = stripe.checkout.Session.create(
            ui_mode = 'embedded',
            payment_intent_data = {
                "metadata": metadata
            },
            invoice_creation={"enabled": True},
            billing_address_collection='auto',
            shipping_address_collection={
              'allowed_countries': ['SG'],
            },
            shipping_options=[
                {
                "shipping_rate_data": {
                    "type": "fixed_amount",
                    "fixed_amount": {"amount": 0, "currency": "sgd"},
                    "display_name": "Free shipping",
                    "delivery_estimate": {
                    "minimum": {"unit": "business_day", "value": 5},
                    "maximum": {"unit": "business_day", "value": 7},
                    },
                },
                },
                {
                "shipping_rate_data": {
                    "type": "fixed_amount",
                    "fixed_amount": {"amount": 500, "currency": "sgd"},
                    "display_name": "Next Day Ground Shipping",
                    "delivery_estimate": {
                    "minimum": {"unit": "business_day", "value": 1},
                    "maximum": {"unit": "business_day", "value": 1},
                    },
                },
                },
            ],
            line_items=[
                {
                    # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                    'price': line_items[0]['price'],
                    'quantity': line_items[0]['quantity'],
                },
            ],
            mode='payment',
            custom_text={
    "shipping_address": {
      "message":
      "Please note that we can't guarantee 2-day delivery for PO boxes at this time.",
    },
    "submit": {"message": "We'll email you instructions on how to get started."},
  },
            return_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        )
    except Exception as e:
        return str(e)

    return jsonify(clientSecret=checkout_session.client_secret, )

@app.route('/manage-card', methods=['POST','GET'])
@login_required
def manage_card():
    email = current_user.get_email()
    cards_dict = {}
    cur = mysql.connection.cursor()
    query = ('SELECT * FROM stripe_customer_card WHERE email = %s')
    params = (email,)
    cur.execute(query, params)
    data = cur.fetchall()
    for item in data:
        cards_dict.update({item[0]: {
            'email': item[1],
            'last_4': item[6]
    }})
    count = len(cards_dict)
    return render_template('manage_card.html', cards_dict = cards_dict, count = count)

@app.route('/deleteCard/<int:id>', methods=['GET','POST'])
@login_required
def delete_card(id):
    email = current_user.get_email()
    cur = mysql.connection.cursor()
    try:
        query = 'select * from stripe_customer_card where email = %s'
        params = (email,)
        cur.execute(query, params)
        data = cur.fetchall()
        cards_dict = {}
        for item in data:
            cards_dict.update({item[0]: {
            'email': item[1],
            'last_4': item[6]
    }})
        for key in cards_dict:
            if key == id:
                customer_info_adapter.info(f"Card ID: ({id}) has been deleted from stripe_customer_card database")
                query = 'DELETE FROM stripe_customer_card WHERE id = %s'
                params = (id,)
                cur.execute(query,params)
        
        

        mysql.connection.commit()
    except Exception as e:
        customer_info_adapter.error(f'Error occurred while deleting Card ID: ({id}) | Error: {str(e)}')
        mysql.connection.rollback()
    finally:
        cur.close()
    return redirect(url_for('manage_card'))

@app.route('/manage-address', methods=['POST','GET'])
@login_required
def manage_address():
    email = current_user.get_email()
    address_dict = {}
    cur = mysql.connection.cursor()
    query = ('SELECT * FROM stripe_customer_address WHERE email = %s')
    params = (email,)
    cur.execute(query, params)
    data = cur.fetchall()
    for item in data:
        address_dict.update({item[0]: {
            'email': item[1],
            'line1': item[4],
            'line2': item[5],
            'City': item[6],
            'Country': item[7],
            'State': item[9],
            'Postal_Code': item[8]
            
    }})
    count = len(address_dict)
    return render_template('manage_address.html', address_dict = address_dict, count = count)

@app.route('/deleteAddress/<int:id>', methods=['GET','POST'])
@login_required
def delete_address(id):
    email = current_user.get_email()
    cur = mysql.connection.cursor()
    try:
        query = 'select * from stripe_customer_address where email = %s'
        params = (email,)
        cur.execute(query, params)
        data = cur.fetchall()
        address_dict = {}
        for item in data:
            address_dict.update({item[0]: {
                'email': item[1],
                'line1': item[4],
                'line2': item[5],
                'City': item[6],
                'Country': item[7],
                'State': item[9],
                'Postal_Code': item[8]
                
        }})
        for key in address_dict:
            if key == id:
                customer_info_adapter.info(f"Address ID: ({id}) has been deleted from stripe_customer_address database")
                query = 'DELETE FROM stripe_customer_address WHERE id = %s'
                params = (id,)
                cur.execute(query,params)

        mysql.connection.commit()
    except Exception as e:
        customer_info_adapter.error(f'Error occurred while deleting Address ID: ({id}) | Error: {str(e)}')
        mysql.connection.rollback()
    finally:
        cur.close()
    return redirect(url_for('manage_address'))

# @app.route('/session-status', methods=['GET'])
# def session_status():
#   session = stripe.checkout.Session.retrieve(request.args.get('session_id'))

#   return jsonify(status=session.status, customer_email=session.customer_details.email)

@app.route('/create-payment-intent', methods=['POST','GET'])
@login_required
def create_payment():
    email = current_user.get_email()
    # otp_form = OtpForm(request.form)
    # entered_otp = otp_form.entered_otp.data
    # if entered_otp != '1':
    #     return render_template('otp-checkout.html')
    if "cart_products" not in session:
        session["cart_products"] = {}

    if "cart_products" in session:
        cart_session = session["cart_products"]


    if "cart_quantity" in session:
        cart_quantity_session = session["cart_quantity"]

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select data from stripe_products')
    data = cur.fetchall()

    stripe_products_dict = {}
    for item in data:
        json_data = item['data']
        stripe_products_data = json.loads(json_data)  # Convert JSON string to dictionary
        stripe_products_dict = stripe_products_data
    cur.close()
    stripe_products_dict = {int(key): value for key, value in stripe_products_dict.items()}
    print(stripe_products_dict)

    line_items = []
    metadata = {}
    images = {}
    formatted_line_items = []
    total_amount = 0
    for key in stripe_products_dict:
        if str(key) in cart_session:
            line_items.append({'price_id': stripe_products_dict[key]['price']['id'], 'quantity' : int(cart_quantity_session[str(key)]['_Cart__cart_quantity']), 'price': stripe_products_dict[key]['price']['unit_amount'], 'description': stripe_products_dict[key]['product']['name']})
    
    for item in line_items:
        formatted_line_items.append({
                'price': item['price'],
                'quantity': item['quantity'],
                'description': item['description']

            })
    print(formatted_line_items)

    for item in formatted_line_items:
        total_amount += item['price'] * item['quantity']
    # for shipping cost $5
    total_amount += 500
    while len(metadata) != len(cart_session):
        for key in stripe_products_dict:
            if str(key) in cart_session:
                for item in formatted_line_items:
                    if item['description'] == stripe_products_dict[key]['product']['name']:
                        description = item['description']
                        price = item['price']
                        cart_quantity = int(cart_quantity_session[str(key)]['_Cart__cart_quantity'])

                        # Create a tuple of item details
                        item_tuple = (cart_quantity, description, price)

                        # Update metadata[key] with unique item tuples
                        if key not in metadata:
                            metadata[key] = set()

                        metadata[key].add(item_tuple)

    selected_card = ''

    if 'selected_card' not in session:
        session['selected_card'] = ''

    else:
        selected_card = session['selected_card']


    selected_card_form_value = request.args.get('card_option')
    if selected_card_form_value != None:
        if selected_card == '':
            selected_card = selected_card_form_value
        else:
            if selected_card != selected_card_form_value:
                selected_card = selected_card_form_value
    session['selected_card'] = selected_card

    selected_address = ''
    if 'selected_address' not in session:
        session['selected_address'] = ''

    else:
        selected_address = session['selected_address']


    selected_address_form_value = request.args.get('address_option')
    if selected_address_form_value != None:
        if selected_address == '':
            selected_address = selected_address_form_value
        else:
            if selected_address != selected_address_form_value:
                selected_address = selected_address_form_value
    session['selected_address'] = selected_address
    print('wagwa')
    print(selected_address)
    
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM stripe_customer_card")
    data = cur.fetchall()



    for row in data:
        customer_id = row[7]
        if customer_id == selected_card:
            encrypted_card_details_iv = row[2]
            encrypted_card_details_ct = row[3]
            encrypted_secret_key_iv = row[4]
            encrypted_secret_key_ct = row[5]
            encrypted_card_details_dict = {'iv': encrypted_card_details_iv, 'ciphertext': encrypted_card_details_ct}
            encrypted_secret_key_dict = {'iv': encrypted_secret_key_iv, 'ciphertext': encrypted_secret_key_ct}
            card_details_bytes = decrypt_card_func(encrypted_card_details_dict, encrypted_secret_key_dict)
            card_details_string = str(card_details_bytes, encoding='utf-8')
            card_num = card_details_string.split('|')[0]
            exp_month = card_details_string.split('|')[1]
            exp_year = card_details_string.split('|')[2]
            cvc = card_details_string.split('|')[3]
            token = stripe.Token.create(
            card={
                'number': str(card_num),
                'exp_month': exp_month,
                'exp_year': exp_year,
                'cvc': str(cvc),
            },
        )
            print(token)
            payment_method = stripe.PaymentMethod.create(
                type='card',
                card={'token': token},
                billing_details={
                    'email': email
                },
            )
            stripe.PaymentMethod.attach(
                payment_method.id,
                customer=customer_id,
            )
            stripe.Customer.modify(
                customer_id,
                invoice_settings={
                    'default_payment_method': payment_method.id,
                },
            )
            payment_method_id = payment_method['id']
            print('pm' + payment_method_id)
            break

    query = 'select * from stripe_customer_address where id = %s'
    params = (selected_address,)
    cur.execute(query,params)
    address_details = cur.fetchall()
    for row in address_details:
        address_details_dict = {
                "city": row[6],
                "country": row[7],
                "line1": row[4],
                "line2": row[5],
                "postal_code": row[8],
                "state": row[9]
        }
        customer_name_phone = {
                'name': row[2],
                'phone': row[3]

            }
    
    print(address_details_dict)

    stripe.PaymentMethod.modify(
        payment_method_id,
        billing_details = {
            'address': address_details_dict,
            'name' : customer_name_phone['name'],
            'phone' : customer_name_phone['phone']
        }
        
    )                           
    try:
        # Create a PaymentIntent with the order amount and currency
        intent = stripe.PaymentIntent.create(
            amount=total_amount,
            currency='sgd',
            # In the latest version of the API, specifying the `automatic_payment_methods` parameter is optional because Stripe enables its functionality by default.
            automatic_payment_methods={
                'enabled': True,
            },
            payment_method=payment_method_id,
            metadata=metadata,
            # payment_method_types=['card'],
            off_session=True,
            customer = customer_id,
            shipping= {
                'address': address_details_dict,
                'name': customer_name_phone['name'],
                'phone': customer_name_phone['phone'],
            },
            confirm=True,
            return_url='https://localhost:3306/success',


        )
        order_reference = str(uuid.uuid4())
        session['order_reference'] = order_reference

        return redirect(url_for('success'))
        # return render_template('success.html')
    except Exception as e:
        return render_template('cancel.html', error=str(e))
    




@app.route('/webhook', methods=['POST'])
def webhook():
    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e
    # Handle the event
    line_items = None

    if event['type'] == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        e = payment_intent['last_payment_error']
        if e['type'] == 'card_error':
            Total_amount = payment_intent['amount']/100
            customer_purchase_adapter.error(f"Error Code: {e['code']} | Status: {payment_intent['status']} | Transaction ID: {payment_intent['id']} | Customer ID: {payment_intent['customer']} | Customer Email: {e['payment_method']['billing_details']['email']} Total: ${Total_amount:.2f} | Status: {payment_intent['status']} | Order Details: {payment_intent['metadata']}")
            print(payment_intent)
            msg = Message(
            subject=f"Oh no, your payment to Renewify has failed", sender = 'renewifysg@gmail.com', recipients=[e['payment_method']['billing_details']['email']] #e['payment_method']['billing_details']['email']
            )  # Replace with recipient(s)
            try:
                msg.body=f"""
                    Hi {e['payment_method']['billing_details']['name']}
                    Your Card has been declined. Please Try Again Later
                    You have not been charged

                    Order Details:
                    Total Price:
                    {Total_amount}



                    Contact Information:
                    Name: renewifysg
                    Email Address: renewifysg@gmail.com
                """
            except:
                print('error')

            mail.send(msg)
        elif e['type'] == 'invalid_request':
            Total_amount = payment_intent['amount']/100
            customer_purchase_adapter.error(f"Error_Code: {e['code']} | Status: {payment_intent['status']} | Transaction ID: {payment_intent['id']} | Customer ID: {payment_intent['customer']} | Total: ${Total_amount:.2f} | Status: {payment_intent['status']} | Order Details: {payment_intent['metadata']}")
            msg = Message(
            subject=f"Oh no, your payment to Renewify has failed", sender = 'renewifysg@gmail.com', recipients=[e['payment_method']['billing_details']['email']] #e['payment_method']['billing_details']['email']
            )  # Replace with recipient(s)
            try:
                msg.body=f"""
                    Hi {e['payment_method']['billing_details']['name']}
                    An invalid request occurred and the payment has failed. Please Try Again Later.
                    You have not been charged

                    Order Details:
                    Total Price:
                    {Total_amount}



                    Contact Information:
                    Name: renewifysg
                    Email Address: renewifysg@gmail.com
                """
            except:
                print('error')

            mail.send(msg)
        else:
            Total_amount = payment_intent['amount']/100
            customer_purchase_adapter.error(f"Error_Code: {e['code']} | Status: {payment_intent['status']} | Transaction ID: {payment_intent['id']} | Customer ID: {payment_intent['customer']} | Total: ${Total_amount:.2f} | Order Details: {payment_intent['metadata']}")
            msg = Message(
            subject=f"Oh no, your payment to Renewify has failed", sender = 'renewifysg@gmail.com', recipients=[e['payment_method']['billing_details']['email']] #e['payment_method']['billing_details']['email']
            )  # Replace with recipient(s)
            try:
                msg.body=f"""
                    Hi {e['payment_method']['billing_details']['name']}
                    An error has occurred. This may be an issue by stripe. Please Try Again Later
                    You have not been charged

                    Order Details:
                    Total Price:
                    {Total_amount}



                    Contact Information:
                    Name: renewifysg
                    Email Address: renewifysg@gmail.com
                """
            except:
                print('error')

            mail.send(msg)
        

    if event['type'] == 'payment_intent.succeeded':
        data_obj = event['data']
        session_id = data_obj['object']['id']
        print(f'dwadaw {session_id}')
        line_items = stripe.PaymentIntent.retrieve(session_id)
        print(f'dwadawwdww {line_items}')
        total_amount = line_items['amount'] / 100
        customer_purchase_adapter.info(f"Status: {line_items['status']} | Transaction ID: {line_items['id']} | Customer ID: {line_items['customer']} | Total: ${total_amount:.2f} | Order Details: {line_items['metadata']}")
        # selected_shipping_rate = stripe.ShippingRate.retrieve(checkout_session.shipping_cost.shipping_rate)
        # fixed_amount = (selected_shipping_rate.get("fixed_amount", {}).get("amount", 0))/100
        pm = line_items['payment_method']
        cus = line_items['customer']
        address = stripe.Customer.retrieve_payment_method(
            cus,
            pm,
        )
        print('dwaaa')
        print(address['billing_details']['address'])
        session_id_dict = {}
        
        

        cur = mysql.connection.cursor()
        cur.execute('select * from product_inventory')
        data = cur.fetchall()
        products_dict = {}
        for row in data:
            product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
            product_item.set_id(row[0])
            product_item.set_url(row[7])
            products_dict[row[0]] = product_item
        cur.close()

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute('select data from db_session_id')
        data = cur.fetchall()

        session_id_dict = {}
        try:
            for item in data:
                json_data = item['data']
                session_id_data = json.loads(json_data)  # Convert JSON string to dictionary
                session_id_dict[session_id_data['pid']] = session_id_data
        except:
            print('session id')
            print(session_id_dict)
        cur.close()
        


        # target_description_array = []
        # for item in line_items:
        #     target_description_array.append(line_items[item]['data'][0]['description'])

        # for item in session_id_dict:
        #     if session_id_dict[item]['data'][0]['description'] not in session_id_dict:
        shipping_amount = 0
        total_price = 0
        order_date = datetime.date.today()
        arrive_by_days = datetime.timedelta(days=7)
        arrive_by_date = order_date + arrive_by_days
        order_date = order_date.isoformat()
        arrive_by_date = arrive_by_date.isoformat()
        metadata = line_items['metadata']
        # Example metadata dictionary with multiple items
        print(metadata)
        parsed_metadata = {}

        # Iterate through each key-value pair in metadata
        for key, value in metadata.items():
            # Remove outer curly braces
            cleaned_string = value.strip("{}")
            
            # Remove parentheses
            inner_content = cleaned_string.strip("()")
            
            # Split into components based on commas
            components = inner_content.split(", ")
            
            # Parse components into appropriate types
            cart_quantity = int(components[0])
            description = components[1].strip("'")  # Remove surrounding single quotes
            price = int(components[2])
            
            # Create a dictionary with parsed values
            parsed_metadata[key] = {
                "quantity": cart_quantity,
                "description": description,
                "amount_total": price
            }

        metadata = parsed_metadata
        print(metadata)
        total_price = (line_items['amount'])/100
        # Print or use the parsed metadata
        # Initialize the session entry if it doesn't exist
        if session_id not in session_id_dict:
            session_id_dict[session_id] = []
        for key, value in metadata.items():

            description = value['description']
            amount_total = (value['amount_total']) / 100
            quantity = value['quantity']
            
            matching_product = next((products_dict[k] for k in products_dict if products_dict[k].get_name().lower() == description.lower()), None)
            
            if matching_product:
                print(f"Matched product: {matching_product.get_name()}")
                new_item = {
                    'id': session_id,
                    'name': description,
                    'price': amount_total,
                    'total_price': total_price,
                    'quantity': quantity,
                    'image': matching_product.get_url(),
                    'order_date': order_date,
                    'arrive_date': arrive_by_date,
                }
                session_id_dict[session_id].append(new_item)
            else:
                print(f"No matching product found for: {description}")

        print(f"Final session_id_dict: {session_id_dict}")


        # items_dict = {}
        # items_list = []
        # for item in line_items['data']:
        #     description = item['description']
        #     amount_total = item['amount_total']
        #     quantity = item['quantity']
        #     items_dict.update({'name': description, 'amount_total': amount_total, 'quantity': quantity})
        # print(items_dict)
        # print(session_id)
        # for item in session_id_dict:
        #     session_id_dict[session_id] = items_dict
        #     print(session_id_dict)

        # cur = mysql.connection.cursor()
        # cur.execute('update db_session_id set id =  ')
        print(session_id_dict)
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        for session_id in session_id_dict:
            json_data = json.dumps(session_id_dict)
            query = ('insert into db_session_id (id, data) VALUES (%s, %s)')
            params = (session_id, json_data)
            cur.execute(query, params)
        mysql.connection.commit()
        cur.close()



        intent_id = event['data']['object']['id']
        intent = stripe.PaymentIntent.retrieve(intent_id)
        print(intent_id)

        cur = mysql.connection.cursor()
        cur.execute('select * from product_inventory')
        data = cur.fetchall()
        products_dict = {}
        for row in data:
            product_item = Products.Products(row[1],row[2],row[3],row[4],row[5],row[6])
            product_item.set_id(row[0])
            product_item.set_url(row[7])
            products_dict[row[0]] = product_item


        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute('select data from stripe_products')
        data = cur.fetchall()

        stripe_products_dict = {}
        for item in data:
            json_data = item['data']
            stripe_products_data = json.loads(json_data)  # Convert JSON string to dictionary
            stripe_products_dict = stripe_products_data
        cur.close()
        stripe_products_dict = {int(key): value for key, value in stripe_products_dict.items()}

        for key, metadata_item in metadata.items():
            user_quantity = metadata_item['quantity']

        for key in products_dict:
            if str(key) in metadata:
                if str(key) in metadata:
                    db_quantity = products_dict[int(key)].get_quantity()
                    new_db_quantity = db_quantity - int(user_quantity)
                    products_dict[key].set_quantity(new_db_quantity)
                    print(products_dict[key].get_quantity())
                    
        

        cur = mysql.connection.cursor()
        for key in products_dict:
            # Update existing record
            query = ("UPDATE product_inventory SET product_name = %s, product_price = %s, product_quantity = %s, product_country = %s, product_type = %s, product_dietary = %s, product_url = %s WHERE product_id = %s")
            params = (products_dict[key].get_name(), products_dict[key].get_price(), products_dict[key].get_quantity(), products_dict[key].get_country(), products_dict[key].get_type(), products_dict[key].get_dietary(), products_dict[key].get_url(), products_dict[key].get_id())
            cur.execute(query, params)
        mysql.connection.commit()

        cur.close()

        print('email sent')

    else:
        print('Unhandled event type {}'.format(event['type']))

    return jsonify(success=True)

@app.route('/boughtProducts', methods=['GET', 'POST'])
@login_required
def bought_products():
    # if not current_user.is_authenticated:
    #     return redirect(url_for('login'))
    email = current_user.get_email()
    print(email)

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select data from db_session_id')
    data = cur.fetchall()

    session_id_dict = {}
    try:
        for item in data:
            json_data = item['data']
            session_id_data = json.loads(json_data)  # Convert JSON string to dictionary
            session_id_dict = session_id_data
    except:
        print('error')
    print('session id')
    print(session_id_dict)
    cur.close()

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select data from stripe_products')
    data = cur.fetchall()

    stripe_products_dict = {}
    for item in data:
        json_data = item['data']
        stripe_products_data = json.loads(json_data)  # Convert JSON string to dictionary
        stripe_products_dict = stripe_products_data
    cur.close()
    stripe_products_dict = {int(key): value for key, value in stripe_products_dict.items()}

    session_bought_products = {}
    if "bought_products" not in session:
        session["bought_products"] = session_bought_products

    session_bought_products = session_id_dict

    today = datetime.date.today()

    # try:
    #     form = LoginForm()
    #     if form.validate_on_submit():
    #         current_user.email = form.email.data
    #     elif request.method == 'GET':
    #         form.email.data = current_user.email
    # except:
    #     print('error')

    # if bought_products_information_dict == {}:
    #     bought_products_information_dict = session_bought_products
    #     print(f'eeeeeeeeeeee{session_bought_products}')
    #     db_bought_information['bought_products_information'] = bought_products_information_dict


    # print(form.email.data)

    # try:
    #     if bought_products_information_dict != {}:
    #         for key in bought_products_information_dict:
    #             if form.email.data in bought_products_information_dict:
    #                 print('d')

    #             elif form.email.data not in bought_products_information_dict:
    #                 bought_products_information_dict[form.email.data] = {}
    #                 print(bought_products_information_dict)

    #             # elif form.email.data not in bought_products_information_dict and bought_products_information_dict != {}:
    #             #     bought_products_information_dict_new = {form.email.data: bought_products_information_dict}
    #             #     bought_products_information_dict[form.email.data] = bought_products_information_dict
    #             # elif form.email.data not in bought_products_information_dict:
    #             #     bought_products_information_dict = {form.email.data: bought_products_information_dict}
    #             #     db_bought_information['bought_products_information'] = bought_products_information_dict
    #     else:
    #         bought_products_information_dict[form.email.data] = {}
    #         db_bought_information['bought_products_information'] = bought_products_information_dict


    # except:
    #     print('error')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select data from bought_products_information')
    data = cur.fetchall()

    bought_products_information_dict = {}
    for item in data:
        json_data = item['data']
        bought_products_data = json.loads(json_data)  # Convert JSON string to dictionary
        bought_products_information_dict = bought_products_data
    print(bought_products_information_dict)
    cur.close()

    
    if email in bought_products_information_dict:
        if bought_products_information_dict[email] != {}:
            session_bought_products.update(bought_products_information_dict[email])
        else:
            # bought_products_information_dict[email] = session_bought_products
            # db_bought_information['bought_products_information'] = bought_products_information_dict
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            json_data = json.dumps(bought_products_information_dict)
            query = ('update bought_products_information set data = %s')
            params = (json_data,)
            cur.execute(query, params)
    else:
        bought_products_information_dict[email] = {}
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        json_data = json.dumps(bought_products_information_dict)
        
        query = ('update bought_products_information set data = %s')
        params = (json_data,)
        cur.execute(query, params)
    mysql.connection.commit()
    cur.close()
    
    print('dwa')
    print(session_bought_products)

    # Uncomment when have user info like email integrated
    print(type(bought_products_information_dict))
    for key in bought_products_information_dict:
        if email == key:
            for item in session_bought_products:
                if item not in bought_products_information_dict[key]:
                    bought_products_information_dict[email].update(session_bought_products)
                    # db_bought_information['bought_products_information'] = bought_products_information_dict
                    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    json_data = json.dumps(bought_products_information_dict)
                    query = ('update bought_products_information set data = %s')
                    params = (json_data,)
                    cur.execute(query, params)
    mysql.connection.commit()
    cur.close()
                        

    unique_products = {}
    seen_ids = set()

    for key, item in session_bought_products.items():
        unique_item = []
        for product in item:
            product_id = product['name']
            if product_id not in seen_ids:
                unique_item.append(product)
                seen_ids.add(product_id)
        unique_products[key] = unique_item

    session_bought_products = unique_products


    # ORIGINAL:
    # session["bought_products"] = session_bought_products 

    # NEW, the 2 lines below
    session["bought_products"] = session_id_dict
    session_bought_products = session_id_dict
    # print(session_id_dict)
    # print(f'pro{session_bought_products}')


    # for key in bought_products_information_dict:
    #     if form.email.data == key:
    #         if bought_products_information_dict[key] == {}:
    #             bought_products_information_dict[key].update(session_bought_products)



    # if bought_products_information_dict != {}:
    #     db_bought_information['bought_products_information'] = bought_products_information_dict


    # try:
    #     if session_bought_products == {}:
    #         if bought_products_information_dict != {}:
    #             for key in bought_products_information_dict:
    #                 if form.email.data in bought_products_information_dict:
    #                     if form.email.data == key:
    #                         session_bought_products = bought_products_information_dict[key]
    #                         session["bought_products"] = session_bought_products
    #                         session_id_dict = bought_products_information_dict[key]
    #                         db_session_id['session_id'] = session_id_dict
    #         else:
    #             print(session_bought_products)
    # except:
    #     pass





    # if form.email.data == None:
    #     session_bought_products = {}
    #     session["bought_products"] = session_bought_products
    # print(form.email.data)


    # try:
    #     for key in session_bought_products:
    #         if form.email.data == key:
    #             if form.email.data not in session_bought_products:
    #                 session_bought_products = {}
    #                 session["bought_products"] = session_bought_products
    #             else:
    #                 session_bought_products = session_bought_products[key]
    #                 session["bought_products"] = session_bought_products
    # except:
    #     pass
    for session_id, items_list in session_bought_products.items():
        print(items_list)

    if request.method == 'POST':
        try:
            remove_history = request.form.get("Remove_history")
            if remove_history == "Delete Cart History":
                # try:
                #     form = LoginForm()
                #     if form.validate_on_submit():
                #         current_user.email = form.email.data
                #     elif request.method == 'GET':
                #         form.email.data = current_user.email
                # except:
                #     print('error')
                empty_dict = {}
                session["bought_products"].clear()
                session_bought_products.clear()
                session_bought_products = empty_dict
                cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cur.execute('delete from db_session_id')
                bought_products_information_dict[email] = {}
                print('ehy')
                print(bought_products_information_dict)
                
                json_data = json.dumps(bought_products_information_dict)
                query = ('update bought_products_information set data = %s')
                params = (json_data,)
                cur.execute(query, params)
                mysql.connection.commit()
                cur.close()

                return redirect(url_for('bought_products', session_bought_products = session_bought_products, today= today, ))
        except:
            return redirect(url_for('bought_products'))



    # for key in bought_products_information_dict:
    #     if current_user.email in bought_products_information_dict:
    #         session_bought_products = bought_products_information_dict[current_user.email]






    # for item in stripe_products_dict:
    #     if stripe_products_dict[item]['product']['name'] in session_id_dict.values():
    #         product_name = stripe_products_dict[item]['product']['name']

    #         bought_products_dict[product_name] = {
    #                 'amount_total': session_id_dict[product_name]['amount_total'],
    #                 'quantity': session_id_dict[product_name]['quantity'],
    #                 'image': stripe_products_dict[item]['product']['images']
    #         }

    # session["bought_products"] = bought_products_dict
    return render_template('boughtProducts.html', session_bought_products = session_bought_products, today= today)

@app.route('/cancel', methods=['GET'])
@login_required
def cancel():
    return render_template('cancel.html')

@app.route('/success', methods=['GET','POST'])
@login_required
def success():
    order_reference = session.get('order_reference')
    print(order_reference)
    if not order_reference:
        return render_template('success.html', order_reference = order_reference)
    else:
        email = current_user.get_email()
        if "cart_products" in session:
            session["cart_products"].clear()

        if "cart_quantity" in session:
            session["cart_quantity"].clear()

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute('select data from db_session_id')
        data = cur.fetchall()

        session_id_dict = {}
        try:
            for item in data:
                json_data = item['data']
                session_id_data = json.loads(json_data)  # Convert JSON string to dictionary
                session_id_dict = session_id_data
        except:
            print('error')


        product_name = []
        total_quantity = 0
        product_price = []
        product_image = []
        product_quantity = []
        total_price = 0
        for key in session_id_dict:
            session_id = key
            total_price = 0
            total_quantity = 0
        for key, item in session_id_dict.items():
            for product in item:
                product_name.append(product['name'])
                product_quantity.append(product['quantity'])
                total_quantity += product['quantity']
                product_price.append(product['price'])
                total_price += product['price'] * product['quantity']
                total_quantity += product['quantity']
        #     session_id_dict[key] = total_price
        # print("Total Prices:", total_prices)
        unique_names = set()
        duplicate_names = set()
        for name in product_name:
            if name in unique_names:
                duplicate_names.add(name)
            else:
                unique_names.add(name)
        product_name_no_dupe = list(set(product_name))

        all_product_names = ', \n'.join(product_name_no_dupe)
        # unique_price = set()
        # duplicate_price = set()
        # for price in product_price:
        #     if price in unique_price:
        #         duplicate_price.add(price)
        #     else:
        #         unique_price.add(price)
        # product_price_no_dupe = list(set(product_price))
        # all_product_price = ' \n'.join(map(str, product_price_no_dupe))
        # print(all_product_price)

        # Iterate through each product and update the total quantity in the dictionary
        # length_difference = len(product_quantity) - len(product_name_no_dupe)

        # # Remove elements from the start of product_quantity to match the lengths
        # if length_difference > 0:
        #     product_quantity = product_quantity[length_difference:]
        # all_product_quantity = '\n'.join(map(str, product_quantity,))
            # Create the email message


        # for the email msg, when logins are created, change the email and other stuff when integrating
        msg = Message(
            subject=f"Receipt for purchase", sender = 'renewifysg@gmail.com', recipients=[email])  # Replace with recipient(s)

        msg_body = f"""

        Products:

        """
        try:
            msg.body=f"""

                Your purchase has went through


                Contact Information:
                Name: 'Renewify'
                Email Address: 'renewifysg@gmail.com
            """
        except:
            pass

        mail.send(msg)
        session.pop('order_reference', None)
        return render_template('success.html', order_reference = order_reference)

# LOGS AND AJAX TO FETCH
@app.route('/staff_logs', methods=['GET','POST']) #MAIN LOG HTML
def logs():
    check_for_banned_ips()
    if 'logged_in' not in session or not session.get('staff'):
        return redirect(url_for('customer_login'))
    if session['role'] == 'Staff':
        return redirect(url_for('dash'))
    else:
        # db_log_content = ""
        # try:
        #     with open('db.log', 'r') as db_log_file:
        #         db_log_content = db_log_file.read()
        # except FileNotFoundError:
        #     db_log_content = "Log file not found."
        
        # for line in file_content:
        #     file_content_list.append(line)
        # print(*file_content_list, sep='\n')


        return render_template('staff_logs.html')

@app.route('/fetch-db-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_db_logs():
    db_log_content = ""
    try:
        with open('../../logs/db.log', 'r') as db_log_file:
            db_log_content = db_log_file.read()
    except FileNotFoundError:
        db_log_content = "Log file not found."
    
    return db_log_content

@app.route('/fetch-customer-purchase-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_customer_purchase_logs():
    customer_purchase_log_content = ""
    try:
        with open('../../logs/customer_purchase.log', 'r') as customer_purchase_log_file:
            customer_purchase_log_content = customer_purchase_log_file.read()
    except FileNotFoundError:
        customer_purchase_log_content = "Log file not found."
    return customer_purchase_log_content

# finish this route for customer info
@app.route('/fetch-customer-info-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_customer_info_logs():
    customer_info_log_content = ""
    try:
        with open('../../logs/customer_info.log', 'r') as customer_info_log_file:
            customer_info_log_content = customer_info_log_file.read()
    except FileNotFoundError:
        customer_info_log_content = "Log file not found."
    return customer_info_log_content

@app.route('/fetch-system-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_system_logs():
    system_log_content = ""
    try:
        with open('../../logs/system.log', 'r') as system_log_file:
            system_log_content = system_log_file.read()
    except FileNotFoundError:
        system_log_content = "Log file not found."
    return system_log_content

@app.route('/fetch-login-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_login_logs():
    login_log_content = ""
    try:
        with open('../../logs/login.log', 'r') as login_log_file:
            login_log_content = login_log_file.read()
    except FileNotFoundError:
        login_log_content = "Log file not found."
    return login_log_content

@app.route('/fetch-general-logs', methods=['GET']) #USED TO FETCH THE LOG AND PASS TO THE staff_logs
def fetch_general_logs():
    general_log_content = ""
    try:
        with open('../../logs/general.log', 'r') as general_log_file:
            general_log_content = general_log_file.read()
    except FileNotFoundError:
        general_log_content = "Log file not found."
    return general_log_content

@app.route('/stocks_dashboard')
def stocks_dashboard():
    with shelve.open("products.db") as db:
        products_dict = db["Products"]

        low_stock_dict = {"Stockout and near stockout items": [], "Product Names": []}
        for key in products_dict:
            product_quantity = products_dict[key].get_quantity()
            product_name = products_dict[key].get_name()

            if product_quantity <= 3:
                low_stock_dict["Stockout and near stockout items"] += [product_quantity]
                low_stock_dict["Product Names"] += [product_name]

        fig = px.bar(low_stock_dict, x="Stockout and near stockout items", y="Product Names", title="Stockout and near stockout items")
        fig.update_layout(height=1000, width=1000, paper_bgcolor = "rgba(0,0,0,0)", plot_bgcolor = "rgba(0,0,0,0)", font_color = 'white', font_family = 'Poppins', font_size = 14, barmode='overlay', xaxis_title=None, yaxis_title=None)
        plot_div = fig.to_html(full_html=False)

        return render_template("stocks_dashboard.html", plot_div=plot_div)


@app.route('/download_csv')
def download_csv():
    with shelve.open("products.db") as db:
        products_dict = db["Products"]

        low_stock_dict = {"Stockout and near stockout items": [], "Product Names": []}
        for key in products_dict:
            product_quantity = products_dict[key].get_quantity()
            product_name = products_dict[key].get_name()

            if product_quantity <= 3:
                low_stock_dict["Stockout and near stockout items"].append(product_quantity)
                low_stock_dict["Product Names"].append(product_name)

        # Write the data to a CSV string
        csv_data = "Stockout and near stockout items,Product Names\n"
        for i in range(len(low_stock_dict["Stockout and near stockout items"])):
            csv_data += f"{low_stock_dict['Stockout and near stockout items'][i]},{low_stock_dict['Product Names'][i]}\n"

        # Send the CSV data as a response
        response = make_response(csv_data)
        response.headers["Content-Disposition"] = "attachment; filename=low_stock_items.csv"
        response.headers["Content-type"] = "text/csv"

        return response


@app.route('/revenue_dashboard')
def revenue_dashboard():
    sales = {}
    sales["Product Name"] = []
    sales["Total Sales"] = 0

    try:
        with shelve.open("session_id.db") as db:
            order_details = db.get('session_id', {})
            sales = {"Product Name": [], "Total Sales": 0}

            for key in order_details:
                for item_dict in order_details[key]:
                    if item_dict["name"] not in sales["Product Name"]:
                        sales['Product Name'].append(item_dict["name"])

            sales_dict = {name: 0 for name in sales['Product Name']}

            for name in sales['Product Name']:
                for key in order_details:
                    for item_dict in order_details[key]:
                        if name == item_dict["name"]:
                            sales_dict[name] += round(item_dict["total_price"], 2)

            product_names_list = list(sales_dict.keys())
            total_sales_list = list(sales_dict.values())

            fig = px.pie(values=total_sales_list, names=product_names_list)
            fig.update_layout(height=1000, width=1000, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color='white', font_family='Poppins', font_size=14)
            plot_div = fig.to_html(full_html=False)

            return render_template("revenue_dashboard.html", plot_div=plot_div)

    except Exception as e:
        print(f"An error occurred: {e}")
        return render_template("revenue_dashboard.html", plot_div=None)

@app.route('/download_csv_revenue')
def download_csv_revenue():


    with shelve.open("session_id.db") as db:
        order_details = db['session_id']
        sales_dict = {}

        for key in order_details:
            for dict in order_details[key]:
                name = dict["name"]
                total_price = dict["total_price"]
                if name in sales_dict:
                    sales_dict[name] += total_price
                else:
                    sales_dict[name] = total_price

        # Write the data to a CSV string
        csv_data = "Product Name,Total Sales\n"
        for name, total_sales in sales_dict.items():
            csv_data += f"{name},{total_sales}\n"

        # Send the CSV data as a response
        response = make_response(csv_data)
        response.headers["Content-Disposition"] = "attachment; filename=revenue_data.csv"
        response.headers["Content-type"] = "text/csv"

        return response

if __name__ == '__main__':
    # app.run(port=3306, debug=True)
    serve(app, host='0.0.0.0', port = 3306, url_scheme='https')
