from wtforms import Form, ValidationError, EmailField, DateField, PasswordField, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, DecimalField
from flask_wtf.file import FileField, FileAllowed, FileRequired, FileSize
from flask import session, Flask
from country_code import COUNTRY_CODES
import pyotp, re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL

from wtforms.validators import DataRequired, Length, Regexp, NumberRange
from wtforms.widgets import MonthInput
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 5000
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'product_inventory'

mysql = MySQL(app)


# class CreateProductsForm(Form):
#     product_name = StringField('Product Name', [validators.Length(min=1, max=30), validators.DataRequired()])
#     product_price = IntegerField('Product Price', [validators.NumberRange(min=1, max=1000), validators.DataRequired()])
#     product_quantity = IntegerField('Product Quantity', [validators.NumberRange(min=1, max=10000), validators.DataRequired()])
#     product_country = StringField('Product Country', [validators.Length(min=1, max=30), validators.DataRequired()])
#     product_type = StringField('Product Type', [validators.Length(min=1, max=500), validators.DataRequired()])
#     product_dietary = StringField('Product Dietary', [validators.Length(min=1, max=30), validators.DataRequired()])
#     product_url = StringField('Product URL')

class CreateProductsForm(Form):
    product_name = StringField('Product Name', [validators.Length(min=1, max=1000), validators.DataRequired()])
    product_price = DecimalField('Product Price', [validators.NumberRange(min=1, max=1000), validators.DataRequired()])
    product_quantity = IntegerField('Product Quantity', [validators.NumberRange(min=0, max=10000), validators.data_required()])

    product_country = SelectField('Product Country', [validators.DataRequired()], 
                                  choices=[
                                      ('Singapore', 'Singapore'), 
                                      ('Japan', 'Japan'), 
                                      ('China', 'China'),
                                      ('India', 'India')], default='Singapore')

    product_type = SelectField('Product Type', [validators.DataRequired()], 
                                choices=[
                                        ('Shoes', 'Shoes'),
                                        ('Tees', 'Tees')], default='Shoes')

    product_dietary = SelectField('Product Material', [validators.DataRequired()], 
                                  choices=[
                                        ('Upcycled', 'Upcycled'),
                                        ('Recycled', 'Recycled')], default='Upcycled')

    product_url = StringField('Product URL')

    product_image = FileField('Product Image', [FileRequired(message="Please upload an image."),FileAllowed(['jpg', 'png', 'jpeg'], 'Images Only!')])
    


class SelectCardForm(Form):
    select_card = RadioField('Select Card')

class CreateCardForm(FlaskForm):
    card_number = StringField('Card Number', [validators.Length(min=16, max=16), validators.DataRequired()])
    month = StringField('Month', validators=[DataRequired(), Length(min=2, max=2)])
    year = StringField('Year', validators=[DataRequired(), Length(min=2, max=2)])
    cvc = StringField('CVC', validators=[DataRequired(), Length(min=3, max=3)])


class SearchForm(Form):
    search = StringField('Search')



class CreateCustomerForm(Form):


    username = StringField('Username', [validators.Length(min=1, max=50), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=8, max=50), validators.DataRequired()])
    name = StringField('Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    country_code = SelectField('Country Code', [validators.DataRequired()], choices=COUNTRY_CODES, default='')
    phone_no = StringField('Phone Number', [validators.DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d')
    profile_picture = FileField('Profile Picture', [FileRequired(message="Please upload an image."),FileAllowed(['jpg', 'png', 'jpeg'], 'Images Only!')])
    remarks = TextAreaField('Remarks', [validators.Optional()])


class SignUpForm(Form):
    recaptcha = RecaptchaField()
    username = StringField('Username', [validators.Length(min=1, max=50), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=8, max=50), validators.DataRequired()])
    name = StringField('Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    country_code = SelectField('Country Code', [validators.DataRequired()], choices=COUNTRY_CODES, default='')
    phone_no = StringField('Phone Number', [validators.DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d')
    profile_picture = FileField('Profile Picture', [FileRequired(message="Please upload an image."),FileAllowed(['jpg', 'png', 'jpeg'], 'Images Only!')])
    remarks = TextAreaField('Remarks', [validators.Optional()])

class LoginForm(Form):
    recaptcha = RecaptchaField()
    LoginEmail = EmailField('Email', [validators.Length(min=1, max=150), validators.DataRequired()])
    LoginPassword = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()])


class ForgotPasswordForm(Form):

    recaptcha = RecaptchaField()
    email = EmailField('Email', [validators.DataRequired(), validators.Length(min=1, max=50)])


class OtpForm(Form):

    entered_otp = StringField('One Time Password', [validators.DataRequired(), validators.Length(min=6, max=6)])


class ResetPasswordForm(Form):


    password = PasswordField('New Password', [validators.Length(min=1, max=15), validators.DataRequired()])
    confirm_password = PasswordField('Confirm Password', [validators.Length(min=1, max=15), validators.DataRequired()])


class UpdateCustomerForm(Form):



    username = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
    name = StringField('Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    country_code = SelectField('Country Code', [validators.DataRequired()], choices=COUNTRY_CODES, default='')
    phone_no = StringField('Phone Number', [validators.DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d')
    profile_picture = FileField('Profile Picture', [FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    remarks = TextAreaField('Remarks', [validators.Optional()])


class UpdateProfileForm(Form):
    username = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])
    name = StringField('Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    country_code = SelectField('Country Code', [validators.DataRequired()], choices=COUNTRY_CODES, default='')
    phone_no = StringField('Phone Number', [validators.DataRequired()])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d')
    profile_picture = FileField('Profile Picture', [FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])


class ChangePasswordForm(Form):

    old_password = PasswordField('Old Password', [validators.Length(min=1, max=15), validators.DataRequired()])
    new_password = PasswordField('New Password', [validators.Length(min=1, max=15), validators.DataRequired()])
    confirm_password = PasswordField('Confirm Password', [validators.Length(min=1, max=15), validators.DataRequired()])



    