from wtforms import Form, StringField, validators, PasswordField, ValidationError
from flask_wtf import FlaskForm

class Loginform(FlaskForm):
    email = StringField('Email', [validators.Length(min=1, max=150), validators.DataRequired()])

    password = PasswordField('password', [validators.Length(min=1, max=20), validators.DataRequired()])

