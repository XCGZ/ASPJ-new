from wtforms import Form, StringField, validators, PasswordField, EmailField, IntegerField, SelectField
from wtforms.validators import number_range
from flask_wtf import FlaskForm

class CreateStaffform(FlaskForm):
    staff_username = StringField('Username', validators=[validators.Length(min=1, max=20), validators.DataRequired()])

    staff_password = PasswordField('password', validators=[validators.Length(min=1, max=20), validators.DataRequired()])

    email = EmailField('Email', validators=[validators.Length(min=1, max=40), validators.DataRequired()])

    phone_no = IntegerField('Phone Number', validators=[number_range(max=99999999999), validators.DataRequired()])

    organisation = StringField('Organisation', validators=[validators.Length(min=1, max=50), validators.DataRequired()])

    address = StringField('Address', validators=[validators.Length(min=1, max=50), validators.DataRequired()])

    city = StringField('City', validators=[validators.Length(min=1, max=21), validators.DataRequired()])

    state = StringField('State', validators=[validators.Length(min=1, max=14), validators.DataRequired()])

    country = StringField('Country', validators=[validators.Length(min=1, max=57), validators.DataRequired()])

    postalcode = IntegerField('Postal Code', validators=[number_range(max=9999999999), validators.DataRequired()])

    role = SelectField('Role', validators=[validators.DataRequired()], choices=[('Admin', 'Admin'), ('Staff', 'Staff')
        , ('Auditor', 'Auditor')])


class SMsearch(Form):
    search = StringField('Search', [validators.Length(min=1, max=150), validators.DataRequired()])