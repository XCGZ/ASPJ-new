import bcrypt
from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, PasswordField, ValidationError
from wtforms.fields import EmailField, DateField
import shelve
from flask import session
from string import ascii_letters, digits

class CreateUserForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "First Name"})
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Last Name"})
    email = EmailField('Email', [validators.Email(), validators.DataRequired()], render_kw={"placeholder": "Staff Email"})
    def validate_email(form, email):
        if "@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')
        elif ".com" not in email.data:
            raise ValidationError('Email Format missing a domain!')
        elif "prime@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')


        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['Users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        x = 1

        for user in users_list:
            if email.data == user.get_email():
                x = 0

        if x == 0:
            raise ValidationError('Email is currently already in use!')

    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    password = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()],
                             render_kw={"placeholder": "Password"})
    def validate_password(form, password):
        if len(password.data) < 8:
            raise ValidationError('Password must be at least 8 characters!')
        if any(char.isdigit() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 number!')

        if set(password.data).difference(ascii_letters + digits):
            pass
        else:
            raise ValidationError('Password must contain at least 1 special character!')

        if any(char.isupper() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 uppercase!')

        if any(char.islower() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 lowercase character!')

    remarks = TextAreaField('Remarks', [validators.Optional()], render_kw={"placeholder": "Remarks if appropriate"})


# MTCHANGE: Added this for update user
class UpdateUserForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "First Name"})
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Last Name"})
    email = EmailField('Email', [validators.Email(), validators.DataRequired()], render_kw={"placeholder": "Staff Email"})
    def validate_email(form, email):
        if "@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')
        elif ".com" not in email.data:
            raise ValidationError('Email Format missing a domain!')
        elif "prime@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')


        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['Users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        # x = 1
        #
        # for user in users_list:
        #     if email.data == user.get_email():
        #         x = 0
        #
        # if x == 0:
        #     raise ValidationError('Email is currently already in use!')

    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    # password = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()],
    #                          render_kw={"placeholder": "Password"})
    # def validate_password(form, password):
    #     if len(password.data) < 8:
    #         raise ValidationError('Password must be at least 8 characters!')
    #     if any(char.isdigit() for char in password.data):
    #         pass
    #     else:
    #         raise ValidationError('Password must contain at least 1 number!')
    #
    #     if set(password.data).difference(ascii_letters + digits):
    #         pass
    #     else:
    #         raise ValidationError('Password must contain at least 1 special character!')
    #
    #     if any(char.isupper() for char in password.data):
    #         pass
    #     else:
    #         raise ValidationError('Password must contain at least 1 uppercase!')
    #
    #     if any(char.islower() for char in password.data):
    #         pass
    #     else:
    #         raise ValidationError('Password must contain at least 1 lowercase character!')

    remarks = TextAreaField('Remarks', [validators.Optional()], render_kw={"placeholder": "Remarks if appropriate"})

class CreateCustomerForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "First Name"})
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Last Name"})
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    email = EmailField('Email', [validators.Email(), validators.DataRequired()], render_kw={"placeholder": "Email"})
    password = StringField('Password', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Password"})
    def validate_password(form, password):
        if len(password.data) < 8:
            raise ValidationError('Password must be at least 8 characters!')
        if any(char.isdigit() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 number!')

        if set(password.data).difference(ascii_letters + digits):
            pass
        else:
            raise ValidationError('Password must contain at least 1 special character!')

        if any(char.isupper() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 uppercase!')

        if any(char.islower() for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 lowercase character!')

    date_joined = DateField('Date Joined', format='%Y-%m-%d', render_kw={"placeholder": "Date Joined"})
    address = TextAreaField('Shipping Address', [validators.length(max=200), validators.DataRequired()], render_kw={"placeholder": "Shipping Address"})
    membership = RadioField('Membership', choices=[('F', 'Fellow'), ('S', 'Senior'), ('P', 'Professional')],
                            default='F')
    remarks = TextAreaField('Remarks', [validators.Optional()], render_kw={"placeholder": "Remarks if appropriate"})


class StaffLogin(Form):
    x = 1
    email_check = EmailField('Email', [validators.Email(), validators.DataRequired()], render_kw={"placeholder": "Staff Email"})
    def validate_email_check(form, email_check):
        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['Users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        email_exists = any(email_check.data == user.get_email() for user in users_list)

        if not email_exists:
            x = 0
            session['email_exists'] = x
            raise ValidationError(f"The email '{email_check.data}' does not exist in the database!")



    password_check = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Password"})
    def validate_password_check(form, password_check):
        if session.get('email_exists') == 0:
            session.pop('email_exists', None)
            pass
        else:
            users_dict = {}
            db = shelve.open('user.db', 'r')
            users_dict = db['Users']
            db.close()

            users_list = []
            for key in users_dict:
                user = users_dict.get(key)
                users_list.append(user)

            # MTCHANGE: Changed this validation to use bcrypt.checkpw against db
            password_same = any(bcrypt.checkpw(password_check.data.encode('utf-8'), user.get_password().encode('utf-8')) for user in users_list)

            if not password_same:
                raise ValidationError(f"Email or password is incorrect")



class CreateStaffForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=20), validators.DataRequired()], render_kw={"placeholder": "First Name"})
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()], render_kw={"placeholder": "Last Name"})
    email = EmailField('Email', [validators.DataRequired()], render_kw={"placeholder": "Staff Email"})
    def validate_email(form, email):
        if "@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')
        elif ".com" not in email.data:
            raise ValidationError('Email missing a domain!')
        elif "prime@gmail.com" not in email.data:
            raise ValidationError('Incorrect Email Format!')

        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['Users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        x = 1

        for user in users_list:
            if email.data == user.get_email():
                x = 0

        if x == 0:
            raise ValidationError('Email is currently already in use!')


    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    password = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()],
                                   render_kw={"placeholder": "Password"})
    def validate_password(form, password):
        if len(password.data) < 8:
            raise ValidationError('Password must be at least 8 characters!')
        if any(char.isdigit()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 number!')

        if set(password.data).difference(ascii_letters + digits):
            pass
        else:
            raise ValidationError('Password must contain at least 1 special character!')

        if any(char.isupper()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 uppercase!')

        if any(char.islower()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 lowercase character!')

    confirm_password = PasswordField('Confirm Password', [validators.Length(min=1, max=150), validators.DataRequired(), validators.EqualTo('password', 'Passwords must match!')],
                                   render_kw={"placeholder": "Confirm Password"},)


class SendEmailForm(Form):
    email_reset = EmailField('Staff Email', [validators.Email(), validators.DataRequired()], render_kw={"placeholder": "Enter Staff Email"})
    def validate_email(form, email_reset):
        if "@gmail.com" not in email_reset.data:
            raise ValidationError('Incorrect Email Format!')
        elif ".com" not in email_reset.data:
            raise ValidationError('Email missing a domain!')


class ResetPasswordForm(Form):
    code = StringField('4 Digit Code', [validators.Length(min=4, max=4), validators.DataRequired()])
    def validate_code(form, code):
        if str(code.data) != str(session.get('reset_code')):
            raise ValidationError('Code does not match! Try Again.')

class ChangePasswordForm(Form):
    password = PasswordField('Password', [validators.Length(min=1, max=150), validators.DataRequired()],
                             render_kw={"placeholder": "Password"})
    def validate_password(form, password):
        if len(password.data) < 8:
            raise ValidationError('Password must be at least 8 characters!')
        if any(char.isdigit()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 number!')

        if set(password.data).difference(ascii_letters + digits):
            pass
        else:
            raise ValidationError('Password must contain at least 1 special character!')

        if any(char.isupper()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 uppercase!')

        if any(char.islower()for char in password.data):
            pass
        else:
            raise ValidationError('Password must contain at least 1 lowercase character!')

        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['Users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        x = 1

        for user in users_list:
            if password.data == user.get_password():
                x = 0

        if x == 0:
            raise ValidationError('Password entered cannot be the same as last time!')

    confirm_password = PasswordField('Confirm Password', [validators.Length(min=1, max=150), validators.DataRequired(),
                                                          validators.EqualTo('password', 'Passwords must match!')],
                                     render_kw={"placeholder": "Confirm Password"}, )