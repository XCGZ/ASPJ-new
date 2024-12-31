from flask_login import UserMixin
class Customer(UserMixin):

    count_id = None

    def __init__(self, username, password, name, email, gender, country_code, phone_no, date_of_birth, profile_picture, remarks):

        self.__user_id = None
        self.__username = username
        self.__password = password
        self.__name = name
        self.__email = email
        self.__gender = gender
        self.__country_code = country_code
        self.__phone_no = phone_no
        self.__date_of_birth = date_of_birth
        self.__profile_picture = profile_picture
        self.__remarks = remarks
    
    def set_user_id(self, user_id):
        self.__user_id = user_id
    
    def get_id(self):
        return self.__user_id

    def get_values(self):
        return [self.__username, self.__name, self.__email, self.__country_code,self.__phone_no, self.__date_of_birth, self.__remarks]

    # accessor methods

    def get_user_id(self):
        return self.__user_id

    def get_username(self):
        return self.__username

    def get_password(self):
        return self.__password

    def get_name(self):
        return self.__name

    def get_email(self):
        return self.__email

    def get_gender(self):
        return self.__gender

    def get_country_code(self):
        return self.__country_code

    def get_phone_no(self):
        return self.__phone_no

    def get_date_of_birth(self):
        return self.__date_of_birth

    def get_profile_picture(self):
        # Check if profile_picture is None, return a default image filename if True
        return self.__profile_picture or 'profile_picture.jpg'

    def get_remarks(self):
        return self.__remarks

    # mutator methods (adjusted for naming conventions)
    def set_user_id(self, user_id):
        self.__user_id = user_id

    def set_username(self, username):
        self.__username = username

    def set_password(self, password):
        self.__password = password

    def set_name(self, name):
        self.__name = name

    def set_email(self, email):
        self.__email = email

    def set_gender(self, gender):
        self.__gender = gender

    def set_country_code(self, country_code):
        self.__country_code = country_code

    def set_phone_no(self, phone_no):
        self.__phone_no = phone_no

    def set_date_of_birth(self, date_of_birth):
        self.__date_of_birth = date_of_birth

    def set_profile_picture(self, profile_picture):
        self.__profile_picture = profile_picture

    def set_remarks(self, remarks):
        self.__remarks = remarks

    # additional methods
    def toggle_password_visibility(self):
        # Toggle the password visibility (show/hide)
        if hasattr(self, '__show_password') and self.__show_password:
            self.__show_password = False
        else:
            self.__show_password = True

    def get_visible_password(self):
        # Return the visible password if it's toggled, otherwise return asterisks
        return self.__password if hasattr(self, '__show_password') and self.__show_password else '*' * 10
