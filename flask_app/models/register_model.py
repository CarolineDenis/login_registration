from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import DATABASE
from flask_app.controllers import registers_controller
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$")
LETTER_REGEX = re.compile(r'^[a-zA-Z]+$')

class Account:
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def save(cls,data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s,%(last_name)s,%(email)s,%(password)s,NOW(),NOW())"
        return connectToMySQL(DATABASE).query_db(query,data)

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results =  connectToMySQL(DATABASE).query_db(query)
        new_list_user =[]
        for b in results:
            new_list_user.append(cls(b))
        return new_list_user

    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(DATABASE).query_db(query,data)
        # Didn't find a matching user
        if len(result) < 1:
            flash("Email not registered.")
            return False
        return cls(result[0])

    @staticmethod
    def validate_form(form):
        is_valid = True
        query = "SELECT * FROM users WHERE email = %(email)s;"
        results = connectToMySQL(DATABASE).query_db(query,form)
        if len(results) >= 1:
            flash("Email already registered.", "err_email")
            is_valid = False
        if not EMAIL_REGEX.match(form['email']): 
            flash("Invalid email address!", "err_email")
            is_valid = False
        if  not LETTER_REGEX.match(form['first_name']):
            flash("First Name must contain only character", "err_name")
            is_valid = False
        if len(form['first_name']) < 2:
            flash("First Name must be at least 2 characters.", "err_first_name")
            is_valid = False
        if len(form['last_name']) < 2:
            flash("Last Name must be at least 2 characters.", "err_last_name")
            is_valid = False
        if len(form['password']) < 8:
            flash("Password must be at least 8 characters", "err_password")
            is_valid = False
        if form['password'] != form['confirm_password']:
            flash("Confirmation doesn't match password", "err_confirm_password")
            is_valid = False
        if not PASSWORD_REGEX.match(form['password']): 
            flash("Invalid password! Must be 8 characters with minimum one uppercase", "err_password")
            is_valid = False
        return is_valid
