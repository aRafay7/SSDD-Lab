"""
Forms for Secure Flask Application
Task 1: Secure Input Handling - Prevent Injection Attacks (SQL Injection, XSS)
Uses Flask-WTF with validators to ensure proper input validation and sanitization
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import (
    DataRequired, 
    Email, 
    Length, 
    Regexp, 
    EqualTo,
    ValidationError
)
from models import User


class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(min=2, max=20, message='Username must be between 2 and 20 characters'),
            Regexp(
                '^[A-Za-z0-9_]+$',
                message='Username must contain only letters, numbers, or underscores'
            )
        ]
    )
    
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address')
        ]
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters long')
        ]
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ]
    )
    
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')


class LoginForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address')
        ]
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required')
        ]
    )
    
    submit = SubmitField('Login')


class FeedbackForm(FlaskForm):
    title = StringField(
        'Feedback Title',
        validators=[
            DataRequired(message='Title is required'),
            Length(min=3, max=100, message='Title must be between 3 and 100 characters')
        ]
    )
    
    message = TextAreaField(
        'Your Feedback',
        validators=[
            DataRequired(message='Feedback message is required'),
            Length(min=5, max=500, message='Feedback must be between 5 and 500 characters')
        ]
    )
    
    submit = SubmitField('Submit Feedback')
