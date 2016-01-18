from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

from ..models import User

# Login Page
class LoginForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('keep me logged in.')
	submit = SubmitField('Log In')

# Registration page
class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

# Change password page
class ChangePasswordForm(Form):
	old_password = PasswordField('Old password', validators=[Required()])
	password = PasswordField('New password', validators=[Required(), \
		    EqualTo('password2', message='Password must match')])
	password2 = PasswordField('Confirm new password', validators=[Required()])
	submit = SubmitField('Update Password')

# Reset password page
class PasswordResetRequestForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	submit = SubmitField('Reset Password')

class PasswordResetForm(Form):
	email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('New Password', validators=[Required(), \
		    EqualTo('password2', message='PasswordField must match')])
	password2 = PasswordField('Confirm password', validators=[Required()])
	submit = SubmitField('Reset Password')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first() is None:
			raise ValidationError('Unknown email address.')

# Change email address page
class ChangeEmailForm(Form):
	email = StringField('New Email', validators=[Required(), Length(1, 64), Email()])
	password = PasswordField('Password', validators=[Required()])
	submit = SubmitField('Update Email Address')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

