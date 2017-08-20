from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo


class NotDoForm(FlaskForm):
	task = StringField("To Not Do", validators=[InputRequired()])



class LoginForm(FlaskForm):
	username = StringField('Username', validators=[InputRequired()])
	password = PasswordField('Password', validators=[InputRequired()])
	remember = BooleanField('Remeber Me')


class SignUpForm(FlaskForm):
	username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
	email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	password = PasswordField('Password', validators=[InputRequired(), EqualTo('password2', message='Passwords must match')])
	password2 = PasswordField('Confirm Password', validators=[InputRequired()])

