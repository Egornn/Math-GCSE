from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    topic = SelectField('Topic', choices=[
        ('algebra', 'Algebra'),
        ('geometry', 'Geometry'),
        ('number', 'Number'),
        ('statistics', 'Statistics'),
        ('probability', 'Probability'),
        ('calculus', 'Calculus')
    ], validators=[DataRequired()])
    difficulty = SelectField('Difficulty', choices=[
        ('foundation', 'Foundation'),
        ('higher', 'Higher')
    ])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Post Image', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    is_published = BooleanField('Publish Immediately', default=True)
    submit = SubmitField('Create Post')

class CommentForm(FlaskForm):
    author_name = StringField('Your Name', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired(), Length(max=200)])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')