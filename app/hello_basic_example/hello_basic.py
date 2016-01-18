from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from flask.ext.wtf import Form
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.mail import Mail, Message
from flask import Flask, render_template, session, redirect, url_for, flash
from datetime import datetime
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from threading import Thread
import os

# configure SQLAlchemy database
basedir = os.path.abspath(os.path.dirname(__file__))

app=Flask(__name__)
bootstrap = Bootstrap(app)
moment = Moment(app)
manager = Manager(app)
mail = Mail(app)

# Flask-WTF set key
app.config['SECRET_KEY'] = 'hard to guess string'

# configure SQLite database
# Program using the database URL must be saved to the Flask configuration object in the 'SQLALCHEMY_DATABASE_URI' key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite') 
# After the end of the request will automatically submit the database changes
app.config['AQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
# The db object is an instance of the SQLAlchemy class
db = SQLAlchemy(app)

# Database migration command
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# E-mail Support
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Flasky]'
app.config['FLASKY_MAIL_SENDER'] = 'Flasky Admin <flasky@example.com>'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['FLASKY_ADMIN'] = os.environ.get('FLASKY_ADMIN')


@app.route('/', methods=['GET','POST'])
def index():
	form = NameForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username = form.name.data).first()
		old_name = session.get('name')
		if user is None:
			user = User(username = form.name.data)
			db.session.add(user)
			session['known'] = False
			if app.config['FLASKY_ADMIN']:
				send_email(app.config['FLASKY_ADMIN'], 'New User', 'mail/new_user', user=user)
		else:
			session['known'] = True
		if old_name is not None and old_name != form.name.data:
			flash('Looks like you have changed your name!')
		session['name'] = form.name.data
		form.name.data = ''
		return redirect(url_for('index'))
	return render_template('index_basic.html', form=form, name=session.get('name'), known=session.get('known', False), current_time=datetime.utcnow())

@app.route('/user/<name>')
def user(name):
    return render_template('user_basic.html', name=name)

# Page Not Found 
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# define form
class NameForm(Form):
	name = StringField('What is your name?', validators=[Required()])
	submit = SubmitField('Submit')

# dfine database
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	# Establish relationship with User model
	users = db.relationship('User', backref='role', lazy='dynamic')
	
	def __repr__(self):
		return '<Role %r>'% self.name

class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, index=True)
	# Establish external links, role_id = id
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

	def __repr__(self):
		return '<User %r>'% self.username

# define let Shell command automatically import specific objects
def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role)
manager.add_command("shell", Shell(make_context=make_shell_context))

# Asynchronous send mail
def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)
# send email
def send_email(to, subject, template, **kwargs):
	msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg])
	thr.start()
	return thr

if __name__ == '__main__':
    app.run(debug=True)
