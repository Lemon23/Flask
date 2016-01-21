from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from markdown import markdown
from flask import current_app, request, session
from datetime import datetime
from flask.ext.login import UserMixin, AnonymousUserMixin
import hashlib
import bleach
from . import login_manager, db

# Setting permissions constant
class Permission:
	FOLLOW = 0x01             # Follow other users
	COMMENT = 0x02            # Published comment in other people's article
	WRITE_ARTICLES = 0x04     # Writing articles
	MODERATE_COMMENTS = 0x08  # Managing Others comments
	ADMINISTER = 0x80         # Administrator privileges, administer the site


# define database
class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	#: Setting role permission
	default = db.Column(db.Boolean, default=False, index=True)
	permissions = db.Column(db.Integer)
	#: Establish relationship with User model
	users = db.relationship('User', backref='role', lazy='dynamic')

	@staticmethod
	# Find an existing role by role name, and then update, 
	# When the database is not the role name, Just Creating a new role objects
	def insert_roles():
		roles = {
		    'User': (Permission.FOLLOW | Permission.COMMENT | \
		    	    Permission.WRITE_ARTICLES, True), 
		    'Moderator': (Permission.FOLLOW | Permission.COMMENT | \
		    	    Permission.WRITE_ARTICLES | Permission.MODERATE_COMMENTS, False), 
		    'Administrator': (0xff, False)
		}
		for r in roles:
			role = Role.query.filter_by(name=r).first()
			if role is None:
				role = Role(name=r)
			role.permissions = roles[r][0]
			role.default = roles[r][1]
			db.session.add(role)
		db.session.commit()
	
	def __repr__(self):
		return '<Role %r>'% self.name

# Followers the associated table model
class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64), unique=True, index=True)
	username = db.Column(db.String(64), unique=True, index=True)
	#: Establish external links, role_id = id
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	#: Password hash
	password_hash = db.Column(db.String(128))
	#: Confirm the user account
	confirmed = db.Column(db.Boolean, default=False)
	#: User information field
	name = db.Column(db.String(64))
	location = db.Column(db.String(64))
	about_me = db.Column(db.Text())
	member_since = db.Column(db.DateTime(), default=datetime.utcnow)
	last_seen = db.Column(db.DateTime(), default=datetime.utcnow)

	avatar_hash = db.Column(db.String(32))
	posts = db.relationship('Post', backref='author', lazy='dynamic')
	#: Use two 'one-to-many' relationship, Realization 'many-to-many' relationship
	followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
	followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
	comments = db.relationship('Comment', backref='author', lazy='dynamic')

	# user set their own Followers
	@staticmethod
	def add_self_follows():
		for user in User.query.all():
			if not user.is_following(user):
				user.follow(user)
				db.session.add(user)
				db.session.commit()

	# Define a default user roles
	def __init__(self, **kwargs):
		super(User, self).__init__(**kwargs)
		if self.role is None:
			if self.email == current_app.config['FLASKY_ADMIN']:
				self.role = Role.query.filter_by(permissions=0xff).first()
			if self.role is None:
				self.role = Role.query.filter_by(default=True).first()
		if self.email is not None and self.avatar_hash is None:
			self.avatar_hash = hashlib.md5(
				self.email.encode('utf-8')).hexdigest()
		self.followed.append(Follow(followed=self))
 

	@property
	def password(self):
		raise AttributeError('Password id not a readable attribute.')

	@password.setter
	# Calculate the hash value of the password
	def password(self, password):
		self.password_hash = generate_password_hash(password)
	
	''' Accept a parameter password, and User model in the password
	    hash value for comparison, 
	    if return True, it means that the password is correct
	'''
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)
	
	# Generate a tokens, valid be set to one hour
	def generate_confirmation_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})

    # Examination tokens
	def confirm(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
		if data.get('confirm') != self.id:
			return False
		self.confirmed = True
		db.session.add(self)
		return True

	# Reset password, reset tokens sent to a mailbox
	def generate_reset_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'reset': self.id})

	def reset_password(self, token, new_password):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
		if data.get('reset') != self.id:
			return False
		self.password = new_password
		db.session.add(self)
		return True

	# Change Email address, need to verify the new address and send a message contain tokens
	def generate_email_change_token(self, new_email, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'change_email': self.id, 'new_email': new_email})
	
	# Server receives tokens and then update the user object
	def change_email(self, token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return False
		if data.get('change_email') != self.id:
			return False
		new_email = data.get('new_email')
		if new_email is None:
			return False
		if self.query.filter_by(email=new_email).first() is not None:
			return False
		self.email = new_email
		self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
		db.session.add(self)
		return True

	# Check whether the user has specified permission
	def can(self, permissions):
		return self.role is not None and \
		    (self.role.permissions & permissions) == permissions

    # Check administrator permissions
	def is_administrator(self):
		return self.can(Permission.ADMINISTER)

	# Refresh the user last access time
	def ping(self):
		self.last_seen = datetime.utcnow()
		db.session.add(self)

	# generate Profile Photos 'Gravatar URL'
	def gravatar(self, size=100, default='identicon', rating='g'):
		if request.is_secure:
			url = 'https://secure.gravatar.com/avatar'
		else:
			url = 'http://www.gravatar.com/avatar'
		hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
		return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

	def follow(self, user):
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)

	def unfollow(self, user):
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			db.session.delete(f)

	def is_following(self, user):
		return self.followed.filter_by(
            followed_id=user.id).first() is not None

	def is_followed_by(self, user):
		return self.followers.filter_by(
            follower_id=user.id).first() is not None

	# Get Concerned User Articles
	@property
	def followed_posts(self):
		return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
            .filter(Follow.follower_id == self.id)
	
	def __repr__(self):
		return '<User %r>'% self.username

''' Without having to first checking whether the user login, 
    It can free calls 'current_user.can()' 
    and 'current_user.is_administrator()'
'''
class AnonymousUser(AnonymousUserMixin):
	def can(self, permissions):
		return False

	def is_administrator(self):
		return False

login_manager.anonymous_user = AnonymousUser


# Load user's callback function
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    # Processing Markdown text in post model
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

db.event.listen(Post.body, 'set', Post.on_changed_body)

# Comment Model
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_changed_body)


