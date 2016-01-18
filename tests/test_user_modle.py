import unittest
import time
from datetime import datetime
from app import db, create_app
from app.models import User, AnonymousUser, Role, Permission


class UserModelTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


    # test password hash
    def test_password_setter(self):
        u = User(password = 'cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password = 'cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password = 'cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_salts_are_random(self):
        u = User(password = 'cat')
        u2 = User(password = 'cat')
        self.assertTrue(u.password_hash != u2.password_hash)

    # Detect tokens, confirmation the account
    def test_valid_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))
    
    def test_expired_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))

    # Users to reset the password, need to reset tokens
    def test_calid_reset_token(self):
        u = User(password='cat')
        db.session.add(u)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u.generate_reset_token()
        self.assertTrue(u.reset_password(token, 'dog'))
        self.assertTrue(u.verify_password('dog'))

    def test_invalid_reset_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u1.generate_reset_token()
        self.assertFalse(u2.reset_password(token, 'horse'))
        self.assertTrue(u2.verify_password('dog'))

    # Verification modify account information: 
    # change Password, reset Password and Modify E-mail address
    def test_valid_email_change_token(self):
        u = User(email = 'john@example.com', password='cat')
        db.session.add(u)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u.generate_email_change_token('ada@example.org')
        self.assertTrue(u.change_email(token))
        self.assertTrue(u.email == 'ada@example.org')

    def test_invalid_email_change_token(self):
        u1 = User(email='john@example.com', password='cat')
        u2 = User(email='ada@example.org', password='dog')
        db.session.add(u1)
        db.session.add(u2)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u1.generate_email_change_token('david@example.net')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'ada@example.org')

    def test_duplicate_email_change_token(self):
        u1 = User(email='john@example.com', password='cat')
        u2 = User(email='ada@example.org', password='dog')
        db.session.add(u1)
        db.session.add(u2)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        token = u2.generate_email_change_token('john@example.com')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'ada@example.org')

    # Detect role
    def test_roles_and_permissions(self):
        u = User(email='john@example.com', password='cat')
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))
    # Detect Permissions
    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))

    # Check the user access time
    def test_timestamps(self):
        u = User(password='cat')
        db.session.add(u)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        self.assertTrue(
            (datetime.utcnow() - u.member_since).total_seconds() < 3)
        self.assertTrue(
            (datetime.utcnow() - u.last_seen).total_seconds() < 3)

    def test_ping(self):
        u = User(password='cat')
        db.session.add(u)
        try:
            db.session.commit()
        except:
            db.session.rollback()
        time.sleep(2)
        last_seen_before = u.last_seen
        u.ping()
        self.assertTrue(u.last_seen > last_seen_before)
