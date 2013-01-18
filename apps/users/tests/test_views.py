from time import time
import requests

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core import mail

import mock
from nose import SkipTest
from nose.tools import eq_, ok_
from nose.plugins.attrib import attr
from pyquery import PyQuery as pq

from notifications.tests import watch
from sumo.tests import TestCase, LocalizingClient
from sumo.urlresolvers import reverse
from users.models import RegistrationProfile, EmailChange
from users.views import SESSION_VERIFIED_EMAIL


class LoginTestCase(TestCase):
    fixtures = ['test_users.json']

    def setUp(self):
        self.old_debug = settings.DEBUG
        settings.DEBUG = True
        self.client = LocalizingClient()
        self.client.logout()

    def tearDown(self):
        settings.DEBUG = self.old_debug

    @mock.patch_object(Site.objects, 'get_current')
    def test_bad_login_fails_both_backends(self, get_current):
        get_current.return_value.domain = 'dev.mo.org'
        self.assertRaises(User.DoesNotExist, User.objects.get,
                          username='nouser')

        response = self.client.post(reverse('users.login'),
                                    {'username': 'nouser',
                                     'password': 'nopass'}, follow=True)
        eq_(200, response.status_code)
        self.assertContains(response, 'Please enter a correct username and '
                                      'password.')

    @mock.patch_object(Site.objects, 'get_current')
    def test_django_login(self, get_current):
        get_current.return_value.domain = 'dev.mo.org'

        response = self.client.post(reverse('users.login'),
                                    {'username': 'testuser',
                                     'password': 'testpass'}, follow=True)
        eq_(200, response.status_code)
        doc = pq(response.content)
        eq_('testuser', doc.find('ul.user-state a:first').text())

    @mock.patch_object(Site.objects, 'get_current')
    def test_django_login_wont_redirect_to_login(self, get_current):
        get_current.return_value.domain = 'dev.mo.org'
        login_uri = reverse('users.login')

        response = self.client.post(login_uri,
                                    {'username': 'testuser',
                                     'password': 'testpass',
                                     'next': login_uri},
                                    follow=True)
        eq_(200, response.status_code)
        for redirect_url, code in response.redirect_chain:
            ok_(login_uri not in redirect_url, "Found %s in redirect_chain"
                % login_uri)
        doc = pq(response.content)
        eq_('testuser', doc.find('ul.user-state a:first').text())

    @mock.patch_object(Site.objects, 'get_current')
    def test_logged_in_message(self, get_current):
        get_current.return_value.domain = 'dev.mo.org'
        login_uri = reverse('users.login')

        response = self.client.post(login_uri,
                                    {'username': 'testuser',
                                     'password': 'testpass'},
                                    follow=True)
        eq_(200, response.status_code)
        response = self.client.get(login_uri, follow=True)
        eq_(200, response.status_code)
        doc = pq(response.content)
        eq_("You are already logged in.", doc.find('div#content-main').text())

    @mock.patch_object(Site.objects, 'get_current')
    def test_django_login_redirects_to_next(self, get_current):
        get_current.return_value.domain = 'dev.mo.org'
        login_uri = reverse('users.login')

        response = self.client.post(login_uri,
                                    {'username': 'testuser',
                                     'password': 'testpass'},
                                    follow=True)
        eq_(200, response.status_code)
        response = self.client.get(login_uri, {'next': '/en-US/demos/submit'},
                                   follow=True)
        eq_('http://testserver/en-US/demos/submit',
                                                response.redirect_chain[0][0])


class RegisterTestCase(TestCase):
    fixtures = ['test_users.json']

    def setUp(self):
        self.old_debug = settings.DEBUG
        settings.DEBUG = True
        self.client = LocalizingClient()
        self.client.logout()

    def tearDown(self):
        settings.DEBUG = self.old_debug

    @mock.patch_object(Site.objects, 'get_current')
    def test_new_user(self, get_current):
        get_current.return_value.domain = 'su.mo.com'
        now = time()
        username = 'newb%s' % now
        response = self.client.post(reverse('users.register'),
                                    {'username': username,
                                     'email': 'newbie@example.com',
                                     'password': 'foo',
                                     'password2': 'foo'}, follow=True)
        eq_(200, response.status_code)
        u = User.objects.get(username=username)
        assert u.password.startswith('sha256')
        assert not u.is_active
        eq_(1, len(mail.outbox))
        assert mail.outbox[0].subject.find('Please confirm your') == 0
        key = RegistrationProfile.objects.all()[0].activation_key
        assert mail.outbox[0].body.find('activate/%s' % key) > 0

        # Now try to log in
        u.is_active = True
        u.save()
        response = self.client.post(reverse('users.login'),
                                    {'username': username,
                                     'password': 'foo'}, follow=True)
        eq_(200, response.status_code)
        eq_('http://testserver/en-US/', response.redirect_chain[0][0])

    @mock.patch_object(Site.objects, 'get_current')
    def test_unicode_password(self, get_current):
        get_current.return_value.domain = 'su.mo.com'
        now = time()
        username = 'cjk%s' % now
        u_str = u'\xe5\xe5\xee\xe9\xf8\xe7\u6709\u52b9'
        response = self.client.post(reverse('users.register', locale='ja'),
                                    {'username': username,
                                     'email': 'cjkuser@example.com',
                                     'password': u_str,
                                     'password2': u_str}, follow=True)
        eq_(200, response.status_code)
        u = User.objects.get(username=username)
        u.is_active = True
        u.save()
        assert u.password.startswith('sha256')

        # make sure you can login now
        response = self.client.post(reverse('users.login', locale='ja'),
                                    {'username': username,
                                     'password': u_str}, follow=True)
        eq_(200, response.status_code)
        eq_('http://testserver/ja/', response.redirect_chain[0][0])

    @mock.patch_object(Site.objects, 'get_current')
    def test_new_user_activation(self, get_current):
        get_current.return_value.domain = 'su.mo.com'
        now = time()
        username = 'sumo%s' % now
        user = RegistrationProfile.objects.create_inactive_user(
            username, 'testpass', 'sumouser@test.com')
        assert not user.is_active
        key = RegistrationProfile.objects.all()[0].activation_key
        url = reverse('users.activate', args=[key])
        response = self.client.get(url, follow=True)
        eq_(200, response.status_code)
        user = User.objects.get(pk=user.pk)
        assert user.is_active

    @mock.patch_object(Site.objects, 'get_current')
    def test_new_user_claim_watches(self, get_current):
        """Claim user watches upon activation."""
        old, settings.CELERY_ALWAYS_EAGER = settings.CELERY_ALWAYS_EAGER, True

        get_current.return_value.domain = 'su.mo.com'

        watch(email='sumouser@test.com', save=True)

        now = time()
        username = 'sumo%s' % now
        user = RegistrationProfile.objects.create_inactive_user(
            username, 'testpass', 'sumouser@test.com')
        key = RegistrationProfile.objects.all()[0].activation_key
        self.client.get(reverse('users.activate', args=[key]), follow=True)

        # Watches are claimed.
        assert user.watch_set.exists()

        settings.CELERY_ALWAYS_EAGER = old

    def test_duplicate_username(self):
        response = self.client.post(reverse('users.register'),
                                    {'username': 'testuser',
                                     'email': 'newbie@example.com',
                                     'password': 'foo',
                                     'password2': 'foo'}, follow=True)
        self.assertContains(response, 'already exists')

    def test_duplicate_email(self):
        User.objects.create(username='noob', email='noob@example.com').save()
        response = self.client.post(reverse('users.register'),
                                    {'username': 'newbie',
                                     'email': 'noob@example.com',
                                     'password': 'foo',
                                     'password2': 'foo'}, follow=True)
        self.assertContains(response, 'already exists')

    def test_no_match_passwords(self):
        response = self.client.post(reverse('users.register'),
                                    {'username': 'newbie',
                                     'email': 'newbie@example.com',
                                     'password': 'foo',
                                     'password2': 'bar'}, follow=True)
        self.assertContains(response, 'must match')


class ReminderEmailTestCase(TestCase):
    fixtures = ['test_users.json']

    def setUp(self):
        self.client = LocalizingClient()

    @mock.patch_object(Site.objects, 'get_current')
    def test_reminder_email(self, get_current):
        """Should send simple email reminder to user."""
        get_current.return_value.domain = 'dev.mo.org'

        response = self.client.post(reverse('users.send_email_reminder'),
                                    {'username': 'testuser'},
                                    follow=True)
        eq_(200, response.status_code)
        eq_(1, len(mail.outbox))
        email = mail.outbox[0]
        assert email.subject.find('Email Address Reminder') == 0
        assert 'testuser' in email.body

    @mock.patch_object(Site.objects, 'get_current')
    def test_unknown_user_no_email_sent(self, get_current):
        """Should send simple email reminder to user."""
        get_current.return_value.domain = 'dev.mo.org'

        response = self.client.post(reverse('users.send_email_reminder'),
                                    {'username': 'testuser404'},
                                    follow=True)
        eq_(200, response.status_code)
        eq_(0, len(mail.outbox))

    @mock.patch_object(Site.objects, 'get_current')
    def test_user_without_email_message(self, get_current):
        """Should send simple email reminder to user."""
        get_current.return_value.domain = 'dev.mo.org'

        u = User.objects.get(username='testuser')
        u.email = ''
        u.save()

        response = self.client.post(reverse('users.send_email_reminder'),
                                    {'username': 'testuser'},
                                    follow=True)
        eq_(200, response.status_code)
        eq_(0, len(mail.outbox))
        ok_('Could not find email' in response.content)
        ok_('file a bug' in response.content)


class ChangeEmailTestCase(TestCase):
    fixtures = ['test_users.json']

    def setUp(self):
        self.client = LocalizingClient()

    @mock.patch_object(Site.objects, 'get_current')
    def test_user_change_email(self, get_current):
        """Send email to change user's email and then change it."""
        get_current.return_value.domain = 'su.mo.com'

        self.client.login(username='testuser', password='testpass')
        # Attempt to change email.
        response = self.client.post(reverse('users.change_email'),
                                    {'email': 'paulc@trololololololo.com'},
                                    follow=True)
        eq_(200, response.status_code)

        # Be notified to click a confirmation link.
        eq_(1, len(mail.outbox))
        assert mail.outbox[0].subject.find('Please confirm your') == 0
        ec = EmailChange.objects.all()[0]
        assert ec.activation_key in mail.outbox[0].body
        eq_('paulc@trololololololo.com', ec.email)

        # Visit confirmation link to change email.
        response = self.client.get(reverse('users.confirm_email',
                                           args=[ec.activation_key]))
        eq_(200, response.status_code)
        u = User.objects.get(username='testuser')
        eq_('paulc@trololololololo.com', u.email)

    def test_user_change_email_same(self):
        """Changing to same email shows validation error."""
        self.client.login(username='testuser', password='testpass')
        user = User.objects.get(username='testuser')
        user.email = 'valid@email.com'
        user.save()
        response = self.client.post(reverse('users.change_email'),
                                    {'email': user.email})
        eq_(200, response.status_code)
        doc = pq(response.content)
        eq_('This is your current email.', doc('ul.errorlist').text())

    def test_user_change_email_duplicate(self):
        """Changing to same email shows validation error."""
        self.client.login(username='testuser', password='testpass')
        email = 'testuser2@test.com'
        response = self.client.post(reverse('users.change_email'),
                                    {'email': email})
        eq_(200, response.status_code)
        doc = pq(response.content)
        eq_('A user with that email address already exists.',
            doc('ul.errorlist').text())

    @mock.patch_object(Site.objects, 'get_current')
    def test_user_confirm_email_duplicate(self, get_current):
        """If we detect a duplicate email when confirming an email change,
        don't change it and notify the user."""
        get_current.return_value.domain = 'su.mo.com'
        self.client.login(username='testuser', password='testpass')
        old_email = User.objects.get(username='testuser').email
        new_email = 'newvalid@email.com'
        response = self.client.post(reverse('users.change_email'),
                                    {'email': new_email})
        eq_(200, response.status_code)
        assert mail.outbox[0].subject.find('Please confirm your') == 0
        ec = EmailChange.objects.all()[0]

        # Before new email is confirmed, give the same email to a user
        other_user = User.objects.filter(username='testuser2')[0]
        other_user.email = new_email
        other_user.save()

        # Visit confirmation link and verify email wasn't changed.
        response = self.client.get(reverse('users.confirm_email',
                                           args=[ec.activation_key]))
        eq_(200, response.status_code)
        doc = pq(response.content)
        eq_('Unable to change email for user testuser',
            doc('.main h1').text())
        u = User.objects.get(username='testuser')
        eq_(old_email, u.email)


class BrowserIDTestCase(TestCase):
    fixtures = ['test_users.json']

    def setUp(self):
        # Ensure @ssl_required goes unenforced.
        settings.DEBUG = True
        # Set up some easily-testable redirects.
        settings.LOGIN_REDIRECT_URL = 'SUCCESS'
        settings.LOGIN_REDIRECT_URL_FAILURE = 'FAILURE'
        # BrowserID will squawk if this isn't set
        settings.SITE_URL = 'http://testserver'
        self.client = LocalizingClient()

    def test_invalid_post(self):
        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'))
        eq_(302, resp.status_code)
        ok_('FAILURE' in resp['Location'])

    @mock.patch('users.views._verify_browserid')
    def test_invalid_assertion(self, _verify_browserid):
        _verify_browserid.return_value = None

        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'bad data'})
        eq_(302, resp.status_code)
        ok_('FAILURE' in resp['Location'])

    @mock.patch('users.views._verify_browserid')
    def test_valid_assertion_with_django_user(self, _verify_browserid):
        _verify_browserid.return_value = {'email': 'testuser2@test.com'}

        # Posting the fake assertion to browserid_verify should work, with the
        # actual verification method mocked out.
        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_(302, resp.status_code)
        ok_('SUCCESS' in resp['Location'])

        # The session should look logged in, now.
        ok_('_auth_user_id' in self.client.session.keys())
        eq_('django_browserid.auth.BrowserIDBackend',
            self.client.session.get('_auth_user_backend', ''))

    @mock.patch('users.views._verify_browserid')
    def test_explain_popup(self, _verify_browserid):
        _verify_browserid.return_value = {'email': 'testuser2@test.com'}
        resp = self.client.get(reverse('home', locale='en-US'))

        # Posting the fake assertion to browserid_verify should work, with the
        # actual verification method mocked out.
        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_('1', resp.cookies.get('browserid_explained').value)

        resp = self.client.get(reverse('users.logout'), locale='en-US')

        # even after logout, cookie should prevent the toggle
        resp = self.client.get(reverse('home', locale='en-US'))
        eq_('1', self.client.cookies.get('browserid_explained').value)

    @mock.patch('users.views._verify_browserid')
    def test_valid_assertion_with_new_account_creation(self,
                                                       _verify_browserid):
        new_username = 'neverbefore'
        new_email = 'never.before.seen@example.com'
        _verify_browserid.return_value = {'email': new_email}

        try:
            user = User.objects.get(email=new_email)
            ok_(False, "User for email should not yet exist")
        except User.DoesNotExist:
            pass

        # Sign in with a verified email, but with no existing account
        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_(302, resp.status_code)

        # This should be a redirect to the BrowserID registration page.
        redir_url = resp['Location']
        reg_url = reverse('users.browserid_register', locale='en-US')
        ok_(reg_url in redir_url)

        # And, as part of the redirect, the verified email address should be in
        # our session now.
        ok_(SESSION_VERIFIED_EMAIL in self.client.session.keys())
        verified_email = self.client.session[SESSION_VERIFIED_EMAIL]
        eq_(new_email, verified_email)

        # Grab the redirect, assert that there's a create_user form present
        resp = self.client.get(redir_url)
        page = pq(resp.content)
        form = page.find('form#create_user')
        eq_(1, form.length)

        # There should be no error lists on first load
        eq_(0, page.find('.errorlist').length)

        # Submit the create_user form, with a chosen username
        resp = self.client.post(redir_url, {'username': 'neverbefore',
                                            'action': 'register'})

        # The submission should result in a redirect to the session's redirect
        # value
        eq_(302, resp.status_code)
        redir_url = resp['Location']
        ok_('SUCCESS' in redir_url)

        # The session should look logged in, now.
        ok_('_auth_user_id' in self.client.session.keys())
        eq_('django_browserid.auth.BrowserIDBackend',
            self.client.session.get('_auth_user_backend', ''))

        # Ensure that the user was created, and with the submitted username and
        # verified email address
        try:
            user = User.objects.get(email=new_email)
            eq_(new_username, user.username)
            eq_(new_email, user.email)
        except User.DoesNotExist:
            ok_(False, "New user should have been created")
    
    @mock.patch('users.views._verify_browserid')
    def test_valid_assertion_with_existing_account_login(self,
                                                         _verify_browserid):
        """ Removed the existing user form: we don't auth the password with
        MindTouch anymore """
        new_email = 'mynewemail@example.com'
        _verify_browserid.return_value = {'email': new_email}

        try:
            User.objects.get(email=new_email)
            ok_(False, "User for email should not yet exist")
        except User.DoesNotExist:
            pass

        # Sign in with a verified email, but with no existing account
        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_(302, resp.status_code)

        # This should be a redirect to the BrowserID registration page.
        redir_url = resp['Location']
        reg_url = reverse('users.browserid_register', locale='en-US')
        ok_(reg_url in redir_url)

        # And, as part of the redirect, the verified email address should be in
        # our session now.
        ok_(SESSION_VERIFIED_EMAIL in self.client.session.keys())
        verified_email = self.client.session[SESSION_VERIFIED_EMAIL]
        eq_(new_email, verified_email)

        # Grab the redirect, assert that there's a create_user form present
        resp = self.client.get(redir_url)
        page = pq(resp.content)
        form = page.find('form#existing_user')
        eq_(0, form.length)

    @mock.patch('users.views._verify_browserid')
    def test_mindtouch_disabled_redirect_login(self, _verify_browserid):
        """When DEKIWIKI_ENDPOINT unavailable, skip MindTouch auth."""
        _verify_browserid.return_value = {'email': 'testuser2@test.com'}

        resp = self.client.post(reverse('users.browserid_verify',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})

        eq_(302, resp.status_code)
        ok_('SUCCESS' in resp['Location'])

        # The session should look logged in, now.
        ok_('_auth_user_id' in self.client.session.keys())
        eq_('django_browserid.auth.BrowserIDBackend',
            self.client.session.get('_auth_user_backend', ''))

    @mock.patch('users.views._verify_browserid')
    def test_valid_assertion_changing_email(self, _verify_browserid):
        # just need to be authenticated, not necessarily BrowserID
        self.client.login(username='testuser', password='testpass')

        _verify_browserid.return_value = {'email': 'testuser+changed@test.com'}

        resp = self.client.post(reverse('users.browserid_change_email',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_(302, resp.status_code)
        ok_('profiles/testuser/edit' in resp['Location'])

        resp = self.client.get(reverse('devmo_profile_edit', locale='en-US',
                                       args=['testuser', ]))
        eq_(200, resp.status_code)
        doc = pq(resp.content)
        ok_('testuser+changed@test.com' in doc.find('li#field_email').text())

    @mock.patch('users.views._verify_browserid')
    def test_valid_assertion_doesnt_steal_email(self, _verify_browserid):
        # just need to be authenticated, not necessarily BrowserID
        self.client.login(username='testuser', password='testpass')

        _verify_browserid.return_value = {'email': 'testuser2@test.com'}

        # doesn't change email if the new email already belongs to another user
        resp = self.client.post(reverse('users.browserid_change_email',
                                        locale='en-US'),
                                {'assertion': 'PRETENDTHISISVALID'})
        eq_(302, resp.status_code)
        ok_('change_email' in resp['Location'])

        resp = self.client.get(reverse('devmo_profile_edit', locale='en-US',
                                       args=['testuser', ]))
        eq_(200, resp.status_code)
        doc = pq(resp.content)
        ok_('testuser@test.com' in doc.find('li#field_email').text())


class OldProfileTestCase(TestCase):
    fixtures = ['test_users.json']

    def test_old_profile_url_gone(self):
        resp = self.client.get('/users/edit', follow=True)
        eq_(404, resp.status_code)
