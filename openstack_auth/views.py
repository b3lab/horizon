# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime
import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth import views as django_auth_views
from django.contrib import messages
from django import http as django_http
from django import shortcuts
from django.urls import reverse
from django.utils import functional
from django.utils import http
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import edit as edit_views
from keystoneauth1 import exceptions as keystone_exceptions

from openstack_auth import exceptions
from openstack_auth import forms
from openstack_auth import plugin

# This is historic and is added back in to not break older versions of
# Horizon, fix to Horizon to remove this requirement was committed in
# Juno
# pylint: disable=unused-import
from openstack_auth.forms import Login  # noqa:F401
from openstack_auth import user as auth_user
from openstack_auth import utils

from openstack_user_manager.manager import OpenstackUserManager
from safir_email_notifier.email_builder import EmailBuilder
from safir_email_notifier.email_notifier import EmailNotifier

from itsdangerous import URLSafeTimedSerializer
import random
import string
import unicodedata
from openstack_auth import univs

LOG = logging.getLogger(__name__)


# TODO(stephenfin): Migrate to CBV
@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """Logs a user in using the :class:`~openstack_auth.forms.Login` form."""

    # If the user enabled websso and the default redirect
    # redirect to the default websso url
    if (request.method == 'GET' and utils.is_websso_enabled and
            utils.is_websso_default_redirect()):
        protocol = utils.get_websso_default_redirect_protocol()
        region = utils.get_websso_default_redirect_region()
        origin = utils.build_absolute_uri(request, '/auth/websso/')
        url = ('%s/auth/OS-FEDERATION/websso/%s?origin=%s' %
               (region, protocol, origin))
        return shortcuts.redirect(url)

    # If the user enabled websso and selects default protocol
    # from the dropdown, We need to redirect user to the websso url
    if request.method == 'POST':
        auth_type = request.POST.get('auth_type', 'credentials')
        request.session['auth_type'] = auth_type
        if utils.is_websso_enabled() and auth_type != 'credentials':
            region_id = request.POST.get('region')
            auth_url = getattr(settings, 'WEBSSO_KEYSTONE_URL', None)
            if auth_url is None:
                auth_url = forms.get_region_endpoint(region_id)
            url = utils.get_websso_url(request, auth_url, auth_type)
            return shortcuts.redirect(url)

    if not request.is_ajax():
        # If the user is already authenticated, redirect them to the
        # dashboard straight away, unless the 'next' parameter is set as it
        # usually indicates requesting access to a page that requires different
        # permissions.
        if (request.user.is_authenticated and
                auth.REDIRECT_FIELD_NAME not in request.GET and
                auth.REDIRECT_FIELD_NAME not in request.POST):
            return shortcuts.redirect(settings.LOGIN_REDIRECT_URL)

    # Get our initial region for the form.
    initial = {}
    current_region = request.session.get('region_endpoint', None)
    requested_region = request.GET.get('region', None)
    regions = dict(settings.AVAILABLE_REGIONS)
    if requested_region in regions and requested_region != current_region:
        initial.update({'region': requested_region})

    if request.method == "POST":
        form = functional.curry(forms.Login)
    else:
        form = functional.curry(forms.Login, initial=initial)

    choices = settings.WEBSSO_CHOICES
    extra_context = {
        'redirect_field_name': auth.REDIRECT_FIELD_NAME,
        'csrf_failure': request.GET.get('csrf_failure'),
        'show_sso_opts': utils.is_websso_enabled() and len(choices) > 1,
    }

    if request.is_ajax():
        template_name = 'auth/_login.html'
        extra_context['hide'] = True
    else:
        template_name = 'auth/login.html'

    try:
        res = django_auth_views.LoginView.as_view(
            template_name=template_name,
            redirect_field_name=auth.REDIRECT_FIELD_NAME,
            form_class=form,
            extra_context=extra_context,
            redirect_authenticated_user=False)(request)
    except exceptions.KeystonePassExpiredException as exc:
        res = django_http.HttpResponseRedirect(
            reverse('password', args=[exc.user_id]))
        msg = _("Your password has expired. Please set a new password.")
        res.set_cookie('logout_reason', msg, max_age=10)

    # Save the region in the cookie, this is used as the default
    # selected region next time the Login form loads.
    if request.method == "POST":
        utils.set_response_cookie(res, 'login_region',
                                  request.POST.get('region', ''))
        utils.set_response_cookie(res, 'login_domain',
                                  request.POST.get('domain', ''))

    # Set the session data here because django's session key rotation
    # will erase it if we set it earlier.
    if request.user.is_authenticated:
        auth_user.set_session_from_user(request, request.user)
        regions = dict(forms.get_region_choices())
        region = request.user.endpoint
        login_region = request.POST.get('region')
        region_name = regions.get(login_region)
        request.session['region_endpoint'] = region
        request.session['region_name'] = region_name
        expiration_time = request.user.time_until_expiration()
        threshold_days = settings.PASSWORD_EXPIRES_WARNING_THRESHOLD_DAYS
        if (expiration_time is not None and
                expiration_time.days <= threshold_days and
                expiration_time > datetime.timedelta(0)):
            expiration_time = str(expiration_time).rsplit(':', 1)[0]
            msg = (_('Please consider changing your password, it will expire'
                     ' in %s minutes') %
                   expiration_time).replace(':', ' Hours and ')
            messages.warning(request, msg)
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            conn = OpenstackUserManager(settings.CLOUD_CONFIG_NAME)
            project_id = conn.get_project_from_user(
                role_name=settings.OPENSTACK_KEYSTONE_DEFAULT_ROLE,
                user_name=username)
#            if project_id:
#                customer_status =  conn.get_billing_customer_status(project_id)
#                if customer_status in ('SUSPENSION_STARTED',
#                                       'SUSPENDED',
#                                       'SUSPENSION_FAILED'):
#                    termination_date = conn.get_customer_termination_date(project_id)
#                    return shortcuts.render(
#                        request, 'auth/suspended.html',
#                        {'termination_date': termination_date})
#                elif customer_status in ('TERMINATION_STARTED',
#                                         'TERMINATED',
#                                         'TERMINATION_FAILED'):
#                    return shortcuts.render(
#                        request, 'auth/terminated.html')
    return res


# TODO(stephenfin): Migrate to CBV
@sensitive_post_parameters()
@csrf_exempt
@never_cache
def websso(request):
    """Logs a user in using a token from Keystone's POST."""
    referer = request.META.get('HTTP_REFERER', settings.OPENSTACK_KEYSTONE_URL)
    auth_url = utils.clean_up_auth_url(referer)
    token = request.POST.get('token')
    try:
        request.user = auth.authenticate(request, auth_url=auth_url,
                                         token=token)
    except exceptions.KeystoneAuthException as exc:
        if utils.is_websso_default_redirect():
            res = django_http.HttpResponseRedirect(settings.LOGIN_ERROR)
        else:
            msg = 'Login failed: %s' % exc
            res = django_http.HttpResponseRedirect(settings.LOGIN_URL)
            res.set_cookie('logout_reason', msg, max_age=10)
        return res

    auth_user.set_session_from_user(request, request.user)
    auth.login(request, request.user)
    if request.session.test_cookie_worked():
        request.session.delete_test_cookie()
    return django_http.HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)


# TODO(stephenfin): Migrate to CBV
def logout(request, login_url=None, **kwargs):
    """Logs out the user if he is logged in. Then redirects to the log-in page.

    :param login_url:
        Once logged out, defines the URL where to redirect after login

    :param kwargs:
        see django.contrib.auth.views.logout_then_login extra parameters.

    """
    msg = 'Logging out user "%(username)s".' % \
        {'username': request.user.username}
    LOG.info(msg)

    """ Securely logs a user out. """
    if (utils.is_websso_enabled and utils.is_websso_default_redirect() and
            utils.get_websso_default_redirect_logout()):
        auth_user.unset_session_user_variables(request)
        return django_http.HttpResponseRedirect(
            utils.get_websso_default_redirect_logout())
    else:
        return django_auth_views.logout_then_login(request,
                                                   login_url=login_url,
                                                   **kwargs)


# TODO(stephenfin): Migrate to CBV
@login_required
def switch(request, tenant_id, redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches an authenticated user from one project to another."""
    LOG.debug('Switching to tenant %s for user "%s".',
              tenant_id, request.user.username)

    endpoint, __ = utils.fix_auth_url_version_prefix(request.user.endpoint)
    session = utils.get_session()
    # Keystone can be configured to prevent exchanging a scoped token for
    # another token. Always use the unscoped token for requesting a
    # scoped token.
    unscoped_token = request.user.unscoped_token
    auth = utils.get_token_auth_plugin(auth_url=endpoint,
                                       token=unscoped_token,
                                       project_id=tenant_id)

    try:
        auth_ref = auth.get_access(session)
        msg = 'Project switch successful for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.info(msg)
    except keystone_exceptions.ClientException:
        msg = (
            _('Project switch failed for user "%(username)s".') %
            {'username': request.user.username})
        messages.error(request, msg)
        auth_ref = None
        LOG.exception('An error occurred while switching sessions.')

    # Ensure the user-originating redirection url is safe.
    # Taken from django.contrib.auth.views.login()
    redirect_to = request.GET.get(redirect_field_name, '')
    if not http.is_safe_url(url=redirect_to,
                            allowed_hosts=[request.get_host()]):
        redirect_to = settings.LOGIN_REDIRECT_URL

    if auth_ref:
        user = auth_user.create_user_from_token(
            request,
            auth_user.Token(auth_ref, unscoped_token=unscoped_token),
            endpoint)
        auth_user.set_session_from_user(request, user)
        message = (
            _('Switch to project "%(project_name)s" successful.') %
            {'project_name': request.user.project_name})
        messages.success(request, message)
    response = shortcuts.redirect(redirect_to)
    utils.set_response_cookie(response, 'recent_project',
                              request.user.project_id)
    return response


# TODO(stephenfin): Migrate to CBV
@login_required
def switch_region(request, region_name,
                  redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches the user's region for all services except Identity service.

    The region will be switched if the given region is one of the regions
    available for the scoped project. Otherwise the region is not switched.
    """
    if region_name in request.user.available_services_regions:
        request.session['services_region'] = region_name
        LOG.debug('Switching services region to %s for user "%s".',
                  region_name, request.user.username)

    redirect_to = request.GET.get(redirect_field_name, '')
    if not http.is_safe_url(url=redirect_to,
                            allowed_hosts=[request.get_host()]):
        redirect_to = settings.LOGIN_REDIRECT_URL

    response = shortcuts.redirect(redirect_to)
    utils.set_response_cookie(response, 'services_region',
                              request.session['services_region'])
    return response


# TODO(stephenfin): Migrate to CBV
@login_required
def switch_keystone_provider(request, keystone_provider=None,
                             redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches the user's keystone provider using K2K Federation

    If keystone_provider is given then we switch the user to
    the keystone provider using K2K federation. Otherwise if keystone_provider
    is None then we switch the user back to the Identity Provider Keystone
    which a non federated token auth will be used.
    """
    base_token = request.session.get('k2k_base_unscoped_token', None)
    k2k_auth_url = request.session.get('k2k_auth_url', None)
    keystone_providers = request.session.get('keystone_providers', None)
    recent_project = request.COOKIES.get('recent_project')

    if not base_token or not k2k_auth_url:
        msg = _('K2K Federation not setup for this session')
        raise exceptions.KeystoneAuthException(msg)

    redirect_to = request.GET.get(redirect_field_name, '')
    if not http.is_safe_url(url=redirect_to,
                            allowed_hosts=[request.get_host()]):
        redirect_to = settings.LOGIN_REDIRECT_URL

    unscoped_auth_ref = None
    keystone_idp_id = settings.KEYSTONE_PROVIDER_IDP_ID

    if keystone_provider == keystone_idp_id:
        current_plugin = plugin.TokenPlugin()
        unscoped_auth = current_plugin.get_plugin(auth_url=k2k_auth_url,
                                                  token=base_token)
    else:
        # Switch to service provider using K2K federation
        plugins = [plugin.TokenPlugin()]
        current_plugin = plugin.K2KAuthPlugin()

        unscoped_auth = current_plugin.get_plugin(
            auth_url=k2k_auth_url, service_provider=keystone_provider,
            plugins=plugins, token=base_token, recent_project=recent_project)

    try:
        # Switch to identity provider using token auth
        unscoped_auth_ref = current_plugin.get_access_info(unscoped_auth)
    except exceptions.KeystoneAuthException as exc:
        msg = 'Switching to Keystone Provider %s has failed. %s' \
              % (keystone_provider, exc)
        messages.error(request, msg)

    if unscoped_auth_ref:
        try:
            request.user = auth.authenticate(
                request, auth_url=unscoped_auth.auth_url,
                token=unscoped_auth_ref.auth_token)
        except exceptions.KeystoneAuthException as exc:
            msg = 'Keystone provider switch failed: %s' % exc
            res = django_http.HttpResponseRedirect(settings.LOGIN_URL)
            res.set_cookie('logout_reason', msg, max_age=10)
            return res
        auth.login(request, request.user)
        auth_user.set_session_from_user(request, request.user)
        request.session['keystone_provider_id'] = keystone_provider
        request.session['keystone_providers'] = keystone_providers
        request.session['k2k_base_unscoped_token'] = base_token
        request.session['k2k_auth_url'] = k2k_auth_url
        message = (
            _('Switch to Keystone Provider "%(keystone_provider)s" '
              'successful.') % {'keystone_provider': keystone_provider})
        messages.success(request, message)

    response = shortcuts.redirect(redirect_to)
    return response

@sensitive_post_parameters()
@csrf_exempt
@never_cache
def register(request):
    form = forms.Register()

    if request.method == 'POST':

        registered = ''
        form = forms.Register(request.POST)
        if form.is_valid():

            registered = 'OK'
            univ = request.POST.get('university')
            name = request.POST.get('name')
            #name = unicodedata.normalize('NFKD',
            #    name).encode('ascii','ignore')
            email = request.POST.get('email')
            username = email
            projectname = email
            projectdescription = name
            password = request.POST.get('password')
            repassword = request.POST.get('retype_password')
            researcharea = request.POST.get('research_area')
#            researcharea = unicodedata.normalize('NFKD',
#                 researcharea).encode('ascii','ignore')

            UNIVS_D = {k: v for k, v in univs.UNIV_CHOICES}
            univ_name = UNIVS_D[univ]

            try:
                client_address = request.META['HTTP_X_FORWARDED_FOR']
            except Exception:
                client_address = request.META['REMOTE_ADDR']

            LOG.info("New user registeration request for " +
                     email + " from " + client_address)

            LOG.info("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSASAS")

            if not (projectname and univ and password and repassword):
                registered = 'empty_fields'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not (password == repassword):
                registered = 'passwords_not_match'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not (len(password) >= 6):
                registered = 'passwords_too_weak'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            mailerror = True
            for univ_mail in univ.split(','):
                if univ_mail in email:
                    mailerror = False
            if mailerror:
                registered = 'univ_mail_not_used'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            conn = OpenstackUserManager(settings.CLOUD_CONFIG_NAME)
            if not conn.check_username_availability(username):
                registered = 'user_in_use'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            project_properties = {'university': univ_name,
                                  'research_area': researcharea,
                                  'email': email}
            if not conn.create_project(projectdescription, projectname,
                                      project_properties):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.create_user(email, username, password):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

#            if not conn.init_billing_customer(projectname,
#                                              projectdescription,
#                                              univ_name,
#                                              email):
#                LOG.error('Billing customer could not be added!')

            default_role_name = settings.OPENSTACK_KEYSTONE_DEFAULT_ROLE
            if default_role_name is None:
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.pair_user_with_project(username, projectname,
                                               default_role_name):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.init_network(projectname,
                                     settings.OPENSTACK_EXT_NET,
                                     settings.OPENSTACK_DNS_NAMESERVERS,
                                     settings.OPENSTACK_DEFAULT_SUBNET_CIDR,
                                     settings.OPENSTACK_DEFAULT_GATEWAY_IP):
                LOG.warning('Network could not be initialized for project ' +
                            projectname + '.')

            if not conn.add_ssh_rule(projectname):
                LOG.warning('SSH security rule could not be added ' +
                            projectname + '.')

            send_confirmation_mail(email, name)
    else:
        registered = ''
    return shortcuts.render(
        request, 'auth/register.html',
        {'registered': registered, 'form': form})


def generate_confirmation_token(secret):
    serializer = URLSafeTimedSerializer(settings.TOKEN_SECRET_KEY)
    return serializer.dumps(secret,
                            salt=settings.TOKEN_SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(settings.TOKEN_SECRET_KEY)
    try:
        secret = serializer.loads(
            token,
            salt=settings.TOKEN_SECURITY_PASSWORD_SALT,
            max_age=expiration
        )
    except Exception:
        return False
    return secret


def confirm_mail(request, token):
    email = confirm_token(token)

    if email is False:
        return shortcuts.render(
            request, 'auth/activation.html',
            {'activation': 'FAIL'})

    conn = OpenstackUserManager(settings.CLOUD_CONFIG_NAME)
    projectname = email
    username = email

#    if check_old_customer(conn, projectname):
#        # enable user
#        activation = 'OK'
#        if not conn.update_project_status(projectname, True):
#            activation = 'openstack_error'
#        if not conn.update_user_status(username, True):
#            activation = 'openstack_error',
#    else:
#        activation = 'failed'
    activation = 'OK'

#    if not conn.update_project_status(projectname, True):
#        activation = 'openstack_error'
#    if not conn.update_user_status(username, True):
#        activation = 'openstack_error'
    # TODO(ecelik): send_success_mail(username, email)
    return shortcuts.render(
        request, 'auth/activation.html',
        {'activation': activation})

#def check_old_customer(conn, project_name):
#    project = conn.get_project(project_name)
#    if project:
#        customer_status = conn.get_billing_customer_status(project.id)
#        if customer_status == 'SUSPENDED' or \
#           customer_status == 'TERMINATED':
#            return False
#        try:
#            customer_status = conn.get_billing_customer_status(project.id)
#            if customer_status == 'SUSPENDED' or \
#               customer_status == 'TERMINATED':
#                return False
#        except:
#            pass
#    return True

def forgot_password(request):
    form = forms.ForgotPassword()
    password_reset = ''

    if request.method == 'POST':
        form = forms.ForgotPassword(request.POST)
        if form.is_valid():
            email = request.POST.get('email')

            conn = OpenstackUserManager(settings.CLOUD_CONFIG_NAME)
            if conn.check_username_availability(email):
                return shortcuts.render(
                        request, 'auth/forgot_password.html',
                        {'password_reset': 'user_not_found',
                         'form': form})

            s = string.lowercase + string.digits
            randpassword = ''.join(random.sample(s, 10))

            if not conn.update_user_password(email, randpassword):
                return shortcuts.render(
                    request, 'auth/forgot_password.html',
                    {'password_reset': 'FAIL', 'form': form})

            send_reset_password_mail(email, randpassword)
            password_reset = 'OK'

    return shortcuts.render(
            request, 'auth/forgot_password.html',
            {'password_reset': password_reset, 'form': form})


def resend_confirm_mail(request, email):

    username = email

    conn = OpenstackUserManager(settings.CLOUD_CONFIG_NAME)
    if conn.check_username_availability(username):
        LOG.warning("User not exist in OpenStack: Username: " + username)
        return shortcuts.render(
            request, 'auth/activation.html',
            {'activation': 'FAIL'})

    LOG.info("Sending confirmation e-mail to " + email)

    send_confirmation_mail(email)
    return django_http.HttpResponseRedirect(settings.LOGIN_URL)


def send_confirmation_mail(email, contact_name=None):

    confirmation_token = generate_confirmation_token(email)
    confirm_url = "http:\/\/" + settings.DOMAIN_URL + "auth/confirm_mail/"
    confirm_url = confirm_url + confirmation_token

    from_email = settings.EMAIL_HOST_USER
    to_list = [email, from_email]

    if contact_name is None:
        contact_name = email
    try:
        mail_data = {'name': contact_name,
                     'link': confirm_url}
        mail_builder = EmailBuilder('user_activation')
        subject, text, html = mail_builder.get_mail_content(mail_data)
        mail_notifier = EmailNotifier(settings.EMAIL_HOST,
                                      settings.EMAIL_PORT,
                                      settings.EMAIL_HOST_USER,
                                      settings.EMAIL_HOST_PASSWORD)
        mail_notifier.send_mail(to_list, subject, text, html)

        LOG.info("Confirmation email sent successfully.")
    except Exception as ex:
        LOG.error("Confirmation email not sent. " + ex.message)
    return


def send_reset_password_mail(email, password):
    url = "http:\/\/" + settings.DOMAIN_URL

    from_email = settings.EMAIL_HOST_USER
    to_list = [email, from_email]

    try:
        mail_data = {'name': email,
                     'new_password': password,
                     'link': url}
        mail_builder = EmailBuilder('reset_password')
        subject, text, html = mail_builder.get_mail_content(mail_data)
        mail_notifier = EmailNotifier(settings.EMAIL_HOST,
                                      settings.EMAIL_PORT,
                                      settings.EMAIL_HOST_USER,
                                      settings.EMAIL_HOST_PASSWORD)
        mail_notifier.send_mail(to_list, subject, text, html)

        LOG.info("Reset password email sent successfully.")
    except Exception as ex:
        LOG.error("Reset password email not sent. " + ex.message)

def credit_load(request):
    return shortcuts.render(
        request, 'auth/creditload.html')


def report_template(request):
    with open(settings.RESEARCH_REPORT_TEMPLATE, 'r') as doc:
        response = django_http.HttpResponse(doc.read(),
            content_type='application/vnd.openxmlformats-officedocument.\
            wordprocessingml.document')
        response['Content-Disposition'] = 'inline;' + \
            'filename=SafirBulutReport.doc'
        return response


def terms_and_conditions(request):
    with open(settings.USER_AGREEMENT_FILE, 'r') as pdf:
        response = django_http.HttpResponse(pdf.read(),
                                            content_type='application/pdf')
        response['Content-Disposition'] = 'inline;' + \
            'filename=UserAgreement.pdf'
        return response

class PasswordView(edit_views.FormView):
    """Changes user's password when it's expired or otherwise inaccessible."""
    template_name = 'auth/password.html'
    form_class = forms.Password
    success_url = settings.LOGIN_URL

    def get_initial(self):
        return {'user_id': self.kwargs['user_id']}

    def form_valid(self, form):
        # We have no session here, so regular messages don't work.
        msg = _('Password changed. Please log in to continue.')
        res = django_http.HttpResponseRedirect(self.success_url)
        res.set_cookie('logout_reason', msg, max_age=10)
        return res
