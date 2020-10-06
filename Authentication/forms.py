import base64

import jwt
import phonenumbers

from authy.api import AuthyApiClient
from django import forms
from django.conf import settings
from phonenumbers.phonenumberutil import NumberParseException

from .models import User

authy_api = AuthyApiClient(settings.ACCOUNT_SECURITY_API_KEY)


class BootstrapInput(forms.TextInput):
    def __init__(self, placeholder, size=12, *args, **kwargs):
        self.size = size
        super(BootstrapInput, self).__init__(attrs={
            'class': 'form-control input-sm',
            'placeholder': placeholder
        })

    def bootwrap_input(self, input_tag):
        classes = 'col-xs-{n} col-                  sm-{n} col-md-{n}'.format(n=self.size)

        return '''<div class="{classes}">
                    <div class="form-group">{input_tag}</div>
                  </div>
               '''.format(classes=classes, input_tag=input_tag)

    def render(self, *args, **kwargs):
        input_tag = super(BootstrapInput, self).render(*args, **kwargs)
        return self.bootwrap_input(input_tag)



class RegistrationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'email')
        widgets = {
            'username': BootstrapInput('User Name'),
            'email': BootstrapInput('Email Address'),
        }

    country_code = forms.CharField(
        widget=BootstrapInput('Country Code', size=6))
    phone_number = forms.CharField(
        widget=BootstrapInput('Phone Number', size=6))

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=encrypt(username)).exists():
            self.add_error('username', 'Username is already taken')
        return username

    def clean_phone_number(self):
        phone_number = self.cleaned_data['phone_number']
        if User.objects.filter(phone_number=encrypt(phone_number)):
            self.add_error('phone_number','Phone number is already taken')
        return phone_number

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=encrypt(email)):
            self.add_error('email','Email is already taken')
        return email

    def clean_country_code(self):
        country_code = self.cleaned_data['country_code']
        if not country_code.startswith('+'):
            country_code = '+' + country_code
        return country_code

    def clean(self):
        data = self.cleaned_data
        username=data['username']
        email=data['email']
        print(data['country_code'],data['phone_number'])
        phone_number = data['country_code'] + data['phone_number']
        try:
            phone_number = phonenumbers.parse(phone_number, None)
            if not phonenumbers.is_valid_number(phone_number):
                self.add_error('phone_number', 'Invalid phone number')
            else:
                username=base64.b16encode(username.encode('utf-8'))
                email=base64.b16encode(email.encode('utf-8'))
                phone_number=base64.b16encode(str(phone_number).encode('utf-8'))
        except NumberParseException as e:
            self.add_error('phone_number', e)


class TokenVerificationForm(forms.Form):
    token = forms.CharField(
        required=True,
        widget=BootstrapInput('Token via SMS, Voice or SoftToken')
    )
    email_token = forms.CharField(
        required=True,
        widget=BootstrapInput('Token via Email, Voice or SoftToken')
    )

    def is_valid(self, authy_id):
        self.authy_id = authy_id
        return super(TokenVerificationForm, self).is_valid()

    def clean(self):
        token = self.cleaned_data['token']
        email_token = self.cleaned_data['email_token']
        try:
            payload = jwt.decode(email_token,settings.SECRET_KEY)
            user=User.objects.get(id=payload['user_id'])
            if user:
                verification = authy_api.tokens.verify(self.authy_id, token)
            if not verification.ok():
                self.add_error('token', 'Invalid token')
        except jwt.InvalidSignatureError:
            self.add_error('email_token',"Invalid email_token")
        except jwt.DecodeError:
            self.add_error('email_token', "Invalid email_token")
        except jwt.ExpiredSignatureError:
            self.add_error('email_token', "Expired email_token")


class LoginForm(forms.Form):

    country_code = forms.CharField(
        widget=BootstrapInput('Country Code', size=6))
    phone_number = forms.CharField(
        widget=BootstrapInput('Phone Number', size=6))

    def clean_country_code(self):
        country_code = self.cleaned_data['country_code']
        if not country_code.startswith('+'):
            country_code = '+' + country_code
        return country_code

    def clean(self):
        data = self.cleaned_data
        phone_number = data['country_code'] + data['phone_number']
        try:
            if not User.objects.filter(phone_number=encrypt(data['phone_number'])).exists():
                self.add_error('phone_number','User phone number not exists')
            phone_number = phonenumbers.parse(phone_number, None)
            if not phonenumbers.is_valid_number(phone_number):
                self.add_error('phone_number', 'Invalid phone number')
        except NumberParseException as e:
            self.add_error('phone_number', e)


class TokenVerificationForm1(forms.Form):
    token = forms.CharField(
        required=True,
        widget=BootstrapInput('Token via SMS, Voice or SoftToken')
    )

    def is_valid(self, authy_id):
        self.authy_id = authy_id
        return super(TokenVerificationForm1, self).is_valid()

    def clean(self):
        token = self.cleaned_data['token']
        verification = authy_api.tokens.verify(decrypt(self.authy_id), token)
        if not verification.ok():
            self.add_error('token', 'Invalid token')


def encrypt(data):
    return base64.b16encode(data.encode('utf-8')).decode('utf-8')

def decrypt(data):
    return base64.b16decode(data.encode('utf-8')).decode('utf-8')