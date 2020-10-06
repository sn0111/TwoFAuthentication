import random
import string

from django.shortcuts import render
from .models import User
import base64
from .forms import RegistrationForm,TokenVerificationForm,LoginForm,TokenVerificationForm1

from authy.api import AuthyApiClient
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, redirect
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util


# from .decorators import twofa_required



authy_api = AuthyApiClient(settings.ACCOUNT_SECURITY_API_KEY)



def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            authy_user = authy_api.users.create(
                form.cleaned_data['email'],
                form.cleaned_data['phone_number'],
                form.cleaned_data['country_code'],
            )
            if authy_user.ok():
                user = User.objects.create_user(
                    username=encrypt(form.cleaned_data['username']),
                    email=encrypt(form.cleaned_data['email']),
                    phone_number=encrypt(form.cleaned_data['phone_number']),
                    authy_id=encrypt(str(authy_user.id))
                )
                login(request, user)
                return redirect('2fa')
            else:
                for key, value in authy_user.errors().items():
                    form.add_error(
                        None,
                        '{key}: {value}'.format(key=key, value=value)
                    )
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})


@login_required
def twofa_verification(request):
    if request.method == 'POST':
        form = TokenVerificationForm(request.POST)
        if form.is_valid(decrypt(request.user.authy_id)):
            request.session['authy'] = True
            user_id=get_random_id()
            user = User.objects.get(authy_id=request.user.authy_id)
            user.user_id=encrypt(user_id)
            user.save()
            return redirect('home')
    else:
        form = TokenVerificationForm()
    return render(request, '2fa.html', {'form': form})


@login_required
def token_sms(request):
    sms = authy_api.users.request_sms(decrypt(request.user.authy_id), {'force': True})
    if sms.ok():
        return redirect('2fa')
        # return HttpResponse('SMS request successful', status=200)
    else:
        return HttpResponse('SMS request failed', status=503)


@login_required
def token_email(request):
    print(decrypt(request.user.username))
    user = User.objects.get(username=request.user.username)
    if user:
        token = RefreshToken.for_user(user).access_token
        email_body = 'Hi ' + decrypt(user.username) + '\n Use token below to verify email. Link will expires in 10 min \ntoken=' + str(
            token)
        data = {'email_body': email_body, 'to_email': decrypt(user.email), 'subject': 'Verify email'}
        Util.send_email(data)
        return redirect('2fa')
        # return HttpResponse('Email request successfull', status=200)
    else:
        return HttpResponse('Email request failed', status=503)


# @twofa_required
def home(request):
    data={
        'user_id':decrypt(request.user.user_id),
        'username':decrypt(request.user.username),
        'email':decrypt(request.user.email),
        'phone_number':decrypt(request.user.phone_number)
    }
    return render(request, 'home.html', {'data':data})


def logining(request):
    if request.method=='POST':
        form=LoginForm(request.POST)
        if form.is_valid():
            user= User.objects.get(phone_number=encrypt(form.cleaned_data['phone_number']))
            login(request,user)
            return redirect('2fa1')
    else:
        form=LoginForm()
    return render(request,'login.html',{'form':form})

@login_required
def login_verification(request):
    if request.method == 'POST':
        form = TokenVerificationForm1(request.POST)
        if form.is_valid(request.user.authy_id):
            request.session['authy'] = True
            return redirect('home')
    else:
        form = TokenVerificationForm1()
    return render(request, '2fa1.html', {'form': form})

@login_required
def token_sms1(request):
    sms = authy_api.users.request_sms(decrypt(request.user.authy_id), {'force': True})
    if sms.ok():
        return redirect('2fa1')
        # return HttpResponse('SMS request successful', status=200)
    else:
        return HttpResponse('SMS request failed', status=503)


def encrypt(data):
    return base64.b16encode(data.encode('utf-8')).decode('utf-8')


def decrypt(data):
    return base64.b16decode(data.encode('utf-8')).decode('utf-8')


def get_random_id():
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    user_id = ''.join(random.choice(letters) for i in range(8))
    return user_id