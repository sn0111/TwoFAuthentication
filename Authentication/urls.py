from django.urls import path
from .views import register,twofa_verification,token_sms,token_email,home,\
    logining,login_verification,token_sms1
from django.contrib.auth import views


urlpatterns = [
    path('register/',register,name='register'),
    path('register_verify', twofa_verification, name='2fa'),
    path('token/sms', token_sms , name='token-sms'),
    path('token/email', token_email, name='token-email'),
    path('home/', home, name='home'),
    path('login/',logining,name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('login_verify/', login_verification, name='2fa1'),
    path('token/sms1', token_sms1, name='token-sms1')
]