from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, email, authy_id, password,
                     **extra_fields):
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        username = self.model.normalize_username(username)
        user = self.model(username=username, email=email,
                          authy_id=authy_id, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, authy_id=None, password=None,
                    **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(
            username,
            email,
            authy_id,
            password,
            **extra_fields
        )

    def create_superuser(self, username, email, authy_id, password,
                         **extra_fields):
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(
            username,
            email,
            authy_id,
            password,
            **extra_fields
        )


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=42, unique=True)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15,unique=True)
    authy_id = models.CharField(max_length=12, null=True, blank=True)
    user_id = models.CharField(max_length=10,null=True)
    objects = UserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'