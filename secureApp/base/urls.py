from django.urls import path, include
from .views import authView, home
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [
 path("", home, name="home"),
 path("signup/", authView, name="authView"),
 path("accounts/", include("django.contrib.auth.urls")),
 path("logout/", auth_views.LogoutView.as_view(next_page="base:home"), name="logout"),
 path('encrypt/', views.encrypt_message, name='encrypt_message'),
 path('decrypt/', views.decrypt_message, name='decrypt_message'),
]
