from django.urls import path, include
from .views import authView, home
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [
 path("", home, name="home"),
 path("signup/", authView, name="authView"),
 path("accounts/", include("django.contrib.auth.urls")),
 path("logout/", auth_views.LogoutView.as_view(next_page="base:home"), name="logout"),
 path('myencrypt/', views.myencrypt, name='myencrypt'),
 path('mydecrypt/', views.mydecrypt, name='mydecrypt'),

]
