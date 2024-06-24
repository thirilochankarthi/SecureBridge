from django.shortcuts import render
from django.http import HttpResponse

def login(request):
    return render(request, 'login.html')

def signup_view(request):
    return render(request, 'signup.html')

def home_view(request):
    return HttpResponse("Welcome to Home")