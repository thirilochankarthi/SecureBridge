from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse


@login_required
def home(request):
 return render(request, "home.html", {})


def authView(request):
 if request.method == "POST":
  form = UserCreationForm(request.POST or None)
  if form.is_valid():
   form.save()
   return redirect("login")
 else:
  form = UserCreationForm()
 return render(request, "registration/signup.html", {"form": form}) 

@login_required
def myencrypt(request):
 return render(request, 'encryption.html')

@login_required
def mydecrypt(request):
 return render(request, 'decryption.html') 



