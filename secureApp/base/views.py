from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_protect
from .forms import EncryptionForm, DecryptionForm
from .models import EncryptedMessage
from cryptography.fernet import Fernet
import base64
import hashlib

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

def generate_key(password: str) -> bytes:
    # Derive a 32-byte key from the password
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

@csrf_protect
def encrypt_message(request):
    if request.method == 'POST':
        form = EncryptionForm(request.POST)
        if form.is_valid():
            message = form.cleaned_data['message']
            password = form.cleaned_data['password']
            key = generate_key(password)
            fernet = Fernet(key)
            encrypted_message = fernet.encrypt(message.encode())
            EncryptedMessage.objects.create(
                message=message,
                encrypted_message=encrypted_message.decode(),
                password=password  
            )
            return render(request, 'encrypt_result.html', {'encrypted_message': encrypted_message.decode()})
    else:
        form = EncryptionForm()
    return render(request, 'encrypt.html', {'form': form})

@csrf_protect
def decrypt_message(request):
    if request.method == 'POST':
        form = DecryptionForm(request.POST)
        if form.is_valid():
            encrypted_message = form.cleaned_data['encrypted_message']
            password = form.cleaned_data['password']
            key = generate_key(password)
            fernet = Fernet(key)
            try:
                decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
                return render(request, 'decrypt_result.html', {'message': decrypted_message})
            except:
                return render(request, 'decrypt_result.html', {'error': 'Invalid password or encrypted message'})
    else:
        form = DecryptionForm()
    return render(request, 'decrypt.html', {'form': form})



