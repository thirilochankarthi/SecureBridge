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
from .forms import FileUploadForm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


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

#message 

def generate_key(password: str) -> bytes:
    
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

#file

def generatekey(password):
    salt = b'\x00' * 16  # Fixed salt for simplicity
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt_file(file, password):
    key = generatekey(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file.read())
    return encrypted_data

def decrypt_file(file, password):
    key = generatekey(password)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(file.read())
    return decrypted_data

def file_crypt_view(request):
    encrypt_form = FileUploadForm(prefix="encrypt")
    decrypt_form = FileUploadForm(prefix="decrypt")

    if request.method == 'POST':
        if 'encrypt-submit' in request.POST:
            encrypt_form = FileUploadForm(request.POST, request.FILES, prefix="encrypt")
            if encrypt_form.is_valid():
                file = request.FILES['encrypt-file']
                password = encrypt_form.cleaned_data['password']
                encrypted_data = encrypt_file(file, password)
                response = HttpResponse(encrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="encrypted_{file.name}"'
                return response
        elif 'decrypt-submit' in request.POST:
            decrypt_form = FileUploadForm(request.POST, request.FILES, prefix="decrypt")
            if decrypt_form.is_valid():
                file = request.FILES['decrypt-file']
                password = decrypt_form.cleaned_data['password']
                decrypted_data = decrypt_file(file, password)
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="decrypted_{file.name}"'
                return response

    return render(request, 'filecrypt/file_crypt.html', {'encrypt_form': encrypt_form, 'decrypt_form': decrypt_form})