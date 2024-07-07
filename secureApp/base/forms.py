from django import forms

class EncryptionForm(forms.Form):
    message = forms.CharField(widget=forms.Textarea)
    password = forms.CharField(widget=forms.PasswordInput)

class DecryptionForm(forms.Form):
    encrypted_message = forms.CharField(widget=forms.Textarea)
    password = forms.CharField(widget=forms.PasswordInput)

class FileUploadForm(forms.Form):
    file = forms.FileField()
    password = forms.CharField(widget=forms.PasswordInput())
