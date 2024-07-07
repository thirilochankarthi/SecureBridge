from django.db import models

class EncryptedMessage(models.Model):
    message = models.TextField()
    encrypted_message = models.TextField()
    password = models.CharField(max_length=256)
    timestamp = models.DateTimeField(auto_now_add=True)
