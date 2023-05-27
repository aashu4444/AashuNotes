from django.db import models
from myapp import utils


# Create your models here.
class Note(models.Model):
    id = models.AutoField
    note_title = models.CharField(max_length=200, default="")
    note = models.CharField(max_length=500, default="")
    timestamp = models.DateTimeField(auto_now_add=True)
    author = models.CharField(max_length=200, default="")
    password = models.CharField(max_length=200, default="", blank=True)
    note_title_when_locked = models.CharField(max_length=500, default="", blank=True)
    note_when_locked = models.CharField(max_length=500, default="", blank=True)

    
    def decrypt(self, request):
        self.note_title = utils.decrypt(request, self.note_title)
        self.note = utils.decrypt(request, self.note)

        return self
    
    def encrypt(self, request):
        self.note_title = utils.encrypt(request, self.note_title)
        self.note = utils.encrypt(request, self.note)

        return self


    def __str__(self):
        return self.note_title

    

class Label(models.Model):
    id = models.AutoField
    note_title = models.CharField(max_length=200, default=list, blank=True)
    note = models.CharField(max_length=500, default=list, blank=True)
    add_date = models.DateField(default="")
    author = models.CharField(max_length=200, default="")
    password = models.CharField(max_length=200, default="", blank=True)
    note_title_when_locked = models.CharField(max_length=500, default=list, blank=True)
    note_when_locked = models.CharField(max_length=500, default=list, blank=True)
    label = models.CharField(max_length=200, default="")
    note_id = models.CharField(max_length=200, default=list, blank=True)

    def __str__(self):
        return self.label