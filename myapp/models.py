from django.db import models

# Create your models here.
class Note(models.Model):
    id = models.AutoField
    note_title = models.CharField(max_length=200, default="")
    note = models.CharField(max_length=500, default="")
    add_date = models.DateField(default="")
    author = models.CharField(max_length=200, default="")
    password = models.CharField(max_length=200, default="", blank=True)
    note_title_when_locked = models.CharField(max_length=500, default="", blank=True)
    note_when_locked = models.CharField(max_length=500, default="", blank=True)


    def __str__(self):
        return self.note_title

class Label(models.Model):
    id = models.AutoField
    note_title = models.CharField(max_length=200, default="", blank=True)
    note = models.CharField(max_length=500, default="", blank=True)
    add_date = models.DateField(default="")
    author = models.CharField(max_length=200, default="")
    password = models.CharField(max_length=200, default="", blank=True)
    note_title_when_locked = models.CharField(max_length=500, default="", blank=True)
    note_when_locked = models.CharField(max_length=500, default="", blank=True)
    label = models.CharField(max_length=200, default="")
    note_id = models.CharField(max_length=200, default="", blank=True)

    def __str__(self):
        return self.label