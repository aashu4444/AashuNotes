import datetime

from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.db.models import Q
from django.shortcuts import render, redirect, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from urllib.parse import urlencode
import cryptography
from cryptography.fernet import Fernet
import base64
from myapp.secrets import SECRET_KEY,FERNET_KEY
from .models import Note, Label

import json

def bytes_string_to_bytes(bytes_string):
    """Convert bytes_string to bytes object"""
    return bytes(bytes_string.split("'")[1], 'utf-8')

def bytes_string_to_string(bytes_string):
    """Convert bytes_string to bytes object"""
    return str(bytes_string).split("'")[1]


def encrypt(request, text):
    key = bytes(SECRET_KEY[:6] + str(request.user.password)[:20] + SECRET_KEY[-7:-1], 'utf-8')
    key = base64.urlsafe_b64encode(key)

    return str(Fernet(key).encrypt(bytes(text,'utf-8')))

def decrypt(request, encrypted_field):
    key = bytes(SECRET_KEY[:6] + str(request.user.password)[:20] + SECRET_KEY[-7:-1], 'utf-8')
    key = base64.urlsafe_b64encode(key)
    print(encrypted_field)
    decrypted = bytes_string_to_string(Fernet(key).decrypt(bytes_string_to_bytes(encrypted_field)))

    return decrypted


# Create your views here.
def index(request):
    user = str(request.user)
    notes = Note.objects.filter(author=user)

    # Decrypt notes of the user
    for note in notes:
        note.note_title = decrypt(request, note.note_title)
        note.note = decrypt(request, note.note)
    params = {"note": notes, "user": user, "anchor": "logout_aashunotes", "btn_text": "<i class='fa fa-sign-out-alt me-2'></i>Log Out", "target_toggle": False}


    try:
        notes_count = Note.objects.filter(author=user)
        params["notes_count"] = notes_count

    except Note.DoesNotExist as error:
        params["description"] = f"{request.user}, looks like you does not have any note"
        params["is_description"] = True

    else:
        params["is_description"] = False

    if request.user.is_anonymous:
        params = {"note": Note.objects.all(), "user": user, "anonymous": True, "anchor": "login_aashunotes",
                  "btn_text": "<i class='fa fa-sign-in-alt me-2'></i>Log In", "target_toggle": True}

    params["labels"] = Label.objects.filter(author=request.user.username)

    return render(request, "myapp/index.html", params)


def add_note(request):
    if request.method == "POST":
        note_title = request.POST.get("note_title")
        note = request.POST.get("note")
        user = request.user

        # Encrypt note details
        encoding = 'utf-8'
        note_title = encrypt(request, note_title)
        note = encrypt(request, note)

        Note(note_title=note_title, note=note, add_date=datetime.datetime.today(), author=user).save()

        # return render(request, index(request))
        messages.success(request, 'Your Note Has Been Added.')

        checkBox = request.POST.get("check")

        # return response
        return redirect("/", {"AutoEscape": checkBox})


    else:
        return render(request, "myapp/add_note.html")


def search(request):
    note = Note.objects.all()
    if request.method == "POST":
        searched = request.POST.get("searched")

        params = {"searched": searched, "note": note, "range": range(1), "anchor": "\logout_aashunotes", "btn_text": "Log Out", "target_toggle": False}
    return render(request, "myapp/search.html", params)


def delete(request, myid):
    try:
        if request.method == "POST":
            if str(request.POST["entered_password"]) == str(Note.objects.get(id=myid).password):
                obj = Note.objects.filter(id=myid)
                obj.delete()
                messages.success(request, 'Your Note Has Been Deleted.')
                return redirect("/")
            else:
                messages.warning(request, "Please Enter Valid Password.")
                return redirect("/")

    except Exception as error:
        obj = Note.objects.filter(id=myid)
        obj.delete()
        messages.success(request, 'Your Note Has Been Deleted.')

        return redirect("/")

    obj = Note.objects.filter(id=myid)
    obj.delete()
    messages.success(request, 'Your Note Has Been Deleted.')
    return redirect("/")



def edit(request, note_id):
    object = Note.objects.filter(id=note_id)
    params = {"id": object[0].id, "NOTE_TITLE": object[0].note_title, "NOTE": object[0].note}

    try:
        ENTERED_PASSWORD = request.POST["entered_password"]
        if str(ENTERED_PASSWORD) == str(Note.objects.get(id=note_id).password):
            return render(request, "myapp/edit.html", params)
        else:
            messages.warning(request, "Please Enter Valid Password.")
            return redirect("/")

    except Exception as error:
        pass

    return render(request, "myapp/edit.html", params)


def confirm_edit(request, confirm_note_id):
    try:
        ENTERED_PASSWORD = request.POST["entered_password"]
        if str(ENTERED_PASSWORD) == str(Note.objects.get(id=confirm_note_id).password):
            OBJ = Note.objects.get(id=confirm_note_id)
            title_of_note = request.POST.get("title_of_note")
            note_of_note = request.POST.get("note_of_note")

            OBJ.note_title = title_of_note
            OBJ.note = note_of_note
            OBJ.save()

            messages.success(request, "Your Note Has Been Edited Successfully.")

            return redirect("/")
        else:
            messages.warning(request, "Please Enter Valid Password.")

            return redirect("/")

    except Exception as e:
        pass

    OBJ = Note.objects.get(id=confirm_note_id)
    if request.method == "POST":
        title_of_note = request.POST.get("title_of_note")
        note_of_note = request.POST.get("note_of_note")

        OBJ.note_title = title_of_note
        OBJ.note = note_of_note
        OBJ.save()

        return redirect("/")


def login_aashunotes(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, "You Have Logged In Successfully")
            return redirect("/")

        else:
            messages.warning(request, "Please Enter Valid Username or Password")
            return redirect("/")
    
    return redirect("/")


def create_account(request):
    if request.method == "POST":
        new_username = request.POST.get("create_username")
        new_password = request.POST.get("create_password")

        create_user = User.objects.create_user(username=new_username, password=new_password)
        create_user.save()

        return redirect("/")

    return render(request, "myapp/create_account.html")


def logout_aashunotes(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("/")


def lock_me_bro(request, id_of_note):
    note = Note.objects.get(id=id_of_note)

    if request.method == "POST":
        lock_password = request.POST["lock_password"]
        note_title_when_locked = request.POST["note_title_when_locked"]
        note_when_locked = request.POST["note_when_locked"]

        note.password = lock_password
        note.note_title_when_locked = note_title_when_locked
        note.note_when_locked = note_when_locked
        note.save()


    return redirect("/")

def view_locked_note(request, id_of_locked_note):
    locked_note_obj = Note.objects.get(id=id_of_locked_note)
    params = {"i":locked_note_obj}
    if request.method == "POST":
        entered_password = request.POST["entered_password"]

        if entered_password == locked_note_obj.password:
            params["right_password"] = True
            return render(request, "myapp/view_locked_note.html", params)
        else:
            params["right_password"] = False
            messages.warning(request, "Please Enter Valid Password.")
            return redirect("/")

def unlock(request, unlock_note_id):
    note = Note.objects.get(id=unlock_note_id)

    if request.method == "POST":
        entered_password = request.POST["entered_password"]

        if entered_password == note.password:
            note.password = ""
            note.note_title_when_locked = ""
            note.note_when_locked = ""
            note.save()
            messages.success(request, "Your Note Has Been Unlocked.")
            return redirect("/")
        else:
            messages.warning(request, "Please Enter Valid Password.")
            return redirect("/")

def delete_account(request):
    user = request.user
    user.delete()

    for notes in Note.objects.all():
        if str(notes.author) == str(user):
            notes.delete()

    messages.success(request, "Your account has been deleted.")
    return redirect("/")


def change_password_page(request):
    return render(request, "myapp/change_password_page.html")

def verify_details(request):
    user = request.user
    if request.method == "POST":
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_new_password = request.POST.get("confirm_new_password")

        if user.check_password(old_password) and str(new_password) == str(confirm_new_password):
            user.set_password(new_password)
            user.save()
            messages.success(request, "Your password has been changed you must log in now!")
            return redirect("/")

        else:
            messages.warning(request, "Please enter valid deatails.")
            return redirect("/change_password_page/")

def labels(request):
    vars = {}
    vars["labels"] = Label.objects.all()
    vars["user"] = str(request.user)
    return render(request, "myapp/labels.html", vars)

def create_label(request):
    user = request.user
    if request.method == "POST":
        label_ls = []
        label_name = request.POST["label_name"]
        label_ls.append(label_name)

        Label(label=label_name, add_date=datetime.datetime.today(), author=user).save()
        messages.success(request, "Your label has been created successfully.")

    return redirect("/")

def add_to_label(request, add_me):
    if request.method == "POST":
        for i in range(1, len(Label.objects.all()) + 1):
            input_box = request.POST.get(f"CheckBox{i}", "off")
            
            if input_box == "on":
                checkLabel = request.POST[f"checkLabel{i}"]
                labels = Label.objects.filter(label=checkLabel)
                note = Note.objects.get(id=add_me)

                for label in labels:
                    
                    if len(label.note_title) != 0 and len(label.note) != 0 and len(label.password) != 0 and len(label.note_title_when_locked) != 0 and len(label.note_when_locked) != 0 and label.note_id != "":
                        # get the string into a list
                        note_title_list = json.loads(label.note_title)
                        note_list = json.loads(label.note)
                        password_list = json.loads(label.password)
                        note_title_when_locked_list = json.loads(label.note_title_when_locked)
                        note_when_locked_list = json.loads(label.note_when_locked)
                        note_id_list = json.loads(label.note_id)

                        # append items into above lists
                        note_title_list.append(note.note_title)
                        note_list.append(note.note)
                        password_list.append(note.password)
                        note_title_when_locked_list.append(note.note_title_when_locked)
                        note_when_locked_list.append(note.note_when_locked)
                        note_id_list.append(note.id)

                        # Change items of the label
                        label.note_title = json.dumps(note_title_list)
                        label.note = json.dumps(note_list)
                        label.password = json.dumps(password_list)
                        label.note_title_when_locked_list = json.dumps(note_title_when_locked_list)
                        label.note_when_locked = json.dumps(note_when_locked_list)
                        label.note_id = json.dumps(note_id_list)

                        # Save all changes of the label
                        label.save()

                    else:
                        # List of contents that a label have
                        note_title_list = []
                        note_list = []
                        password_list = []
                        note_title_when_locked_list = []
                        note_when_locked_list = []
                        note_id_list = []

                        # Append items of note in above lists 
                        note_title_list.append(note.note_title)
                        note_list.append(note.note)
                        password_list.append(note.password)
                        note_title_when_locked_list.append(note.note_title_when_locked)
                        note_when_locked_list.append(note.note_when_locked)
                        note_id_list.append(note.id)

                        # change item the of label
                        # json.dumps() is used to change lists,dicts,etc.. into string
                        label.note_title = json.dumps(note_title_list) 
                        label.note = json.dumps(note_list) 
                        label.password = json.dumps(password_list) 
                        label.note_title_when_locked = json.dumps(note_title_when_locked_list) 
                        label.note_when_locked = json.dumps(note_when_locked_list) 
                        label.note_id = json.dumps(note_id_list) 

                        # Save all changes of the label 
                        label.save()
        messages.success(request, "Your note has been successfully added to label(s).")        
            
    return redirect("/")

def remove_from_label(request, remove_me_from_label):
    if request.method == "POST":
        for i in range(1, len(Label.objects.all()) + 1):
            input_box = request.POST.get(f"CheckToRemove{i}", "off")
            
            if input_box == "on":
                checkLabel = request.POST[f"CheckToRemoveLabel{i}"]
                labels = Label.objects.filter(label=checkLabel)
                note = Note.objects.get(id=remove_me_from_label)

                for label in labels:                    
                    if len(label.note_title) != 0 and len(label.note) != 0 and len(label.password) != 0 and len(label.note_title_when_locked) != 0 and len(label.note_when_locked) != 0 and label.note_id != "":
                        
                        # get the string into a list
                        note_title_list = json.loads(label.note_title)
                        note_list = json.loads(label.note)
                        password_list = json.loads(label.password)
                        note_title_when_locked_list = json.loads(label.note_title_when_locked)
                        note_when_locked_list = json.loads(label.note_when_locked)
                        note_id_list = json.loads(label.note_id)

                        id_index = note_id_list.index(note.id)

                        # remove items from above lists
                        note_title_list.remove(note_title_list[id_index])
                        note_list.remove(note_list[id_index])
                        password_list.remove(password_list[id_index])
                        note_title_when_locked_list.remove(note_title_when_locked_list[id_index])
                        note_when_locked_list.remove(note_when_locked_list[id_index])
                        note_id_list.remove(note_id_list[id_index])

                        # Change items of the label
                        label.note_title = json.dumps(note_title_list)
                        label.note = json.dumps(note_list)
                        label.password = json.dumps(password_list)
                        label.note_title_when_locked_list = json.dumps(note_title_when_locked_list)
                        label.note_when_locked = json.dumps(note_when_locked_list)
                        label.note_id = json.dumps(note_id_list)

                        # Save all changes of the label
                        label.save()
        messages.success(request, "Your note has been successfully removed from label(s).")

    return redirect("/")

def view_label(request, label_id):
    params = {}
    label = Label.objects.get(id=label_id)
    note = Note.objects.all()
    params["note"] = note
    params["labels"] = Label.objects.all()
    try:
        params["loads"] = json.loads(label.note_title)
    except Exception as error:
        pass

    return render(request, "myapp/view_label.html", params)