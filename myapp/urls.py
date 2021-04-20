from django.contrib import admin
from django.urls import path, include
from . import views

app_name = "myapp"

urlpatterns = [
    path('', views.index, name="index"),
    path('add_note/', views.add_note),
    path('create_account/', views.create_account, name="create_account"),
    path('search/', views.search),
    path('delete/<int:myid>', views.delete),
    path('edit/<int:note_id>', views.edit),
    path('confirm_edit/<int:confirm_note_id>', views.confirm_edit),
    path('login_aashunotes/', views.login_aashunotes),
    path('logout_aashunotes/', views.logout_aashunotes),
    path('lock_me_bro/<int:id_of_note>', views.lock_me_bro),
    path('view_locked_note/<int:id_of_locked_note>', views.view_locked_note),
    path('unlock/<int:unlock_note_id>', views.unlock),
    path('delete_account/', views.delete_account),
    path('change_password_page/', views.change_password_page),
    path('verify_details/', views.verify_details),
    path('labels/', views.labels),
    path('create_label/', views.create_label),
    path('add_to_label/<int:add_me>', views.add_to_label),
    path('remove_from_label/<int:remove_me_from_label>', views.remove_from_label),
    path('view_label/<int:label_id>', views.view_label),
]
