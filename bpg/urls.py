from django.urls import path

from . import views

urlpatterns = [    
    path('', views.init, name='bpg'),
    path('update/<str:user_id>/<str:object_id>/<str:app_name>/',views.update_user_details,name='update'),
    path('logout', views.logout, name='bpg-logout'),
]
