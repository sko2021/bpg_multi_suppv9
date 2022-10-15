from django.urls import path

from . import views

urlpatterns = [    
    path('', views.init, name='bpg'),
    path('update/<str:user_id>/<str:access_token>/',views.update_user_details,name='update'),
    path('logout', views.logout, name='bpg-logout'),
]
