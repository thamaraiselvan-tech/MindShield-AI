from django.contrib import admin
from django.urls import path
from analyzer.views import analyze_multimodal

urlpatterns = [
    path('admin/', admin.site.urls),
    path('analyze/', analyze_multimodal),
]