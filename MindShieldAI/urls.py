from django.urls import path
from analyzer.views import analyze_multimodal, index, health_check

urlpatterns = [
    path('', index, name='index'),
    path('analyze/', analyze_multimodal, name='analyze'),
    path('health/', health_check, name='health'),
]