from django.urls import path
from .views import ThreatGivenDeviceListAPIView,IotDevicesBySectorsAPIView,IotDeviceGivenSectorListAPIView,IotDeviceViewSet, SectorViewSet, ThreatViewSet,ThreatDetailViewSet,ThreatInfoCategoryViewSet 
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'iot-devices', IotDeviceViewSet, basename='iot-device')
router.register(r'sectors', SectorViewSet, basename='sector')
router.register(r'threats', ThreatViewSet, basename='threat')
router.register(r'threat-details', ThreatDetailViewSet, basename='threat-detail')
router.register(r'threat-info-categories', ThreatInfoCategoryViewSet, basename='threat-info-category')

urlpatterns =  [
    path('iot-devices/<int:device_id>/threats/', ThreatGivenDeviceListAPIView.as_view(), name='iot-device-threats'),
    path('sectors/<int:sector_id>/devices/', IotDeviceGivenSectorListAPIView.as_view(), name='sector-device'),
    path('sectors/devices/', IotDevicesBySectorsAPIView.as_view(), name='filter-devices-by-sectors'),
]+router.urls
# 
# [
#     path('iot-devices/', IotDeviceListAPIView.as_view(), name='iot-device-list'),
#     path('iot-devices/<int:pk>/', IotDeviceDetailAPIView.as_view(), name='iot-device-detail'),  
    
    
#     path('sectors/', SectorListAPIView.as_view(), name='sector-list'),
#     path('threats/', ThreatListAPIView.as_view(), name='threat-list'),
#     path('threat-details/', ThreatDetailListAPIView.as_view(), name='threat-detail-list'),
#     path('threat-info-categories/', ThreatInfoCategoryListAPIView.as_view(), name='threat-info-category-list'),
# ]