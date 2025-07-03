from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import generics, viewsets,status
from rest_framework.views import APIView
from .models import Iot_Device, Sector, Threat, Threat_Detail, Threat_Info_Category
from .serializers import IotDeviceSerializer , SectorSerializer, ThreatSerializer, ThreatDetailSerializer, ThreatInfoCategorySerializer

class IotDeviceViewSet(viewsets.ModelViewSet):
    queryset = Iot_Device.objects.all()
    serializer_class = IotDeviceSerializer

class SectorViewSet(viewsets.ModelViewSet):
    queryset = Sector.objects.all()
    serializer_class = SectorSerializer

class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.all()
    serializer_class = ThreatSerializer
    
class ThreatDetailViewSet(viewsets.ModelViewSet):
    queryset = Threat_Detail.objects.all()
    serializer_class = ThreatDetailSerializer
    
class ThreatInfoCategoryViewSet(viewsets.ModelViewSet):
    queryset = Threat_Info_Category.objects.all()
    serializer_class = ThreatInfoCategorySerializer
    

class ThreatGivenDeviceListAPIView(generics.ListAPIView):
    serializer_class = ThreatSerializer
    def get_queryset(self):
        device_id = self.kwargs.get('device_id')
        if device_id:
            return Threat.objects.filter(devices__id=device_id)
        return Threat.objects.none()  # Return empty queryset if no device_id provided
 
class IotDeviceGivenSectorListAPIView(generics.ListAPIView):
    serializer_class = IotDeviceSerializer
    def get_queryset(self):
        sector_id = self.kwargs.get('sector_id')
        if sector_id:
            return Iot_Device.objects.filter(sector__id=sector_id)
        return Iot_Device.objects.none()  # Return empty queryset if no sector_id provided

class IotDevicesBySectorsAPIView(APIView): 
    @swagger_auto_schema(
        operation_description="Get IoT devices that belong to any of the provided sector IDs",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['sector_ids'],
            properties={
                'sector_ids': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_INTEGER),
                    description='List of sector IDs to filter devices by'
                )
            },
            example={
                'sector_ids': [1,2]
            }
        ),
        responses={
            200: IotDeviceSerializer(many=True),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING)
                },
                example={'error': 'Please provide sector_ids as a list'}
            )
        }
    )   
    def post(self, request, *args, **kwargs):
        # Extract sector IDs from request body
        sector_ids = request.data.get('sector_ids', [])
        
        if not sector_ids:
            return Response(
                {"error": "Please provide sector_ids as a list"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Query devices that belong to any of the provided sectors
        devices = Iot_Device.objects.filter(sector__id__in=sector_ids).distinct()
        serializer = IotDeviceSerializer(devices, many=True)
        
        return Response(serializer.data)
    
    
