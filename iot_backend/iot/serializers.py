from rest_framework import serializers
from .models import Iot_Device, Sector, Threat, Threat_Detail, Threat_Info_Category

class IotDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Iot_Device
        fields = ['id', 'name', 'description', 'IP_Address', 'Mac_Address', 'sector']

class SectorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sector
        fields = "__all__"

class ThreatInfoCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat_Info_Category
        fields = ['id', 'topic', 'description']

class ThreatDetailSerializer(serializers.ModelSerializer):
    # Include the category information
    threat_info_category = ThreatInfoCategorySerializer(source='threat_Info_Category', read_only=True)
    
    class Meta:
        model = Threat_Detail
        fields = ['id', 'threat_info_category', 'ai_summary', 'details'] 
        # "threat_Info_Category" is only the id number
        # "threat_info_category" is the serialized model

class ThreatSerializer(serializers.ModelSerializer):
    # Include all related threat details
    threat_details = ThreatDetailSerializer(many=True, read_only=True)
    
    class Meta:
        model = Threat
        fields = ['id', 'threat_Level', 'attack_Name', 'description', 'devices', 'threat_details']
