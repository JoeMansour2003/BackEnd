from django.contrib import admin
from .models import Iot_Device , Sector, Threat , Threat_Detail, Threat_Info_Category

# Register your models here.
admin.site.register(Iot_Device)
admin.site.register(Sector)
admin.site.register(Threat)
admin.site.register(Threat_Detail)
admin.site.register(Threat_Info_Category)