from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Iot_Device
from .utils import search_vulnerabilities_for_device

@receiver(post_save, sender=Iot_Device)
def auto_search_vulnerabilities(sender, instance, created, **kwargs):
    """
    When a new device is created, automatically search for vulnerabilities
    """
    if created:
        # Run in background or async task if available
        search_vulnerabilities_for_device(instance.id)