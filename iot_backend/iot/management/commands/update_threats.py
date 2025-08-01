from django.core.management.base import BaseCommand
from iot.models import Iot_Device
from iot.utils import search_vulnerabilities_for_device
import time

class Command(BaseCommand):
    help = 'Update threat information for all IoT devices'

    def handle(self, *args, **options):
        devices = Iot_Device.objects.all()
        total_devices = devices.count()

        self.stdout.write(f"Found {total_devices} IoT devices. Starting vulnerability search...")

        for i, device in enumerate(devices):
            try:
                self.stdout.write(f"Processing device {i+1}/{total_devices}: {device.name} (ID: {device.id})")
                search_vulnerabilities_for_device(device.id)
                time.sleep(1)
            except Exception as e:
                self.stderr.write(f"Error processing device {device.name}: {str(e)}")

        self.stdout.write(self.style.SUCCESS("Completed vulnerability search for all devices!"))