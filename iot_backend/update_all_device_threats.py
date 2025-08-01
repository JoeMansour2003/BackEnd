import os
import sys
import django
import time

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iot_backend.settings')
django.setup()

# Import after Django setup
from iot.models import Iot_Device
from iot.utils import search_vulnerabilities_for_device

def update_all_devices():
    """
    Update all IoT devices with vulnerability information and threat details
    """
    # Get all IoT devices
    devices = Iot_Device.objects.all()
    total_devices = devices.count()

    if total_devices == 0:
        print("No IoT devices found in the database.")
        return

    print(f"Found {total_devices} IoT devices. Starting vulnerability search...")

    # Process each device
    for device in devices:
        try:
            print(f"\nProcessing device: {device.name} (ID: {device.id})")
            search_vulnerabilities_for_device(device.id)
            # Add a small delay to avoid overwhelming the APIs
            time.sleep(1)
        except Exception as e:
            print(f"Error processing device {device.name} (ID: {device.id}): {str(e)}")

    print("\nCompleted vulnerability search for all devices!")

if __name__ == "__main__":
    print("Starting IoT device vulnerability update...")
    start_time = time.time()
    update_all_devices()
    elapsed_time = time.time() - start_time
    print(f"Process completed in {elapsed_time:.2f} seconds")