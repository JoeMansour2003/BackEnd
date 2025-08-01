# Generated by Django 4.2.21 on 2025-06-09 20:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iot', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='iot_device',
            name='created_at',
        ),
        migrations.RemoveField(
            model_name='iot_device',
            name='updated_at',
        ),
        migrations.AddField(
            model_name='iot_device',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, null=True, verbose_name=''),
        ),
        migrations.AlterField(
            model_name='iot_device',
            name='description',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
