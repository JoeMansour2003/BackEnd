# Generated by Django 4.2.14 on 2025-06-10 19:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iot', '0008_remove_iot_device_threat'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='iot_device',
            name='sector',
        ),
        migrations.AddField(
            model_name='iot_device',
            name='sector',
            field=models.ManyToManyField(related_name='Associated_Sector', to='iot.sector'),
        ),
    ]
