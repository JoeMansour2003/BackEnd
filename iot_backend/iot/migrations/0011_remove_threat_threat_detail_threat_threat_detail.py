# Generated by Django 4.2.14 on 2025-06-10 19:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iot', '0010_rename_topic_of_detail_threat_info_category_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='threat',
            name='Threat_Detail',
        ),
        migrations.AddField(
            model_name='threat',
            name='Threat_Detail',
            field=models.ManyToManyField(blank=True, null=True, to='iot.threat_detail'),
        ),
    ]
