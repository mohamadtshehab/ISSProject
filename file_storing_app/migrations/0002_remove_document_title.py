# Generated by Django 5.1.4 on 2025-01-01 21:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('file_storing_app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='document',
            name='title',
        ),
    ]
