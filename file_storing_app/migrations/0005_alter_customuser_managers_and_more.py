# Generated by Django 5.1.4 on 2025-01-02 12:41

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('file_storing_app', '0004_alter_customuser_birth_date_and_more'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='customuser',
            managers=[
            ],
        ),
        migrations.AlterField(
            model_name='customuser',
            name='birth_date',
            field=models.DateField(verbose_name='Birth Date'),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='phone_number',
            field=models.CharField(max_length=10, unique=True, validators=[django.core.validators.RegexValidator('^09\\d{8}$', 'Enter a 10-digit number starting with 09.')]),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='user_type',
            field=models.CharField(choices=[('admin', 'Admin'), ('citizen', 'Citizen')], default='citizen', max_length=10),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='username',
            field=models.CharField(blank=True, max_length=256, null=True, verbose_name='User Name'),
        ),
    ]
