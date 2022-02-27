from django.db import models

from django.contrib.auth.models import AbstractUser


def get_default_filters():
    return {
        "cvss": 0,
        "event_types": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }


def get_default_settings():
    return {"activities_view": "all"}


class User(AbstractUser):
    class Meta:
        db_table = "opencve_users"

    class FrequencyNotification(models.TextChoices):
        ONCE = "once", "Once a day"
        ALWAYS = "always", "As soon as a change is detected"

    enable_notifications = models.BooleanField(default=True)
    filters_notifications = models.JSONField(default=get_default_filters)
    settings = models.JSONField(default=get_default_settings)
    frequency_notifications = models.CharField(
        max_length=6,
        choices=FrequencyNotification.choices,
        default=FrequencyNotification.ALWAYS,
    )
