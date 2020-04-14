from django.db import models
from django.contrib.auth.models import User

class Jog(models.Model):

    class WeatherType(models.IntegerChoices):
        SUNNY = 0
        RAINY = 1
        CLOUDY = 2
        WINDY = 3
        SNOWY = 4

    user_id = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    date = models.DateTimeField(db_index=True, null=False)
    distance = models.FloatField(default=0) # in meters
    time = models.FloatField() # in seconds
    location = models.CharField()
    weather = models.IntegerField(choices=WeatherType.choices)

    def __str__(self):
        return '{user}, {date}'.format(user=str(self.user), date=self.date)


class AuthRole(models.Model):

    class RoleTypes(models.IntegerChoices):
        USER = 0
        MANAGER = 1
        ADMIN = 9

    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.IntegerField(choices=RoleTypes.choices, default=RoleTypes.USER)
