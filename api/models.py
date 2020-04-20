from django.db import models
from django.contrib.auth.models import User

class Jog(models.Model):

    class WeatherType(models.IntegerChoices):
        SUNNY = 1
        RAINY = 2
        CLOUDY = 3
        WINDY = 4
        SNOWY = 5

    user_id = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    date = models.DateTimeField(db_index=True, null=False)
    distance = models.FloatField(default=0) # in meters
    time = models.FloatField(default=0) # in seconds
    location = models.CharField(max_length=255, default='')
    weather = models.IntegerField(choices=WeatherType.choices, null=True)

    def __str__(self):
        return '{user}, {date}, {distance}, {time}, {location}, {weather}'.format(user=str(self.user_id), date=self.date,
               distance=self.distance, time=self.time, location=self.location, weather=self.weather )


class AuthRole(models.Model):

    class RoleTypes(models.IntegerChoices):
        USER = 0
        MANAGER = 1
        ADMIN = 9

    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.IntegerField(choices=RoleTypes.choices, default=RoleTypes.USER)

    def __str__(self):
        return '{id}, {user_id}, {role}'.format(id=self.pk, user_id=self.user_id, role=self.role)

