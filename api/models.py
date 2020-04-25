from django.db import models
from django.contrib.auth.models import User


class Jog(models.Model):

    user_id = models.ForeignKey(User, on_delete=models.CASCADE, db_index=True)
    date = models.DateField(db_index=True, null=False)
    distance = models.FloatField(default=0) # in meters
    time = models.FloatField(default=0) # in seconds
    location = models.CharField(max_length=255, null=False)
    weather = models.CharField(max_length=255, null=False)

    def __str__(self):
        return '{user}, {date}, {distance}, {time}, {location}, {weather}'.format(user=str(self.user_id), date=self.date,
               distance=self.distance, time=self.time, location=self.location, weather=self.weather)


class AuthRole(models.Model):

    class RoleTypes(models.IntegerChoices):
        USER = 0
        MANAGER = 1
        ADMIN = 9

    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.IntegerField(choices=RoleTypes.choices, default=RoleTypes.USER)

    def __str__(self):
        return '{id}, {user_id}, {role}'.format(id=self.pk, user_id=self.user_id, role=self.role)

    @staticmethod
    def get_auth_role(user_id):
        """
        Retrieves the auth role for the given user_id

        Args:
            user_id (int): user_id for which to retrieve the role

        Returns:
            AuthRole.RoleTypes: user's role
        """
        auth_role = AuthRole.objects.get(user_id__exact=user_id) # type: AuthRole

        if not auth_role:
            raise Exception('No auth role for user_id ' + str(user_id) + ' found')

        role = auth_role.role
        return role





