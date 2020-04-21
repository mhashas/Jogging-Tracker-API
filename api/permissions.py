from rest_framework.permissions import BasePermission
from api.models import AuthRole

class IsCreatingHasAccessOrNoAccess(BasePermission):
    """
    Either the user is trying to sign up, or no permissions
    """

    SAFE_METHODS = ['POST']

    def has_permission(self, request, view):
        if (request.method in self.SAFE_METHODS):
            return True

        if (request.user and request.user.is_authenticated):
            auth_role = AuthRole.objects.get(user_id__exact=request.user.pk) # type: AuthRole
            if auth_role.role == AuthRole.RoleTypes.ADMIN or auth_role.role == AuthRole.RoleTypes.MANAGER:
                return True

        return False

class IsAtLeastManagerOrNoAccess(BasePermission):

    def has_permission(self, request, view):
        if (request.user and request.user.is_authenticated):
            auth_role = AuthRole.objects.get(user_id__exact=request.user.pk) # type: AuthRole
            if auth_role.role == AuthRole.RoleTypes.ADMIN or auth_role.role == AuthRole.RoleTypes.MANAGER:
                return True

        return False

    def has_object_permission(self, request, view, obj):
        if obj.user_id == request.user:
            return True

        user_auth_role = AuthRole.objects.get(user_id__exact=request.user.pk) #type: AuthRole
        obj_auth_role = AuthRole.objects.get(user_id__exact=obj.user_id) # type: AuthRole

        # user auth role is at least MANAGER since has_permission method passed so grant access to users
        if obj_auth_role.role == AuthRole.RoleTypes.USER:
            return True
        elif user_auth_role.role == AuthRole.RoleTypes.ADMIN:
            return True

        return False






