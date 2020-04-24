from rest_framework.permissions import BasePermission
from api.models import AuthRole

class IsCreatingOrAuthElseNoAccess(BasePermission):
    """
    Either the user is trying to sign up, or no permissions
    """

    SAFE_METHODS = ['POST']

    def has_permission(self, request, view):
        if (request.method in self.SAFE_METHODS):
            return True

        if (request.user and request.user.is_authenticated):
            return True

        return False


class IsCreatingOrReadingOrStaffElseNoAccess(BasePermission):

    SAFE_METHODS = ['POST', 'GET']

    def has_permission(self, request, view):
        if (request.user and request.user.is_authenticated):
            if request.method in self.SAFE_METHODS:
                return True
            else:
                auth_role = AuthRole.get_auth_role(request.user.pk)
                if auth_role in [AuthRole.RoleTypes.ADMIN, AuthRole.RoleTypes.MANAGER]:
                    return True

        return False

    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user_id'):
            obj_user_id = obj.user_id
        else:
            obj_user_id = obj

        if obj_user_id == request.user:
            return True

        user_auth_role = AuthRole.get_auth_role(request.user.pk) # type: AuthRole.RoleTypes
        obj_auth_role = AuthRole.get_auth_role(obj_user_id) # type: AuthRole.RoleTypes

        if obj_auth_role == AuthRole.RoleTypes.USER:
            if user_auth_role == AuthRole.RoleTypes.ADMIN or user_auth_role == AuthRole.RoleTypes.MANAGER:
                return True
            else:
                return False
        elif user_auth_role == AuthRole.RoleTypes.ADMIN:
            return True

        return False






