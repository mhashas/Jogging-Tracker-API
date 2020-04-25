from rest_framework.permissions import BasePermission
from api.models import AuthRole

class IsCreatingOrAuthElseNoAccess(BasePermission):
    """Permission that is used for creating users. Sign-ing up does not require you to be authenticated."""

    SAFE_METHODS = ['POST']

    def has_permission(self, request, view):
        """
            Only logged in users have permission can retrieve records. Non-logged in users can only create a new user.

            Args:
                request: incoming request
                view: accesed view

            Returns:
                bool: if user should be granted access or not
            """
        if (request.method in self.SAFE_METHODS):
            return True

        if (request.user and request.user.is_authenticated):
            return True

        return False


class IsCreatingOrReadingOrStaffElseNoAccess(BasePermission):
    """General permission scheme used throughout the app."""

    SAFE_METHODS = ['POST', 'GET']

    def has_permission(self, request, view):
        """
        Only logged in users have permission.

        Args:
            request: incoming request
            view: accesed view

        Returns:
            bool: if user should be granted access or not
        """
        if (request.user and request.user.is_authenticated):
            return True

        return False

    def has_object_permission(self, request, view, obj):
        """
        Users can CRUD their own records. Managers can CRUD user records. Admins can CRUD any records.

        Args:
            request: incoming request
            view: accesed view
            obj: requested object

        Returns:
            bool: if user should be granted access or not
        """

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






