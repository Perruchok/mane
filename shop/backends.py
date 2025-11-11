from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

UserModel = get_user_model()

class UsernameOrEmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # Try username match first
            user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            # If not found, try email
            try:
                user = UserModel.objects.get(email=username)
            except UserModel.DoesNotExist:
                return None
        
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None