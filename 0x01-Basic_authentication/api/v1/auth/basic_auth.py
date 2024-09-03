#!/usr/bin/env python3
"""Basic authentication module for the API.
"""

from .auth import Auth
from typing import TypeVar
import base64
import binascii

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class.
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header
        for a Basic Authentication.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split("Basic ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes a given base64-encoded authorization header.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_value = base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except (TypeError, binascii.Error):
            return None
        return decoded_value

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str): # type: ignore
        """Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication method.
        """
        if decoded_base64_authorization_header is None or not isinstance(
                decoded_base64_authorization_header, str):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(":")
        return email, password

    # def user_object_from_credentials(
    #         self,
    #         user_email: str,
    #         user_pwd: str) -> TypeVar('User'):
    #     """Retrieves a user based on the user's authentication credentials.
    #     """
    #     if user_email is None or not isinstance(user_email, str):
    #         return None
    #     if user_pwd is None or not isinstance(user_pwd, str):
    #         return None

    #     user = User.search(user_email)
    #     if not user:
    #         return None

    #     if not user.is_valid_password(user_pwd):
    #         return None

    #     return user

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'): # type: ignore
        """Retrieves a user based on the user's authentication credentials.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'): # type: ignore
        """Retrieves the user from a request.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
