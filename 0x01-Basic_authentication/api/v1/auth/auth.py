#!/usr/bin/env python3
"""
Authentication file
"""


from flask import request
from typing import List, TypeVar


class Auth():
    """ Authentication call declaration
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ A public method of class Auth
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths is [""]:
            return True
        if path in excluded_paths or path + "/" in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """ Another public method to check authorization
            header
        """
        if request is None:
            return None
        if 'Authorization' in request.headers:
            headerr = request.headers['Authorization']
            return headerr
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current User request method
        """
        return None
