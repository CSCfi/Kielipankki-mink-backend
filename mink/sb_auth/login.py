"""Mock authentication server for local development.

This module provides a simplified version of the sb_auth authentication system
that accepts all authentication attempts without verification for local testing.
"""

import functools
import inspect
import time
import uuid
from pathlib import Path

from flask import Blueprint, g, request, session
from flask import current_app as app

from mink.core import exceptions, registry, utils
from mink.core.user import User

bp = Blueprint("mock_auth_login", __name__)

# Constants for access levels
ACCESS_LEVELS = {"READ": 1, "WRITE": 2, "ADMIN": 3}


def login(
    include_read=False,
    require_resource_id=True,
    require_resource_exists=True,
    require_admin=False,
):
    """Mock login function that accepts all authentication attempts.

    Args:
        include_read (bool, optional): Include resources that the user has read access to. Defaults to False.
        require_resource_id (bool, optional): This route requires the user to supply a resource ID. Defaults to True.
        require_resource_exists (bool, optional): This route requires that the supplied resource ID occurs in the JWT.
            Defaults to True.
        require_admin (bool, optional): This route requires the user to be a mink admin. Defaults to False.
    """

    def decorator(function):
        @functools.wraps(
            function
        )  # Copy original function's information, needed by Flask
        def wrapper():
            # Get the function's params
            params = inspect.signature(function).parameters.keys()

            auth_header = request.headers.get("Authorization")
            apikey = request.headers.get("X-Api-Key")

            auth_token = None

            # For local development, create a mock authentication instance
            # that bypasses actual verification
            if auth_header:
                try:
                    auth_token = auth_header.split(" ")[1]
                except Exception:
                    return (
                        utils.response(
                            "No authorization token provided",
                            err=True,
                            return_code="missing_auth_token",
                        ),
                        401,
                    )

                # Use MockJwtAuthentication instead of JwtAuthentication
                auth = MockJwtAuthentication(auth_token)

            elif apikey:
                # Use MockApikeyAuthentication instead of ApikeyAuthentication
                auth = MockApikeyAuthentication(apikey)
                auth_token = None

            else:
                return (
                    utils.response(
                        "No login credentials provided",
                        err=True,
                        return_code="missing_login_credentials",
                    ),
                    401,
                )

            resources = auth.get_resource_ids(include_read)
            user = auth.get_user()

            if require_admin and not auth.is_admin():
                return (
                    utils.response(
                        "Mink admin status could not be confirmed",
                        err=True,
                        return_code="not_admin",
                    ),
                    401,
                )

            # Give access to all resources if admin mode is on and user is mink admin
            if session.get("admin_mode") and auth.is_admin():
                resources = registry.get_all_resources()
            else:
                # Turn off admin mode if user is not admin
                session["admin_mode"] = False

            if "auth_token" in params and auth_token is None:
                return (
                    utils.response(
                        "This route requires authentication by JWT",
                        err=True,
                        return_code="route_requires_jwt",
                    ),
                    400,
                )

            try:
                # Store random ID in app context, used for temporary storage
                g.request_id = str(uuid.uuid4())

                if not require_resource_id:
                    return function(
                        **{
                            k: v
                            for k, v in {
                                "user_id": user.id,
                                "user": user,
                                "corpora": resources,
                                "auth_token": auth_token,
                            }.items()
                            if k in params
                        }
                    )

                # Check if resource ID was provided
                resource_id = request.args.get("corpus_id") or request.form.get(
                    "resource_id"
                )
                if not resource_id:
                    return (
                        utils.response(
                            "No resource ID provided",
                            err=True,
                            return_code="missing_corpus_id",
                        ),
                        400,
                    )

                # Check if resource exists
                if not require_resource_exists:
                    return function(
                        **{
                            k: v
                            for k, v in {
                                "user_id": user.id,
                                "user": user,
                                "corpora": resources,
                                "resource_id": resource_id,
                                "auth_token": auth_token,
                            }.items()
                            if k in params
                        }
                    )

                # For local development, we'll automatically add the resource_id to resources
                # to simulate the user having access to it
                if resource_id not in resources:
                    resources.append(resource_id)

                return function(
                    **{
                        k: v
                        for k, v in {
                            "user_id": user.id,
                            "user": user,
                            "corpora": resources,
                            "resource_id": resource_id,
                            "auth_token": auth_token,
                        }.items()
                        if k in params
                    }
                )

            except Exception as e:
                import traceback

                traceback_str = f"{e}: {''.join(traceback.format_tb(e.__traceback__))}"
                return (
                    utils.response(
                        "Something went wrong",
                        err=True,
                        info=traceback_str,
                        return_code="something_went_wrong",
                    ),
                    500,
                )

        return wrapper

    return decorator


@bp.route("/admin-mode-on", methods=["POST"])
@login(require_resource_exists=False, require_resource_id=False, require_admin=True)
def admin_mode_on():
    """Turn on admin mode."""
    session["admin_mode"] = True
    return utils.response("Admin mode turned on", return_code="admin_on")


@bp.route("/admin-mode-off", methods=["POST"])
@login(require_resource_exists=False, require_resource_id=False)
def admin_mode_off():
    """Turn off admin mode."""
    session["admin_mode"] = False
    return utils.response("Admin mode turned off", return_code="admin_off")


@bp.route("/admin-mode-status", methods=["GET"])
@login(require_resource_exists=False, require_resource_id=False)
def admin_mode_status():
    """Return status of admin mode."""
    admin_status = session.get("admin_mode", False)
    return utils.response(
        "Returning status of admin mode",
        admin_mode_status=admin_status,
        return_code="returning_admin_status",
    )


class MockAuthentication:
    """Mock authentication base class that always succeeds."""

    def __init__(self):
        """Initialize with default values."""
        self.set_user("local", "dev-user", "Local Developer", "dev@example.com")

        # Create a default scope with admin access
        default_scope = {
            "corpora": {"test-corpus": ACCESS_LEVELS["ADMIN"]},
            "metadata": {"test-metadata": ACCESS_LEVELS["ADMIN"]},
            "other": {"mink": ACCESS_LEVELS["ADMIN"]},
        }

        self.set_resources(default_scope, ACCESS_LEVELS)

    def set_user(self, idp, sub, name, email):
        """Set user attributes."""
        user_id = f"{idp}-{sub}"
        self.user = User(id=user_id, name=name, email=email)

    def set_resources(self, scope, levels):
        """Set scope and levels of resource grants."""
        self.scope = scope
        self.levels = levels

    def get_user(self):
        """Return user."""
        return self.user

    def get_resource_ids(self, include_read=False):
        """Get a list of all resource IDs the user has access to."""
        min_level = "READ" if include_read else "WRITE"

        resource_prefix = app.config.get("RESOURCE_PREFIX", "")

        # In local mode, we're creating a list of mock resources
        # This could be extended to include actual resources from a config file
        mock_resources = ["test-corpus", "test-corpus-2", "test-metadata"]

        return [r for r in mock_resources if r.startswith(resource_prefix)]

    def is_admin(self):
        """Always return True for admin status in local development."""
        return True


class MockJwtAuthentication(MockAuthentication):
    """Mock JWT authentication that always succeeds."""

    def __init__(self, token):
        """Initialize with mock JWT data."""
        super().__init__()
        # Store the token but don't actually validate it
        self.token = token


class MockApikeyAuthentication(MockAuthentication):
    """Mock API key authentication that always succeeds."""

    def __init__(self, apikey):
        """Initialize with mock API key data."""
        super().__init__()
        # Store the key but don't actually validate it
        self.apikey = apikey


def create_resource(auth_token, resource_id, resource_type=None):
    """Create a new resource in the mock system."""
    # For local development, just return success
    app.logger.info(f"Mock resource created: {resource_id} of type {resource_type}")
    return True


def remove_resource(resource_id):
    """Remove a resource from the mock system."""
    # For local development, just return success
    app.logger.info(f"Mock resource removed: {resource_id}")
    return True
