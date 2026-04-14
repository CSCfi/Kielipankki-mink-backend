"""Login functions."""

import functools
import inspect
import json
import re
import time
import traceback
from pathlib import Path

import jwt
import requests
import shortuuid
from flask import Blueprint
from flask import current_app as app
from flask import g, request, session

from mink.core import exceptions, registry, utils
from mink.core.user import User

bp = Blueprint("sb_auth_login", __name__)


def login(include_read=False, require_resource_id=True, require_resource_exists=True, require_admin=False):
    """Attempt to login on sb-auth.

    Args:
        include_read (bool, optional): Include resources that the user has read access to. Defaults to False.
        require_resource_id (bool, optional): This route requires the user to supply a resource ID. Defaults to True.
        require_resource_exists (bool, optional): This route requires that the supplied resource ID occurs in the JWT.
            Defaults to True.
        require_admin (bool, optional): This route requires the user to be a mink admin. Defaults to False.
    """
    def decorator(function):
        @functools.wraps(function)  # Copy original function's information, needed by Flask
        def wrapper():
            # Get the function's params
            params = inspect.signature(function).parameters.keys()

            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return utils.response("No login credentials provided", err=True,
                                      return_code="missing_login_credentials"), 401
            try:
                auth_token = auth_header.split(" ")[1]
            except Exception:
                return utils.response("No authorization token provided", err=True,
                                      return_code="missing_auth_token"), 401

            try:
                user_id, resources, mink_admin, username, email = _get_resources(auth_token, include_read)
                user = User(id=user_id, name=username, email=email)
            except Exception as e:
                return utils.response("Failed to authenticate", err=True, info=str(e),
                                      return_code="failed_authenticating"), 401

            if require_admin and not mink_admin:
                    return utils.response("Mink admin status could not be confirmed", err=True,
                                          return_code="not_admin"), 401

            # Give access to all resources if admin mode is on and user is mink admin
            if session.get("admin_mode") and mink_admin:
                resources = registry.get_all_resources()
            else:
                # Turn off admin mode if user is not admin
                session["admin_mode"] = False

            try:
                # Store random ID in app context, used for temporary storage
                g.request_id = shortuuid.uuid()

                if not require_resource_id:
                    return function(**{k: v for k, v in {"user_id": user_id, "user": user,
                                                         "corpora": resources, "auth_token": auth_token
                                                        }.items() if k in params})

                # Check if resource ID was provided
                # TODO: change param name from corpus_id to resource_id!
                resource_id = request.args.get("corpus_id") or request.form.get("resource_id")
                if not resource_id:
                    return utils.response("No resource ID provided", err=True, return_code="missing_corpus_id"), 400

                # Check if resource exists
                if not require_resource_exists:
                    return function(**{k: v for k, v in {"user_id": user_id, "user": user,
                                                         "corpora": resources, "resource_id": resource_id,
                                                         "auth_token": auth_token
                                                        }.items() if k in params})

                # Check if user is admin for resource
                if resource_id not in resources:
                    return utils.response(f"Corpus '{resource_id}' does not exist or you do not have access to it",
                                          err=True, return_code="corpus_not_found"), 404
                return function(**{k: v for k, v in {"user_id": user_id, "user": user,
                                                     "corpora": resources, "resource_id": resource_id,
                                                     "auth_token": auth_token}.items() if k in params})

            # Catch everything else and return a traceback
            except Exception as e:
                traceback_str = f"{e}: {''.join(traceback.format_tb(e.__traceback__))}"
                return utils.response("Something went wrong", err=True, info=traceback_str,
                                      return_code="something_went_wrong"), 500

        return wrapper
    return decorator


@bp.route("/admin-mode-on", methods=["POST"])
@login(require_resource_exists=False, require_resource_id=False, require_admin=True)
def admin_mode_on():
    session["admin_mode"] = True
    return utils.response("Admin mode turned on", return_code="admin_on")


@bp.route("/admin-mode-off", methods=["POST"])
@login(require_resource_exists=False, require_resource_id=False)
def admin_mode_off():
    session["admin_mode"] = False
    return utils.response("Admin mode turned off", return_code="admin_off")


@bp.route("/admin-mode-status", methods=["GET"])
@login(require_resource_exists=False, require_resource_id=False)
def admin_mode_status():
    admin_status = session.get("admin_mode", False)
    return utils.response("Returning status of admin mode", admin_mode_status=admin_status,
                          return_code="returning_admin_status")


def read_jwt_key():
    """Read and return the public key for validating JWTs."""
    app.config["JWT_KEY"] = open(Path(app.instance_path) / app.config.get("SBAUTH_PUBKEY_FILE")).read()


def _get_resources(auth_token, include_read=False):
    """Check validity of auth_token and get Mink resources that user has write access for."""
    resources = []
    mink_admin = False
    user_token = jwt.decode(auth_token, key=app.config.get("JWT_KEY"), algorithms=["RS256"])
    if user_token["exp"] < time.time():
        return utils.response("The provided JWT has expired", err=True, return_code="jwt_expired"), 401

    min_level = "WRITE"
    if include_read:
        min_level = "READ"
    if "scope" in user_token:
        # Check if user is mink admin
        mink_app_name = app.config.get("SBAUTH_MINK_APP_RESOURCE", "")
        mink_admin = user_token["scope"].get("other", {}).get(mink_app_name, 0) >= user_token["levels"]["ADMIN"]
        # Get list of corpora
        for corpus, level in user_token["scope"].get("corpora", {}).items():
            if level >= user_token["levels"][min_level] and corpus.startswith(app.config.get("RESOURCE_PREFIX")):
                resources.append(corpus)
        # Get list of metadata resources
        for metadata, level in user_token["scope"].get("metadata", {}).items():
            if level >= user_token["levels"][min_level] and corpus.startswith(app.config.get("RESOURCE_PREFIX")):
                resources.append(metadata)
    user = re.sub(r"[^\w\-_\.]", "", (user_token["idp"] + "-" + user_token["sub"]))
    username = user_token.get("name", "")
    email = user_token.get("email", "")
    return user, resources, mink_admin, username, email


def create_resource(auth_token, resource_id, resource_type=None):
    """Create a new resource in sb-auth."""
    # TODO: specify resource_type when sbauth is ready
    url = app.config.get("SBAUTH_URL") + resource_id
    api_key = app.config.get("SBAUTH_API_KEY")
    headers = {"Authorization": f"apikey {api_key}", "Content-Type": "application/json"}
    data = {"jwt": auth_token}
    try:
        r = requests.post(url, headers=headers, data=json.dumps(data))
        status = r.status_code
    except Exception as e:
        app.logger.error(f"Could not create resource: {e}")
        raise(e)
    if status == 400:
        raise exceptions.CorpusExists
    elif status != 201:
        message = r.content
        app.logger.error(f"Could not create resource, sb-auth returned status {status}: {message}")
        raise Exception(message)


def remove_resource(auth_token, resource_id) -> bool:
    """Remove a resource from sb-auth."""
    url = app.config.get("SBAUTH_URL") + resource_id
    api_key = app.config.get("SBAUTH_API_KEY")
    headers = {"Authorization": f"apikey {api_key}", "Content-Type": "application/json"}
    data = {"jwt": auth_token}
    try:
        r = requests.delete(url, headers=headers, data=json.dumps(data))
        status = r.status_code
    except Exception as e:
        raise e
    if status == 204:
        return True
    elif status == 400:
        # Corpus does not exist
        return False
    else:
        message = r.content
        raise Exception(message)
