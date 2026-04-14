"""Routes related to storing metadata files."""

import requests
import shortuuid
from flask import Blueprint
from flask import current_app as app
from flask import request, send_file

from mink.core import exceptions, registry, utils
from mink.core.info import Info
from mink.core.resource import Resource, ResourceType
from mink.metadata import storage
from mink.sb_auth import login

bp = Blueprint("metadata_storage", __name__)


# ------------------------------------------------------------------------------
# Corpus operations
# ------------------------------------------------------------------------------

@bp.route("/create-metadata", methods=["POST"])
@login.login(require_resource_id=False, require_resource_exists=False)
def create_metadata(user: dict, auth_token: str):
    """Create a new metadata resource."""
    public_id = request.args.get("public_id") or request.form.get("public_id") or ""
    if not public_id:
        return utils.response("Failed to create resource: no public ID provided", err=True,
                              return_code="failed_creating_resource"), 500

    # TODO: better solution for getting user's organization prefix!
    org_prefixes = app.config.get("METADATA_ORG_PREFIXES")
    org_prefix = org_prefixes.get(user.id)
    if org_prefix is None:
        return utils.response("No organization prefix was found for user", info=str(e),
                              return_code="failed_getting_org_prefix"), 500
    org_prefix = org_prefix.lower()
    if not public_id.startswith(org_prefix + "-"):
        return utils.response("Failed to create resource: chosen public ID does not contain the correct "
                              "organization prefix", err=True,
                              return_code="failed_creating_resource"), 500

    # Check availability of ID in SBX metadata and the Mink backend resource registry
    check_id_url = app.config.get("METADATA_ID_AVAILABLE_URL") + public_id
    try:
        id_available = requests.get(check_id_url).json().get("available", False)
    except Exception as e:
        return utils.response("Failed to create resource: failed to check ID availability", err=True, info=str(e),
                              return_code="failed_creating_resource"), 500
    if not id_available or public_id in registry.get_all_resources():
        return utils.response("Failed to create resource: ID not available", err=True,
                              return_code="failed_creating_resource"), 500

    # Create internal resource ID
    resource_id = None
    prefix = app.config.get("RESOURCE_PREFIX")
    tries = 1
    while resource_id is None:
        # Give up after 3 tries
        if tries > 3:
            return utils.response("Failed to create resource", err=True,
                                  return_code="failed_creating_resource"), 500
        tries += 1
        resource_id = f"{prefix}{shortuuid.uuid()[:10]}".lower()
        if resource_id in registry.get_all_resources():
            resource_id = None
        else:
            try:
                login.create_resource(auth_token, resource_id, resource_type="metadata")
            except exceptions.CorpusExists:
                # Resource ID is in use in authentication system, try to create another one
                resource_id = None
            except Exception as e:
                return utils.response("Failed to create resource", err=True, info=str(e),
                                    return_code="failed_creating_resource"), 500

    try:
        res = Resource(resource_id, type=ResourceType.metadata, public_id=public_id)
        info_obj = Info(resource_id, resource=res, owner=user)
        info_obj.create()
    except Exception as e:
        return utils.response("Failed to create resource", err=True, info=str(e),
                            return_code="failed_creating_resource"), 500

    # Create metadata resource dir with sources subdir
    try:
        resource_dir = str(storage.get_resource_dir(resource_id, mkdir=True))
        storage.get_source_dir(resource_id, mkdir=True)
        return utils.response(f"Resource '{resource_id}' created successfully", resource_id=resource_id,
                              return_code="created_resource"), 201
    except Exception as e:
        try:
            # Try to remove partially uploaded resource data
            storage.remove_dir(resource_dir, resource_id)
        except Exception as err:
            app.logger.error(f"Failed to remove partially uploaded corpus data for '{resource_id}'. {err}")
        try:
            login.remove_resource(auth_token, resource_id)
        except Exception as err:
            app.logger.error(f"Failed to remove corpus '{resource_id}' from auth system. {err}")
        try:
            info_obj.remove()
        except Exception as err:
            app.logger.error(f"Failed to remove object '{resource_id}' from registry. {err}")
        return utils.response("Failed to create resource dir", err=True, info=str(e),
                              return_code="failed_creating_resource_dir"), 500


@bp.route("/remove-metadata", methods=["DELETE"])
@login.login()
def remove_metadata(resource_id: str, auth_token: str):
    """Remove metadata resource."""
    # Get info object
    info_obj = registry.get(resource_id)

    try:
        # Remove from storage
        resdir = str(storage.get_resource_dir(resource_id))
        storage.remove_dir(resdir, resource_id)
    except Exception as e:
        return utils.response(f"Failed to remove resource '{resource_id}' from storage", err=True, info=str(e),
                              return_code="failed_removing_storage"), 500

    try:
        # Remove from auth system
        login.remove_resource(auth_token, resource_id)
    except Exception as e:
        return utils.response(f"Failed to remove corpus '{resource_id}' from authentication system", err=True,
                              info=str(e), return_code="failed_removing_auth"), 500

    try:
        # Remove from Mink registry
        info_obj.remove()
    except Exception as err:
        app.logger.error(f"Failed to remove job '{resource_id}'. {err}")
    return utils.response(f"Corpus '{resource_id}' successfully removed", return_code="removed_corpus")


# ------------------------------------------------------------------------------
# Metadata (yaml) file operations
# ------------------------------------------------------------------------------

@bp.route("/upload-metadata-yaml", methods=["PUT"])
@login.login()
def upload_metadata_yaml(resource_id: str):
    """Upload a metadata yaml as file or plain text."""
    def set_resource_name(resource_name):
        res = registry.get(resource_id).resource
        res.set_resource_name = resource_name

    attached_files = list(request.files.values())
    metadata_txt = request.args.get("yaml") or request.form.get("yaml") or ""

    if attached_files and metadata_txt:
        return utils.response("Found both a file and metadata in plain text but can only process one of these",
                              err=True, return_code="too_many_params_upload_metadata"), 400

    # Process uploaded metadata file
    if attached_files:
        # Check if metadata file is YAML
        yaml_file = attached_files[0]
        if yaml_file.mimetype not in ("application/x-yaml", "text/yaml"):
            return utils.response("Metadata file needs to be YAML", err=True, return_code="wrong_metadata_format"), 400

        yaml_contents = yaml_file.read()

        try:
            new_yaml, resource_name = utils.standardize_metadata_yaml(yaml_contents)
            set_resource_name(resource_name)
            storage.write_file_contents(str(storage.get_yaml_file(resource_id)), new_yaml.encode("UTF-8"), resource_id)
            return utils.response(f"Metadata file successfully uploaded for '{resource_id}'",
                                  return_code="uploaded_yaml"), 201
        except Exception as e:
            return utils.response(f"Failed to upload metadata file for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_uploading_metadata"), 500

    # Process metadata in plain text
    elif metadata_txt:
        try:
            new_yaml, resource_name = utils.standardize_metadata_yaml(metadata_txt)
            set_resource_name(resource_name)
            storage.write_file_contents(str(storage.get_yaml_file(resource_id)), new_yaml.encode("UTF-8"), resource_id)
            return utils.response(f"Metadata file successfully uploaded for '{resource_id}'",
                                  return_code="uploaded_metadata"), 201
        except Exception as e:
            return utils.response(f"Failed to upload metadata file for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_uploading_metadata"), 500

    else:
        return utils.response("No metadata file provided for upload", err=True, return_code="missing_metadata_upload"), 400


@bp.route("/download-metadata-yaml", methods=["GET"])
@login.login()
def download_metadata_yaml(resource_id: str):
    """Download the metadata yaml file."""
    storage_yaml_file = str(storage.get_yaml_file(resource_id))
    # Create directory for the current resource locally (on Mink backend server)
    utils.get_resource_dir(resource_id, mkdir=True)
    local_yaml_file = utils.get_metadata_yaml_file(resource_id)

    try:
        # Get file from storage
        if storage.download_file(storage_yaml_file, local_yaml_file, resource_id, ignore_missing=True):
            return send_file(local_yaml_file, mimetype="text/yaml")
        else:
            return utils.response(f"No metadata file found for corpus '{resource_id}'", err=True,
                                  return_code="metadata_not_found"), 404
    except Exception as e:
        return utils.response(f"Failed to download metadata file for corpus '{resource_id}'", err=True, info=str(e),
                              return_code="failed_downloading_metadata"), 500


# # ------------------------------------------------------------------------------
# # Source file operations
# # ------------------------------------------------------------------------------

# @bp.route("/upload-metadata-sources", methods=["PUT"])
# @login.login()
# def upload_metadata_sources(resource_id: str):
#     pass


# @bp.route("/list-metadata-sources", methods=["GET"])
# @login.login()
# def list_metadata_sources(resource_id: str):
#     pass


# @bp.route("/remove-metadata-sources", methods=["DELETE"])
# @login.login()
# def remove_metadata_sources(resource_id: str):
#     pass


# @bp.route("/download-metadata-sources", methods=["GET"])
# @login.login()
# def download_metadata_sources(resource_id: str):
#     pass
