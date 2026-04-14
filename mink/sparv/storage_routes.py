"""Routes related to storage on Sparv server."""

from pathlib import Path

import shortuuid
from flask import Blueprint
from flask import current_app as app
from flask import request, send_file

from mink.core import exceptions, registry, utils
from mink.core.info import Info
from mink.sb_auth import login
from mink.sparv import storage
from mink.sparv import utils as sparv_utils

bp = Blueprint("sparv_storage", __name__)


# ------------------------------------------------------------------------------
# Corpus operations
# ------------------------------------------------------------------------------

@bp.route("/create-corpus", methods=["POST"])
@login.login(require_resource_exists=False, require_resource_id=False)
def create_corpus(user: dict, auth_token: str):
    """Create a new corpus."""
    # Create corpus ID
    resource_id = None
    prefix = app.config.get("RESOURCE_PREFIX")
    tries = 1
    while resource_id is None:
        # Give up after 3 tries
        if tries > 3:
            return utils.response("Failed to create corpus", err=True,
                                  return_code="failed_creating_corpus"), 500
        tries += 1
        resource_id = f"{prefix}{shortuuid.uuid()[:10]}".lower()
        if resource_id in registry.get_all_resources():
            resource_id = None
        else:
            try:
                login.create_resource(auth_token, resource_id, resource_type="corpora")
            except exceptions.CorpusExists:
                # Corpus ID is in use in authentication system, try to create another one
                resource_id = None
            except Exception as e:
                return utils.response("Failed to create corpus", err=True, info=str(e),
                                    return_code="failed_creating_corpus"), 500

    info_obj = Info(resource_id, owner=user)
    info_obj.create()

    # Create corpus dir with subdirs
    try:
        corpus_dir = str(storage.get_corpus_dir(resource_id, mkdir=True))
        storage.get_source_dir(resource_id, mkdir=True)
        return utils.response(f"Corpus '{resource_id}' created successfully", corpus_id=resource_id,
                              return_code="created_corpus"), 201
    except Exception as e:
        try:
            # Try to remove partially uploaded corpus data
            storage.remove_dir(corpus_dir, resource_id)
        except Exception as err:
            app.logger.error(f"Failed to remove partially uploaded corpus data for '{resource_id}'. {err}")
        try:
            login.remove_resource(auth_token, resource_id)
        except Exception as err:
            app.logger.error(f"Failed to remove corpus '{resource_id}' from auth system. {err}")
        try:
            info_obj.remove()
        except Exception as err:
            app.logger.error(f"Failed to remove job '{resource_id}'. {err}")
        return utils.response("Failed to create corpus dir", err=True, info=str(e),
                              return_code="failed_creating_corpus_dir"), 500


@bp.route("/list-corpora", methods=["GET"])
@login.login(require_resource_id=False, require_resource_exists=False)
def list_corpora(corpora: list):
    """List all available corpora."""
    return utils.response("Listing available corpora", corpora=corpora, return_code="listing_corpora")


@bp.route("/list-korp-corpora", methods=["GET"])
@login.login(include_read=True, require_resource_id=False, require_resource_exists=False)
def list_korp_corpora(corpora: list):
    """List all the user's corpora that are installed in Korp."""
    installed_corpora = []
    try:
        # Get resource infos beloning to corpora that the user may edit
        resources = registry.filter_resources(corpora)
        for res in resources:
            if res.job.installed_korp:
                installed_corpora.append(res.id)
    except Exception as e:
        return utils.response(f"Failed to list corpora installed in Korp", err=True, info=str(e),
                              return_code="failed_listing_korp_corpora"), 500
    return utils.response("Listing corpora installed in Korp", corpora=installed_corpora,
                          return_code="listing_korp_corpora")


@bp.route("/remove-corpus", methods=["DELETE"])
@login.login()
def remove_corpus(resource_id: str, auth_token: str):
    """Remove corpus."""
    # Get job
    info_obj = registry.get(resource_id)
    if info_obj.job.installed_korp:
        try:
            # Uninstall corpus from Korp using Sparv
            info_obj.job.uninstall_korp()
        except Exception as e:
            return utils.response(f"Failed to remove corpus '{resource_id}' from Korp", err=True, info=str(e),
                                  return_code="failed_removing_korp"), 500
    if info_obj.job.installed_strix:
        try:
            # Uninstall corpus from Strix using Sparv
            info_obj.job.uninstall_strix()
        except Exception as e:
            return utils.response(f"Failed to remove corpus '{resource_id}' from Strix", err=True, info=str(e),
                                  return_code="failed_removing_strix"), 500

    try:
        # Remove from storage
        corpus_dir = str(storage.get_corpus_dir(resource_id))
        storage.remove_dir(corpus_dir, resource_id)
    except Exception as e:
        return utils.response(f"Failed to remove corpus '{resource_id}' from storage", err=True, info=str(e),
                              return_code="failed_removing_storage"), 500

    try:
        # Remove from auth system
        login.remove_resource(auth_token, resource_id)
    except Exception as e:
        return utils.response(f"Failed to remove corpus '{resource_id}' from authentication system", err=True,
                              info=str(e), return_code="failed_removing_auth"), 500

    # Remove from Mink registry
    try:
        info_obj.remove()
    except Exception as err:
        app.logger.error(f"Failed to remove job '{resource_id}'. {err}")
    return utils.response(f"Corpus '{resource_id}' successfully removed", return_code="removed_corpus")


# ------------------------------------------------------------------------------
# Source file operations
# ------------------------------------------------------------------------------

@bp.route("/upload-sources", methods=["PUT"])
@login.login()
def upload_sources(resource_id: str):
    """Upload corpus source files.

    Attached files will be added to the corpus or replace existing ones.
    """
    # Check if corpus files were provided
    files = list(request.files.listvalues())
    if not files:
        return utils.response("No corpus files provided for upload", err=True,
                              return_code="missing_sources_upload"), 400

    # Check request size constraint
    try:
        source_dir = storage.get_source_dir(resource_id)
        if not utils.check_size_ok(source_dir, request.content_length):
            h_max_size = str(round(app.config.get("MAX_CORPUS_LENGTH", 0) / 1024 / 1024, 2))
            return utils.response(f"Failed to upload source files to '{resource_id}'. "
                                  f"Max corpus size ({h_max_size} MB) exceeded",
                                  info="max corpus size exceeded",
                                  err=True, max_corpus_size=app.config.get("MAX_CORPUS_LENGTH"),
                                  return_code="failed_uploading_sources_corpus_size"), 403
    except Exception as e:
        return utils.response(f"Failed to upload source files to '{resource_id}'", err=True, info=str(e),
                              return_code="failed_uploading_sources"), 500

    try:
        h_max_file_size = str(round(app.config.get("MAX_FILE_LENGTH", 0) / 1024 / 1024, 2))
        file_extension_warnings = []
        # Upload data
        for f in files[0]:
            name = sparv_utils.secure_filename(f.filename)
            if Path(name).suffix.lower() != Path(name).suffix:
                new_name = str(Path(name).stem + Path(name).suffix.lower())
                file_extension_warnings.append((name, new_name))
                name = new_name
            if not utils.check_file_ext(name, app.config.get("SPARV_IMPORTER_MODULES", {}).keys()):
                return utils.response(f"Failed to upload some source files to '{resource_id}' due to invalid "
                                      "file extension", err=True, file=f.filename, info="invalid file extension",
                                      return_code="failed_uploading_sources_invalid_file_extension"), 400
            compatible, current_ext, existing_ext = utils.check_file_compatible(name, source_dir)
            if not compatible:
                return utils.response(f"Failed to upload some source files to '{resource_id}' due to incompatible "
                                      "file extensions", err=True, file=f.filename, info="incompatible file extensions",
                                      current_file_extension=current_ext, existing_file_extension=existing_ext,
                                      return_code="failed_uploading_sources_incompatible_file_extension"), 400
            file_contents = f.read()

            # Check file size constraint
            if len(file_contents) > app.config.get("MAX_FILE_LENGTH"):
                return utils.response(f"Failed to upload some source files to '{resource_id}'. "
                                      f"Max file size ({h_max_file_size} MB) exceeded",
                                      info="max file size exceeded",
                                      err=True, file=f.filename, max_file_size=app.config.get("MAX_FILE_LENGTH"),
                                      return_code="failed_uploading_sources_file_size"), 403

            # Validate XML files
            if current_ext == ".xml":
                if not utils.validate_xml(file_contents):
                    return utils.response(f"Failed to upload some source files to '{resource_id}' due to invalid XML",
                                          err=True, file=f.filename, info="invalid XML",
                                          return_code="failed_uploading_sources_invalid_xml"), 400
            storage.write_file_contents(str(source_dir / name), file_contents, resource_id)

        res = registry.get(resource_id).resource
        res.set_source_files()

        # Check if file names have been changed and produce a warning
        warnings = ""
        if file_extension_warnings:
            name_changes = "'" + "', '".join(name for name, _ in file_extension_warnings) + "'"
            warnings = (f"File extensions need to be in lower case! The following files have received new names during "
                        f"upload: {name_changes}. This may lead to existing files being replaced.")

        return utils.response(f"Source files successfully added to '{resource_id}'", warnings=warnings,
                              return_code="uploaded_sources")
    except Exception as e:
        return utils.response(f"Failed to remove object '{resource_id}' from registry", err=True, info=str(e),
                              return_code="failed_uploading_sources"), 500


@bp.route("/list-sources", methods=["GET"])
@login.login()
def list_sources(resource_id: str):
    """List the available corpus source files."""
    source_dir = str(storage.get_source_dir(resource_id))
    try:
        objlist = storage.list_contents(source_dir)
        return utils.response(f"Listing current source files for '{resource_id}'", contents=objlist,
                              return_code="listing_sources")
    except Exception as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              retrun_code="failed_listing_sources"), 500


@bp.route("/remove-sources", methods=["DELETE"])
@login.login()
def remove_sources(resource_id: str):
    """Remove file paths listed in 'remove' (comma separated) from the corpus."""
    remove_files = request.args.get("remove") or request.form.get("remove") or ""
    remove_files = [i.strip() for i in remove_files.split(",") if i]
    if not remove_files:
        return utils.response("No files provided for removal", err=True,
                              return_code="missing_sources_remove"), 400

    source_dir = storage.get_source_dir(resource_id)

    # Remove files
    successes = []
    fails = []
    for rf in remove_files:
        storage_path = str(source_dir / Path(rf))
        try:
            storage.remove_file(storage_path, resource_id)
            successes.append(rf)
        except Exception:
            fails.append(rf)

    if fails and successes:
        return utils.response(f"Failed to remove some source files form '{resource_id}'",
                              failed=fails, succeeded=successes, err=True,
                              return_code="failed_removing_some_sources"), 500
    if fails:
        return utils.response(f"Failed to remove source files form '{resource_id}'", err=True,
                              return_code="failed_removing_sources"), 500

    res = registry.get(resource_id).resource
    res.set_source_files()

    return utils.response(f"Source files for '{resource_id}' successfully removed", return_code="removed_sources")


@bp.route("/download-sources", methods=["GET"])
@login.login()
def download_sources(resource_id: str):
    """Download the corpus source files as a zip file.

    The parameter 'file' may be used to download a specific source file. This
    parameter must either be a file name or a path on the storage server. The `zip`
    parameter may be set to `false` in combination with the `file` param to avoid
    zipping the file to be downloaded.
    """
    download_file = request.args.get("file") or request.form.get("file") or ""

    # Check if there are any source files
    storage_source_dir = str(storage.get_source_dir(resource_id))
    try:
        source_contents = storage.list_contents(storage_source_dir, exclude_dirs=False)
        if source_contents == []:
            return utils.response(f"You have not uploaded any source files for corpus '{resource_id}'", err=True,
                                  return_code="missing_sources_download"), 404
    except Exception as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    local_source_dir = utils.get_source_dir(resource_id, mkdir=True)
    local_corpus_dir = utils.get_resource_dir(resource_id, mkdir=True)

    # Download and zip file specified in args
    if download_file:
        download_file_name = Path(download_file).name
        full_download_file = str(Path(storage_source_dir) / download_file)
        if download_file not in [i.get("path") for i in source_contents]:
            return utils.response(f"The source file you are trying to download does not exist",
                                  err=True, return_code="source_not_found"), 404
        try:
            local_path = local_source_dir / download_file_name
            zipped = request.args.get("zip", "") or request.form.get("zip", "")
            zipped = not zipped.lower() == "false"
            storage.download_file(full_download_file, local_path, resource_id)
            if zipped:
                outf = str(local_corpus_dir / Path(f"{resource_id}_{download_file_name}.zip"))
                utils.create_zip(local_path, outf, zip_rootdir=resource_id)
                return send_file(outf, mimetype="application/zip")
            else:
                # Determine content type
                content_type = "application/xml"
                for file_obj in source_contents:
                    if file_obj.get("name") == download_file_name:
                        content_type = file_obj.get("type")
                        break
                return send_file(local_path, mimetype=content_type)
        except Exception as e:
            return utils.response(f"Failed to download file", err=True, info=str(e),
                                  return_code="failed_downloading_file"), 500

    # Download all files as zip archive
    try:
        zip_out = str(local_corpus_dir / f"{resource_id}_source.zip")
        # Get files from storage server
        storage.download_dir(storage_source_dir, local_source_dir, resource_id, zipped=True, zippath=zip_out)
        return send_file(zip_out, mimetype="application/zip")
    except Exception as e:
        return utils.response(f"Failed to download source files for corpus '{resource_id}'", err=True,
                              info=str(e), return_code="failed_downloading_sources"), 500


# ------------------------------------------------------------------------------
# Config file operations
# ------------------------------------------------------------------------------

@bp.route("/upload-config", methods=["PUT"])
@login.login()
def upload_config(resource_id: str):
    """Upload a corpus config as file or plain text."""
    def set_corpus_name(corpus_name):
        res = registry.get(resource_id).resource
        res.set_resource_name = corpus_name

    attached_files = list(request.files.values())
    config_txt = request.args.get("config") or request.form.get("config") or ""

    if attached_files and config_txt:
        return utils.response("Found both a config file and a plain text config but can only process one of these",
                              err=True, return_code="too_many_params_upload_config"), 400

    source_dir = str(storage.get_source_dir(resource_id))
    source_files = storage.list_contents(str(source_dir))

    # Process uploaded config file
    if attached_files:
        # Check if config file is YAML
        config_file = attached_files[0]
        if config_file.mimetype not in ("application/x-yaml", "text/yaml"):
            return utils.response("Config file needs to be YAML", err=True, return_code="wrong_config_format"), 400

        config_contents = config_file.read()

        # Check if config file is compatible with the uploaded source files
        if source_files:
            compatible, resp = utils.config_compatible(config_contents, source_files[0])
            if not compatible:
                return resp, 400

        try:
            new_config, corpus_name = utils.standardize_config(config_contents, resource_id)
            set_corpus_name(corpus_name)
            storage.write_file_contents(str(storage.get_config_file(resource_id)), new_config.encode("UTF-8"), resource_id)
            return utils.response(f"Config file successfully uploaded for '{resource_id}'",
                                  return_code="uploaded_config"), 201
        except Exception as e:
            return utils.response(f"Failed to upload config file for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_uploading_config"), 500

    elif config_txt:
        try:
            # Check if config file is compatible with the uploaded source files
            if source_files:
                compatible, resp = utils.config_compatible(config_txt, source_files[0])
                if not compatible:
                    return resp, 400
            new_config, corpus_name = utils.standardize_config(config_txt, resource_id)
            set_corpus_name(corpus_name)
            storage.write_file_contents(str(storage.get_config_file(resource_id)), new_config.encode("UTF-8"), resource_id)
            return utils.response(f"Config file successfully uploaded for '{resource_id}'",
                                  return_code="uploaded_config"), 201
        except Exception as e:
            return utils.response(f"Failed to upload config file for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_uploading_config"), 500

    else:
        return utils.response("No config file provided for upload", err=True, return_code="missing_config_upload"), 400


@bp.route("/download-config", methods=["GET"])
@login.login()
def download_config(resource_id: str):
    """Download the corpus config file."""
    storage_config_file = str(storage.get_config_file(resource_id))
    # Create directory for the current resource locally (on Mink backend server)
    utils.get_source_dir(resource_id, mkdir=True)
    local_config_file = utils.get_config_file(resource_id)

    try:
        # Get file from storage
        if storage.download_file(storage_config_file, local_config_file, resource_id, ignore_missing=True):
            return send_file(local_config_file, mimetype="text/yaml")
        else:
            return utils.response(f"No config file found for corpus '{resource_id}'", err=True,
                                  return_code="config_not_found"), 404
    except Exception as e:
        return utils.response(f"Failed to download config file for corpus '{resource_id}'", err=True, info=str(e),
                              return_code="failed_downloading_config"), 500


# ------------------------------------------------------------------------------
# Export file operations
# ------------------------------------------------------------------------------

@bp.route("/list-exports", methods=["GET"])
@login.login()
def list_exports(resource_id: str):
    """List exports available for download for a given corpus."""
    path = str(storage.get_export_dir(resource_id))
    try:
        objlist = storage.list_contents(path, blacklist=app.config.get("SPARV_EXPORT_BLACKLIST"))
        return utils.response(f"Listing current export files for '{resource_id}'", contents=objlist,
                              return_code="listing_exports")
    except Exception as e:
        return utils.response(f"Failed to list export files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_exports"), 500


@bp.route("/download-exports", methods=["GET"])
@login.login()
def download_export(resource_id: str):
    """Download export files for a corpus as a zip file.

    The parameters 'file' and 'dir' may be used to download a specific export file or a directory of export files. These
    parameters must be supplied as  paths relative to the export directory. The `zip` parameter may be set to `false` in
    combination with the `file` param to avoid zipping the file to be downloaded.
    """
    download_file = request.args.get("file") or request.form.get("file") or ""
    download_folder = request.args.get("dir") or request.form.get("dir") or ""

    if download_file and download_folder:
        return utils.response("The parameters 'dir' and 'file' must not be supplied simultaneously", err=True,
                              return_code="too_many_params_download_exports"), 400

    storage_export_dir = str(storage.get_export_dir(resource_id))
    local_corpus_dir = utils.get_resource_dir(resource_id, mkdir=True)
    local_export_dir = utils.get_export_dir(resource_id, mkdir=True)
    blacklist = app.config.get("SPARV_EXPORT_BLACKLIST")

    try:
        export_contents = storage.list_contents(storage_export_dir, exclude_dirs=False, blacklist=blacklist)
        if export_contents == []:
            return utils.response(f"There are currently no exports available for corpus '{resource_id}'", err=True,
                                  return_code="no_exports_available"), 404
    except Exception as e:
        return utils.response(f"Failed to download exports for corpus '{resource_id}'", err=True, info=str(e),
                              return_code="failed_downloading_exports"), 500

    # Download all export files
    if not (download_file or download_folder):
        try:
            zip_out = str(local_corpus_dir / f"{resource_id}_export.zip")
            # Get files from storage server
            storage.download_dir(storage_export_dir, local_export_dir, resource_id, zipped=True, zippath=zip_out,
                                 excludes=blacklist)
            return send_file(zip_out, mimetype="application/zip")
        except Exception as e:
            return utils.response(f"Failed to download exports for corpus '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_downloading_exports"), 500

    # Download and zip folder specified in args
    if download_folder:
        download_folder_name = "_".join(Path(download_folder).parts)
        full_download_folder = str(Path(storage_export_dir) / download_folder)
        if download_folder not in [i.get("path") for i in export_contents]:
            return utils.response(f"The export folder you are trying to download does not exist",
                                  err=True, return_code="export_folder_not_found"), 404
        try:
            zip_out = str(local_corpus_dir / f"{resource_id}_{download_folder_name}.zip")
            (local_export_dir / download_folder).mkdir(exist_ok=True)
            storage.download_dir(full_download_folder, local_export_dir / download_folder, resource_id,
                                 zipped=True, zippath=zip_out)
            return send_file(zip_out, mimetype="application/zip")
        except Exception as e:
            return utils.response(f"Failed to download export folder", err=True, info=str(e),
                                  return_code="failed_downloading_export_folder"), 500

    # Download and zip file specified in args
    if download_file:
        download_file_name = Path(download_file).name
        full_download_file = str(Path(storage_export_dir) / download_file)
        if download_file not in [i.get("path") for i in export_contents]:
            return utils.response(f"The file '{download_file}' you are trying to download does not exist",
                                  err=True, file=str(download_file), return_code="export_not_found"), 404
        try:
            local_path = local_export_dir / download_file
            (local_export_dir / download_file).parent.mkdir(exist_ok=True)
            zipped = request.args.get("zip", "") or request.form.get("zip", "")
            zipped = not zipped.lower() == "false"
            if zipped:
                outf = str(local_corpus_dir / Path(f"{resource_id}_{download_file_name}.zip"))
                storage.download_file(full_download_file, local_path, resource_id)
                utils.create_zip(local_path, outf, zip_rootdir=resource_id)
                return send_file(outf, mimetype="application/zip")
            else:
                storage.download_file(full_download_file, local_path, resource_id)
                # Determine content type
                content_type = "application/xml"
                for file_obj in export_contents:
                    if file_obj.get("name") == download_file_name:
                        content_type = file_obj.get("type")
                        break
                return send_file(local_path, mimetype=content_type)
        except Exception as e:
            return utils.response(f"Failed to download file", err=True, info=str(e),
                                  file=str(download_file), return_code="failed_downloading_file"), 500


@bp.route("/remove-exports", methods=["DELETE"])
@login.login()
def remove_exports(resource_id: str):
    """Remove export files."""
    if not storage.local:
        try:
            # Remove export dir from storage server and create a new empty one
            export_dir = str(storage.get_export_dir(resource_id))
            storage.remove_dir(export_dir, resource_id)
            storage.get_export_dir(resource_id, mkdir=True)
        except Exception as e:
            return utils.response(f"Failed to remove export files from storage server for corpus '{resource_id}'",
                                  err=True, info=str(e), return_code="failed_removing_exports_storage"), 500

    try:
        # Remove from Sparv server
        job = registry.get(resource_id).job
        success, sparv_output = job.clean_export()
        if not success:
            return utils.response(f"Failed to remove export files from Sparv server for corpus '{resource_id}'", err=True,
                                  info=str(sparv_output), return_code="failed_removing_exports_sparv"), 500
    except Exception as e:
        return utils.response(f"Failed to remove export files from Sparv server for corpus '{resource_id}'", err=True,
                              info=str(e), return_code="failed_removing_exports_sparv"), 500

    return utils.response(f"Export files for corpus '{resource_id}' successfully removed", return_code="removed_exports")


@bp.route("/download-source-text", methods=["GET"])
@login.login()
def download_source_text(resource_id: str):
    """Get one of the source files in plain text.

    The source file name (including its file extension) must be specified in the 'file' parameter.
    """
    download_file = request.args.get("file") or request.form.get("file") or ""

    storage_work_dir = str(storage.get_work_dir(resource_id))
    local_corpus_dir = str(utils.get_resource_dir(resource_id, mkdir=True))

    if not download_file:
        return utils.response("No source file specified for download", err=True,
                              return_code="missing_sources_download_text"), 400

    try:
        source_texts = storage.list_contents(storage_work_dir, exclude_dirs=False)
        if source_texts == []:
            return utils.response(f"There are currently no source texts for corpus '{resource_id}'. "
                                   "You must run Sparv before you can view source texts.", err=True,
                                   return_code="no_source_texts_run_sparv"), 404
    except Exception as e:
        return utils.response(f"Failed to download source text", err=True, info=str(e),
                              return_code="failed_downloading_source_text"), 500

    # Download file specified in args
    download_file_stem = Path(download_file).stem
    short_path = str(Path(download_file_stem) / app.config.get("SPARV_PLAIN_TEXT_FILE"))
    if short_path not in [i.get("path") for i in source_texts]:
        return utils.response(f"The source text for this file does not exist",
                              err=True, return_code="source_text_not_found"), 404
    try:
        full_download_path = str(Path(storage_work_dir) / Path(download_file).parent / download_file_stem /
                                app.config.get("SPARV_PLAIN_TEXT_FILE"))
        out_file_name = download_file_stem + "_plain.txt"
        local_path = Path(local_corpus_dir) / out_file_name
        storage.download_file(full_download_path, local_path, resource_id)
        utils.uncompress_gzip(local_path)
        return send_file(local_path, mimetype="text/plain")
    except Exception as e:
        return utils.response(f"Failed to download source text", err=True, info=str(e),
                              return_code="failed_downloading_source_text"), 500


@bp.route("/check-changes", methods=["GET"])
@login.login()
def check_changes(resource_id: str):
    """Check if config or source files have changed since the last job was started."""
    try:
        job = registry.get(resource_id).job
    except Exception as e:
        return utils.response(f"Failed to get job for corpus '{resource_id}'", err=True, info=str(e),
                              return_code="failed_getting_job"), 500
    try:
        added_sources, changed_sources, deleted_sources, changed_config = storage.get_file_changes(resource_id, job)
        if added_sources or changed_sources or deleted_sources or changed_config:
            return utils.response(f"Your input for the corpus '{resource_id}' has changed since the last run",
                                  config_changed=bool(changed_config), sources_added=bool(added_sources),
                                  sources_changed=bool(changed_sources), sources_deleted=bool(deleted_sources),
                                  changed_config=changed_config, added_sources=added_sources,
                                  changed_sources=changed_sources, deleted_sources=deleted_sources,
                                  last_run_started=job.started,
                                  return_code="input_changed")
        return utils.response(f"Your input for the corpus '{resource_id}' has not changed since the last run",
                              last_run_started=job.started, return_code="input_not_changed")

    except exceptions.JobNotFound:
        return utils.response(f"Corpus '{resource_id}' has not been run", return_code="corpus_not_run")

    except exceptions.CouldNotListSources as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    except Exception as e:
        return utils.response(f"Failed to check changes for corpus '{resource_id}'", err=True, info=str(e),
                              return_code="failed_checking_changes"), 500
