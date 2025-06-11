"""General utility functions."""

import functools
import gzip
import json
import subprocess
import zipfile
from pathlib import Path

import yaml
from flask import Response
from flask import current_app as app
from flask import g, request

from mink.sparv import storage


def response(msg, err=False, **kwargs):
    """Create json error response."""
    # Log error
    if err:
        args = "\n".join(f"{k}: {v}" for k, v in kwargs.items() if v != "")
        args = "\n" + args if args else ""
        app.logger.error(f"{msg}{args}")

    res = {"status": "error" if err else "success", "message": msg}
    for key, value in kwargs.items():
        if value != "":
            res[key] = value
    return Response(json.dumps(res, ensure_ascii=False), mimetype="application/json")


def gatekeeper(function):
    """Make sure that only the protected user can access the decorated endpoint."""
    @functools.wraps(function)  # Copy original function's information, needed by Flask
    def decorator(*args, **kwargs):
        secret_key = request.args.get("secret_key") or request.form.get("secret_key")
        if secret_key != app.config.get("MINK_SECRET_KEY"):
            return response("Failed to confirm secret key for protected route", err=True,
                            return_code="failed_confirming_secret_key"), 401
        return function(*args, **kwargs)
    return decorator


def ssh_run(command, input=None):
    """Execute 'command' on server and return process."""
    user = app.config.get("SPARV_USER")
    host = app.config.get("SPARV_HOST")
    p = subprocess.run(["ssh", "-i", app.config.get("SSH_KEY"), f"{user}@{host}", command],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input)
    return p


def uncompress_gzip(inpath, outpath=None):
    """Uncompress file with with gzip and safe to outpath (or inpath if no outpath is given."""
    with gzip.open(inpath, "rb") as z:
        data = z.read()
        if outpath is None:
            outpath = inpath
        with open(outpath, "wb") as f:
            f.write(data)


def create_zip(inpath, outpath, zip_rootdir=None):
    """Zip files in inpath into an archive at outpath.

    zip_rootdir: name that the root folder inside the zip file should be renamed to.
    """
    zipf = zipfile.ZipFile(outpath, "w")
    if Path(inpath).is_file():
        zipf.write(inpath, Path(inpath).name)
    else:
        for filepath in Path(inpath).rglob("*"):
            zippath = filepath.relative_to(Path(inpath).parent)
            if zip_rootdir:
                zippath = Path(zip_rootdir) / Path(*zippath.parts[1:])
            zipf.write(filepath, zippath)
    zipf.close()


def check_file_ext(filename, valid_extensions=None) -> bool:
    """Check if file extension is valid."""
    filename = Path(filename)
    if valid_extensions:
        if not any(i.lower() == filename.suffix.lower() for i in valid_extensions):
            return False
    return True


def check_file_compatible(filename, source_dir):
    """Check if the file extension of filename is identical to the first file in source_dir."""
    existing_files = storage.list_contents(str(source_dir))
    current_ext = Path(filename).suffix
    if not existing_files:
        return True, current_ext, None
    existing_ext = Path(existing_files[0].get("name")).suffix
    return current_ext == existing_ext, current_ext, existing_ext


def check_size_ok(source_dir, incoming_size):
    """Check if the size of the incoming files exceeds the max corpus size."""
    if app.config.get("MAX_CORPUS_LENGTH") is not None:
        current_size = storage.get_size(str(source_dir))
        total_size = current_size + incoming_size
        if total_size > app.config.get("MAX_CORPUS_LENGTH"):
            return False
    return True


def validate_xml(file_contents):
    """Check if inputfile is valid XML."""
    import xml.etree.ElementTree as etree
    try:
        etree.fromstring(file_contents)
        return True
    except etree.ParseError:
        return False


def config_compatible(config, source_file):
    """Check if the importer module in the corpus config is compatible with the source files."""
    file_ext = Path(source_file.get("name")).suffix
    config_yaml = yaml.load(config, Loader=yaml.FullLoader)
    current_importer = config_yaml.get("import", {}).get("importer", "").split(":")[0] or None
    importer_dict = app.config.get("SPARV_IMPORTER_MODULES", {})

    # If no importer is specified xml is default
    if current_importer is None and file_ext == ".xml":
        return True, None

    expected_importer = importer_dict.get(file_ext)
    if current_importer == expected_importer:
        return True, None
    return False, response("The importer in your config file is not compatible with your source files",
                            err=True, current_importer=current_importer, expected_importer=expected_importer,
                            return_code="incompatible_config_importer")


def standardize_config(config, corpus_id):
    """Set the correct corpus ID and remove the compression setting in the corpus config."""
    config_yaml = yaml.load(config, Loader=yaml.FullLoader)

    # Set correct corpus ID
    if config_yaml.get("metadata", {}).get("id") != corpus_id:
        if not config_yaml.get("metadata"):
            config_yaml["metadata"] = {}
        config_yaml["metadata"]["id"] = corpus_id

    # Get corpus name
    name = config_yaml.get("metadata", {}).get("name", {})

    # Remove the compression setting in order to use the standard one given by the default config
    if config_yaml.get("sparv", {}).get("compression") != None:
        config_yaml["sparv"].pop("compression")
        # Remove entire Sparv section if empty
        if not config_yaml.get("sparv", {}):
            config_yaml.pop("sparv")

    # Remove settings that a Mink user is not allowed to modify
    config_yaml.pop("cwb", None)
    config_yaml.pop("korp", None)
    config_yaml.pop("sbx_strix", None)
    # Remove all install and uninstall targets (this is handled in the installation step instead)
    config_yaml.pop("install", None)
    config_yaml.pop("uninstall", None)

    # Make corpus protected
    config_yaml["korp"] = {"protected": True}
    # Make Strix corpora appear in correct mode
    # Next lines commented out to remove strix from configs
    # config_yaml["sbx_strix"] = {"modes": [{"name": "mink"}]}
    # # Add '<text>:misc.id as _id' to annotations for Strix' sake
    # if "export" in config_yaml and "annotations" in config_yaml["export"]:
    #     if "<text>:misc.id as _id" not in config_yaml["export"]["annotations"]:
    #         config_yaml["export"]["annotations"].append("<text>:misc.id as _id")

    return yaml.dump(config_yaml, sort_keys=False, allow_unicode=True), name


def standardize_metadata_yaml(yamlf):
    """Get resource name from metadata yaml and remove comments etc."""
    yaml_contents = yaml.load(yamlf, Loader=yaml.FullLoader)

    # Get resource name
    name = yaml_contents.get("name", {})

    return yaml.dump(yaml_contents, sort_keys=False, allow_unicode=True), name


################################################################################
# Get local paths (mostly used for download)
################################################################################

def get_resources_dir(mkdir: bool = False) -> Path:
    """Get user specific dir for corpora."""
    resources_dir = Path(app.instance_path) / Path(app.config.get("TMP_DIR")) / g.request_id
    if mkdir:
        resources_dir.mkdir(parents=True, exist_ok=True)
    return resources_dir

def get_resource_dir(resource_id: str, mkdir: bool = False) -> Path:
    """Get dir for given resource."""
    resources_dir = get_resources_dir(mkdir=mkdir)
    resdir = resources_dir / Path(resource_id)
    if mkdir:
        resdir.mkdir(parents=True, exist_ok=True)
    return resdir

def get_export_dir(corpus_id: str, mkdir: bool = False) -> Path:
    """Get export dir for given resource."""
    resdir = get_resource_dir(corpus_id, mkdir=mkdir)
    export_dir = resdir / Path(app.config.get("SPARV_EXPORT_DIR"))
    if mkdir:
        export_dir.mkdir(parents=True, exist_ok=True)
    return export_dir


def get_work_dir(corpus_id: str, mkdir: bool = False) -> Path:
    """Get sparv workdir for given corpus."""
    resdir = get_resource_dir(corpus_id, mkdir=mkdir)
    work_dir = resdir / Path(app.config.get("SPARV_WORK_DIR"))
    if mkdir:
        work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir


def get_source_dir(corpus_id: str, mkdir: bool = False) -> Path:
    """Get source dir for given corpus."""
    resdir = get_resource_dir(corpus_id, mkdir=mkdir)
    source_dir = resdir / Path(app.config.get("SPARV_SOURCE_DIR"))
    if mkdir:
        source_dir.mkdir(parents=True, exist_ok=True)
    return source_dir


def get_config_file(corpus_id: str) -> Path:
    """Get path to corpus config file."""
    resdir = get_resource_dir(corpus_id)
    return resdir / Path(app.config.get("SPARV_CORPUS_CONFIG"))


def get_metadata_yaml_file(resource_id: str) -> Path:
    """Get path to local metadata yaml file."""
    resdir = get_resource_dir(resource_id)
    return resdir / (resource_id + ".yaml")
