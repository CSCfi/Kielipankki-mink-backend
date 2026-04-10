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

    # Make corpus protected and add Korp config directory
    config_yaml["korp"] = {
        "protected": True,
        "modes": [{"name": "mink"}],
        # Include all annotations even if they lack a Korp preset file on the server
        "keep_undefined_annotations": True,
        # Derive Korp UI languages from the language codes present in the corpus name
        "languages": list(name.keys()) if name else ["eng"],
    }

    # Extract the CWB attribute name from an annotation string: if it has an "as <name>"
    # alias, use that; otherwise fall back to the part after the last dot (module namespace stripped).
    def _cwb_attr_name(annotation_str: str) -> str:
        if " as " in annotation_str:
            return annotation_str.split(" as ")[-1].strip()
        return annotation_str.split(".")[-1].strip()

    export_annotations = config_yaml.get("export", {}).get("annotations", [])

    # Build annotation_definitions to override preset matching for certain attributes.
    # The Korp config exporter matches CWB attribute names to preset YAML files by name;
    # we need to redirect some attributes to different presets or inline definitions to
    # avoid mismatches (e.g. CWB attr "pos" would otherwise match the Swedish SUC pos.yaml,
    # and "deprel" has no preset but should use deprel_trankit.yaml).
    annotation_defs = {}
    for ann_str in export_annotations:
        ann = str(ann_str)
        # The Sparv annotation name is everything before " as " (or the whole string)
        sparv_name = ann.split(" as ")[0].strip()
        cwb_name = _cwb_attr_name(ann)
        # Map trankit deprel → deprel_trankit preset (UD dependency relations dropdown)
        if "trankit.deprel" in ann and cwb_name == "deprel":
            annotation_defs[sparv_name] = "deprel_trankit"
        # Map any annotation exported as "pos" → inline label to avoid the Swedish SUC pos.yaml preset
        elif cwb_name == "pos":
            annotation_defs[sparv_name] = {
                "label": {"eng": "part of speech", "fin": "sanaluokka", "swe": "ordklass"},
                "order": 2,
            }
        # Show dephead (sentence-relative head index) instead of hiding it
        elif cwb_name == "dephead":
            annotation_defs[sparv_name] = {
                "label": {"eng": "dependency head", "fin": "pääsana", "swe": "dephead"},
                "order": 5,
            }
    if annotation_defs:
        config_yaml["korp"]["annotation_definitions"] = annotation_defs

    if app.config.get("KORP_REMOTE_HOST"):
        config_yaml["korp"]["remote_host"] = app.config.get("KORP_REMOTE_HOST")
    if app.config.get("KORP_CONFIG_DIR"):
        config_yaml["korp"]["config_dir"] = app.config.get("KORP_CONFIG_DIR")

    # Add CWB (Corpus Workbench) configuration
    cwb_config = {}
    if app.config.get("CWB_REMOTE_HOST"):
        cwb_config["remote_host"] = app.config.get("CWB_REMOTE_HOST")
    if app.config.get("CWB_REMOTE_REGISTRY_DIR"):
        cwb_config["remote_registry_dir"] = app.config.get("CWB_REMOTE_REGISTRY_DIR")
    if app.config.get("CWB_REMOTE_DATA_DIR"):
        cwb_config["remote_data_dir"] = app.config.get("CWB_REMOTE_DATA_DIR")
    # Forward export.annotations to cwb.annotations so that all annotated attributes
    # are encoded in the CWB corpus and exposed in the Korp corpus config.
    export_anns = config_yaml.get("export", {}).get("annotations", [])
    if export_anns:
        cwb_config["annotations"] = list(export_anns)
    if cwb_config:
        config_yaml["cwb"] = cwb_config
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
