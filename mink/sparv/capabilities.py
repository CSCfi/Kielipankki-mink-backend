"""Durable on-disk cache of Sparv's capability listings (languages, annotators, exports).

These listings are slow to generate (an SSH round-trip to the Sparv host, ~15 s) but
only change when Sparv itself is (re)deployed. They are therefore NOT kept in memcached
(see mink.memcached.cache): a volatile cache whose eviction or restart was exactly what
made the create-corpus view fall back to the slow Sparv round-trip and briefly show the
wrong languages/annotators. Instead each listing lives in a JSON file in the Flask
instance dir, generated as a deploy step (see the /refresh-sparv-capabilities route) and
read back on every request. A few-KB page-cached read is fast enough for an endpoint hit
only when opening the create/config views, and it survives memcached evictions, restarts
and the recurring memcached degradation. A missing file (None) just means "not generated
yet".
"""

import json
import os
from pathlib import Path

from flask import current_app as app


def _path(config_key):
    """Path to a capability file in the instance dir, named by the given config key."""
    return Path(app.instance_path) / app.config.get(config_key)


def _read(config_key):
    """Read and parse a capability JSON file, or None if missing/unreadable."""
    path = _path(config_key)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        app.logger.error(f"Failed to read capability file {path}! {str(e)}")
        return None


def _write(config_key, value):
    """Atomically write a capability JSON file (rename so readers never see a partial file)."""
    path = _path(config_key)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(value, f)
        os.replace(tmp, path)
    except OSError as e:
        app.logger.error(f"Failed to write capability file {path}! {str(e)}")


def get_languages():
    """Get the cached Sparv language list, or None if not yet generated."""
    return _read("SPARV_LANGUAGES_FILE")


def set_languages(value):
    """Store the Sparv language list."""
    _write("SPARV_LANGUAGES_FILE", value)


def get_annotators():
    """Get the cached Sparv annotator info, or None if not yet generated."""
    return _read("SPARV_ANNOTATORS_FILE")


def set_annotators(value):
    """Store the Sparv annotator info."""
    _write("SPARV_ANNOTATORS_FILE", value)


def get_exports(language):
    """Get the cached Sparv exports for 'language', or None if not yet generated."""
    return (_read("SPARV_EXPORTS_FILE") or {}).get(language)


def set_exports(language, value):
    """Store the Sparv exports for 'language' (merged into the per-language map)."""
    by_language = _read("SPARV_EXPORTS_FILE") or {}
    by_language[language] = value
    _write("SPARV_EXPORTS_FILE", by_language)
