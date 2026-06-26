"""Generate the durable on-disk cache of Sparv's capability listings.

Run as a deploy step (a oneshot, before the backend starts), NOT as part of the
gunicorn server. Sparv's languages, annotators and exports only change when Sparv
itself is (re)deployed, so they are generated once here by querying the Sparv host
over SSH and written to JSON files in the Flask instance dir. The backend request
path then only ever reads those files (see mink.sparv.capabilities), so the
create-corpus view is instant and correct even when memcached is unavailable.

This boots a real create_app() context so it reuses the exact config loading,
instance-path resolution and Sparv output parsing of the running backend, rather
than duplicating any of it.
"""

import sys

from mink import create_app
from mink.core.jobs import DefaultJob

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        try:
            languages, annotators = DefaultJob().refresh_capabilities()
        except Exception as e:
            app.logger.error(f"Failed to generate Sparv capabilities: {e}")
            print(f"Failed to generate Sparv capabilities: {e}", file=sys.stderr)
            sys.exit(1)
        msg = (f"Generated Sparv capabilities: {len(languages)} languages, "
               f"{len(annotators)} annotator modules")
        app.logger.info(msg)
        print(msg)
