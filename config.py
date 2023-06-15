"""Default configuration for mink.

Can be overridden with config.py in instance folder.
"""

LOG_LEVEL = "INFO"   # Log level for the application

# Prefix used when creating new resources
RESOURCE_PREFIX = "mink-"

# File upload settings
MAX_CONTENT_LENGTH = 1024 * 1024 * 100 # Max size (bytes) for one request (which may contain multiple files)
MAX_FILE_LENGTH = 1024 * 1024 * 10     # Max size (bytes) for one corpus source file
MAX_CORPUS_LENGTH = 1024 * 1024 * 500  # Max size (bytes) for one corpus
RECOMMENDED_MIN_FILE_LENGTH = 1024 * 1024 * 1 # Recommended min size (bytes) for one corpus source file (when uploading may files)
RECOMMENDED_MAX_FILE_LENGTH = 1024 * 1024 * 5 # Recommended max size (bytes) for one corpus source file

# sb-auth settings
SBAUTH_PUBKEY_FILE = "pubkey.pem"
SBAUTH_URL = "https://spraakbanken.gu.se/auth/resources/resource/"
SBAUTH_API_KEY = ""
SBAUTH_MINK_APP_RESOURCE = "mink-app" # Name of the resource used to control admin grants

# Sparv specific strings and settings
SPARV_SOURCE_DIR = "source"
SPARV_EXPORT_DIR = "export"
SPARV_WORK_DIR = "sparv-workdir"
SPARV_CORPUS_CONFIG = "config.yaml"
SPARV_PLAIN_TEXT_FILE = "@text"
SPARV_IMPORTER_MODULES = {  # File extensions for corpus input and the modules that handle them
    ".xml": "xml_import",
    ".txt": "text_import",
    ".docx": "docx_import",
    ".odt": "odt_import",
    ".pdf": "pdf_import",
}

# Settings for the server where Sparv is run
SSH_KEY = "~/.ssh/id_rsa"
SPARV_HOST = ""  # Define this in instance/config.py!
SPARV_USER = ""    # Define this in instance/config.py!
SPARV_WORKERS = 1  # Number of available Sparv workers
SPARV_DEFAULT_CORPORA_DIR = "~/mink-data/default"  # Dir for running listings like 'sparv run -l'
SPARV_CORPORA_DIR = "mink-data"                    # Dir where the user corpora are stored and run, relative to the user's home dir
SPARV_ENVIRON = "SPARV_DATADIR=~/sparv-pipeline/data/"                       # Environment variables to set when running Sparv
SPARV_COMMAND = "~/sparv-pipeline/venv/bin/python -u -m sparv"               # Command for calling Sparv
SPARV_RUN = "run --socket ~/sparv-pipeline/sparv.socket --json-log --log-to-file info"  # Sparv's 'run' command
SPARV_INSTALL = "install --json-log --log-to-file info"                                 # Sparv's 'install' command
SPARV_UNINSTALL = "uninstall --log-to-file info"                            # Sparv's 'uninstall' command
SPARV_DEFAULT_EXPORTS = ["xml_export:pretty", "csv_export:csv", "stats_export:freq_list"]  # Default export format to create if nothing is specified
SPARV_EXPORT_BLACKLIST = [  # Glob patterns for exports that will be excluded from listings and downloads
    "cwb.*",
    "korp.*",
    "sbx_strix.*",
]
SPARV_DEFAULT_PREINSTALLS = ["korp:timespan_sql", "korp:config", "korp:lemgram_sql"]  # Default targets to create before installing (necessary when re-installing after file removal)
SPARV_DEFAULT_INSTALLS = ["korp:install_timespan", "korp:install_config", "korp:install_lemgrams"]  # Default install targets to create
SPARV_DEFAULT_UNINSTALLS = ["cwb:uninstall_corpus", "korp:uninstall_timespan", "korp:uninstall_config", "korp:uninstall_lemgrams"]  # Default uninstall targets
SPARV_NOHUP_FILE = "mink.out"                # File collecting Sparv output for a job
SPARV_TMP_RUN_SCRIPT = "run_sparv.sh"          # Temporary Sparv run script created for every job

# Local files relative to flask instance dir
TMP_DIR = "tmp"                      # Temporary file storage
MEMCACHED_SOCKET = "memcached.sock"  # Memcached socket file
QUEUE_DIR = "queue"                  # Directory for storing job files
QUEUE_FILE = "priorities"            # File to store the queue priorities
CORPUS_REGISTRY = "corpus_registry"  # Directory for storing corpus IDs

# Settings for queue manager
MINK_URL = "https://ws.spraakbanken.gu.se/ws/mink"  # URL for mink API
CHECK_QUEUE_FREQUENCY = 20  # How often the queue will be checked for new jobs (in seconds)
MINK_SECRET_KEY = ""  # Define this in instance/config.py!
HEALTHCHECKS_URL = ""   # Healthchecks URL, define this in instance/config.py!
PING_FREQUENCY = 60     # Frequency (in minutes) for how often healthchecks should be pinged
