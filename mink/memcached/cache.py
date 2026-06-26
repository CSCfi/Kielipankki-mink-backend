"""Caching with Memcached using app context as backoff solution."""

from pathlib import Path

from flask import current_app as app
from flask import g
from pymemcache import serde
from pymemcache.client.base import Client

from mink.core import registry


class Cache():
    """Cache class providing caching with Memcached (and app context as backoff)."""

    def __init__(self):
        """
        Init variables in app context (as backup for regular cache) and try to reconnect to cache if necessary.

        This is done before each request (app context g cannot be stored in between requests).
        """
        # Queue
        g.queue_initialized = False
        g.job_queue = []  # List of IDs of all active jobs
        g.all_resources = []  # All resource IDs
        g.resource_dict = {}  # All resource info objects

        self.client = None
        self.connect()

    def connect(self):
        """Connect to the memcached socket and set client."""
        socket_path = Path(app.instance_path) / app.config.get("MEMCACHED_SOCKET")
        try:
            self.client = Client(f"unix:{socket_path}", serde=serde.pickle_serde)
            # Check if connection is working
            self.client.get("test")
        except Exception as e:
            app.logger.error(f"Failed to connect to memcached! {str(e)}")
            self.client = None

    def set_queue_initialized(self, is_initialized):
        """Set 'queue_initialized' to bool 'is_initialized' in memcached (or app context)."""
        if self.client is not None:
            self.client.set("queue_initialized", bool(is_initialized))
        else:
            g.queue_initialized = bool(is_initialized)

    def registry_initialized(self):
        """Whether the resource registry has actually been loaded into the cache.

        This gates registry.initialize(). It checks the real data key
        ('all_resources') rather than the separate 'queue_initialized' flag,
        because the two are independent memcached keys that can diverge: memcached
        may evict the (larger) data under memory pressure while the small,
        frequently-read flag survives, and the flag is never reset to False. Gating
        on the flag alone therefore leaves the registry permanently empty until a
        manual memcached flush. An empty registry is stored as '[]', so only a
        missing key (None) means "not built" — this makes the gate self-heal after
        an eviction by triggering a fresh filesystem scan.

        Reads the key directly; must NOT call get_all_resources(), which re-enters
        registry.initialize().
        """
        if self.client is not None:
            return self.client.get("all_resources") is not None
        # App-context fallback: the data lives in g for this request only and is
        # rebuilt on every request, so the per-request flag is authoritative.
        return g.queue_initialized

    def get_job_queue(self):
        """Get entire job queue from memcached (or app context)."""
        registry.initialize()

        if self.client is not None:
            return self.client.get("job_queue")
        else:
            return g.job_queue

    def set_job_queue(self, value):
        """Set job queue in memcached (or app context)."""
        if self.client is not None:
            self.client.set("job_queue", value)
        else:
            g.job_queue = value

    def get_all_resources(self):
        """Get list of all jobs from memcached (or app context)."""
        registry.initialize()
        if self.client is not None:
            return self.client.get("all_resources")
        else:
            return g.all_resources

    def set_all_resources(self, value):
        """Set list of all jobs in memcached (or app context)."""
        if self.client is not None:
            self.client.set("all_resources", list(set(value)))
        else:
            g.all_resources = list(set(value))

    def get_job(self, job):
        """Get 'job' from memcached (or from resource_dict in app context) and return it."""
        registry.initialize()

        if self.client is not None:
            return self.client.get(job)
        else:
            return g.resource_dict.get(job)

    def set_job(self, job, value):
        """Set 'job' to 'value' in memcached (or in resource_dict in app context)."""
        registry.initialize()

        if self.client is not None:
            self.client.set(job, value)
        else:
            g.resource_dict[job] = value

    def remove_job(self, job):
        """Remove 'job' from memcached (or resource_dict in app context)."""
        registry.initialize()

        if self.client is not None:
            self.client.delete(job)
        else:
            del g.resource_dict[job]
