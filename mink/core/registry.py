"""Utilities related to the resource registry and job queue.

The registry and job queue live in the cache and also on the local file system (as backup).
"""

import json
from pathlib import Path
from typing import List

from flask import current_app as app
from flask import g

from mink.core import exceptions, info


def initialize():
    """Init the registry and job queue from the filesystem if it has not been initialized already."""
    if not g.cache.get_queue_initialized():
        app.logger.info("Initializing queue")
        all_resources = []  # Storage for all resource IDs
        registry_dir = Path(app.instance_path) / app.config.get("REGISTRY_DIR")
        registry_dir.mkdir(exist_ok=True)

        # Load queue priorities
        queue_file = registry_dir / Path(app.config.get("QUEUE_FILE"))
        if queue_file.is_file():
            with queue_file.open() as p:
                jsonstr = p.read()
                queue = json.loads(jsonstr) or []
        else:
            queue = []

        # Mark as initialized BEFORE the per-file scan, and pre-populate the
        # queue and all-resources keys so they are never observed as None.
        # The gate must be set before the scan because infoobj.update() below
        # writes to the cache via set_job, which re-enters initialize(); if
        # the gate were still False at that point the scan would recurse.
        g.cache.set_job_queue(queue)
        g.cache.set_all_resources(all_resources)
        g.cache.set_queue_initialized(True)

        # Load info instances into memory, append to queue if necessary
        for f in sorted(registry_dir.glob("*/*"), key=lambda x: x.stat().st_mtime):
            if f == queue_file:
                continue
            if f.is_file():
                with f.open() as fobj:
                    infoobj = info.load_from_str(fobj.read())
                    infoobj.update()  # Update resource in file system and add to cache
                    all_resources.append(infoobj.id)
                    # app.logger.debug(f"Job in cache: '{g.cache.get_job(job.id)}'")
                # Queue job unless it is done, aborted or erroneous
                if infoobj.id not in queue:
                    if not (infoobj.job.status.is_done(infoobj.job.current_process) or infoobj.job.status.is_inactive()):
                        queue.append(infoobj.job.id)
        g.cache.set_job_queue(queue)
        g.cache.set_all_resources(all_resources)
        app.logger.debug(f"Queue in cache: {g.cache.get_job_queue()}")
        # app.logger.debug(f"All jobs in cache: {g.cache.get_all_resources()}")
        app.logger.debug(f"Total resources in cache: {len(g.cache.get_all_resources())}")

def get_all_resources() -> str:
    """Get a list of all existing resource IDs."""
    return g.cache.get_all_resources()

def get(resource_id) -> info.Info:
    """Get an existing info instance from the cache."""
    if g.cache.get_job(resource_id) is not None:
        return info.load_from_str(g.cache.get_job(resource_id))
    else:
        raise exceptions.JobNotFound(f"No resource found with ID '{resource_id}'!")

def filter_resources(resource_ids: list = None) -> List[info.Info]:
    """Get info for all resources listed in 'resource_ids'."""
    filtered_resources = []
    all_resources = g.cache.get_all_resources()
    # all_resources is None before the registry is done initializing
    if all_resources is None:
        return filtered_resources
    for res_id in all_resources:
        if resource_ids is not None and res_id not in resource_ids:
            continue
        infoobj = info.load_from_str(g.cache.get_job(res_id))
        filtered_resources.append(infoobj)
    return filtered_resources

def add_to_queue(job):
    """Add a job item to the queue."""
    queue = g.cache.get_job_queue()
    # Avoid starting multiple jobs for the same resource simultaneously
    if job.id in queue and job.status.is_active():
        raise Exception("There is an unfinished job for this resource!")
    # Unqueue if old job is queued since before
    if job.id in queue:
        queue.pop(queue.index(job.id))
    # Add job to queue and save priority
    queue.append(job.id)
    g.cache.set_job_queue(queue)
    save_priorities()
    return job

def pop_from_queue(job):
    """Remove job item from queue (but keep in all jobs), e.g. when a job is aborted."""
    queue = g.cache.get_job_queue()
    if job.id in queue:
        queue.pop(queue.index(job.id))
        g.cache.set_job_queue(queue)
        save_priorities()

def get_priority(job):
    """Get the queue priority of the job."""
    _, waiting_jobs = get_running_waiting()
    waiting_jobs = [j.id for j in waiting_jobs]
    try:
        return waiting_jobs.index(job.id) + 1
    except ValueError:
        return -1

def save_priorities():
    """Save queue order so it can be loaded from disk upon app restart."""
    registry_dir = Path(app.instance_path) / Path(app.config.get("REGISTRY_DIR"))
    registry_dir.mkdir(exist_ok=True)
    queue = g.cache.get_job_queue()
    queue_file = registry_dir / Path(app.config.get("QUEUE_FILE"))
    with queue_file.open("w") as f:
        f.write(json.dumps(queue))

def get_running_waiting():
    """Get the running and waiting jobs from the queue."""
    running_jobs = []
    waiting_jobs = []

    queue = g.cache.get_job_queue()
    # queue is None before it is done initializing
    if queue is not None:
        for res_id in queue:
            jobstr = g.cache.get_job(res_id)
            # A queued id whose blob isn't in the cache is either still being
            # loaded during init (the queue is set before every per-resource blob
            # has been reloaded, see initialize()) or a dangling entry. Either
            # way, skip it rather than crash; don't count it as running/waiting.
            if jobstr is None:
                continue
            job = info.load_from_str(jobstr).job
            if job.status.is_running():
                running_jobs.append(job)
            elif job.status.is_waiting():
                waiting_jobs.append(job)

    return running_jobs, waiting_jobs

def unqueue_inactive():
    """Unqueue jobs that are done, aborted or erroneous."""
    queue = g.cache.get_job_queue()
    # queue is None before it is done initializing
    if queue is None:
        return
    old_jobs = []
    for res_id in queue:
        jobstr = g.cache.get_job(res_id)
        # Skip (don't prune) entries with a missing blob: during init the queue is
        # populated before all per-resource blobs are reloaded, so a None here can
        # be a still-loading job, and pruning would drop it. A genuinely dangling
        # id is inert (skipped everywhere); clean it up via the remove path or a
        # provisioning reset of QUEUE_FILE, not here.
        if jobstr is None:
            continue
        job = info.load_from_str(jobstr).job
        if job.status.is_inactive():
            old_jobs.append(res_id)

    if old_jobs:
        for res_id in old_jobs:
            app.logger.info(f"Removing job {res_id}")
            queue.pop(queue.index(res_id))
        g.cache.set_job_queue(queue)
        save_priorities()
