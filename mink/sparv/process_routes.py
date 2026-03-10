"""Routes related to Sparv."""

import time

from flask import Blueprint
from flask import current_app as app
from flask import request, session

from mink.core import exceptions, jobs, registry, utils
from mink.core.status import JobStatuses, ProcessName, Status
from mink.sb_auth import login
from mink.sparv import storage

bp = Blueprint("sparv", __name__)


@bp.route("/run-sparv", methods=["PUT"])
@login.login()
def run_sparv(resource_id: str):
    """Run Sparv on given corpus."""
    # Parse requested exports
    sparv_exports = request.args.get("exports") or request.form.get("exports") or ""
    sparv_exports = [i.strip() for i in sparv_exports.split(",") if i] or app.config.get("SPARV_DEFAULT_EXPORTS")

    current_files = request.args.get("files") or request.form.get("files") or ""
    current_files = [i.strip() for i in current_files.split(",") if i]

    # Get list of available source files to be stored in the job info
    source_dir = str(storage.get_source_dir(resource_id))
    try:
        source_files = storage.list_contents(source_dir)
    except Exception as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    if not source_files:
        return utils.response(f"No source files found for '{resource_id}'", err=True, return_code="no_sources_found"), 404

    # Check compatibility between source files and config
    try:
        config_file = str(storage.get_config_file(resource_id))
        config_contents = storage.get_file_contents(config_file)
        if source_files:
            compatible, resp = utils.config_compatible(config_contents, source_files[0])
            if not compatible:
                return resp, 400
    except Exception as e:
        return utils.response(f"Failed to get config file for '{resource_id}'", err=True, info=str(e),
                              return_code="failed_getting_config"), 500

    # Get job, check for changes and remove exports if necessary
    try:
        old_job = registry.get(resource_id).job
        _, _, deleted_sources, changed_config = storage.get_file_changes(resource_id, old_job)
        if deleted_sources or changed_config:
            try:
                success, sparv_output = old_job.clean_export()
                assert success
            except Exception as e:
                return utils.response(f"Failed to remove export files from Sparv server for corpus '{resource_id}'. "
                                      "Cannot run Sparv safely", err=True, info=str(e), sparv_message=sparv_output,
                                      return_code="failed_removing_exports"), 500
    except exceptions.JobNotFound:
        pass
    except exceptions.CouldNotListSources as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    info = registry.get(resource_id)
    job = info.job
    job.set_sparv_exports(sparv_exports)
    job.set_current_files(current_files)

    # Queue job
    job.reset_time()
    try:
        job = registry.add_to_queue(job)
    except Exception as e:
        return utils.response(f"Failed to queue job for '{resource_id}'", err=True, info=str(e),
                              return_code="failed_queuing"), 500

    # Check that all required files are present
    job.check_requirements()

    if storage.local:
        job.set_status(Status.waiting, ProcessName.sparv)
    else:
        # Sync files
        try:
            job.sync_to_sparv()
        except Exception as e:
            return utils.response(f"Failed to start job for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_starting_job"), 500

    # Wait a few seconds to check whether anything terminated early
    time.sleep(3)
    return make_status_response(info)


@bp.route("/advance-queue", methods=["PUT"])
@utils.gatekeeper
def advance_queue():
    """Check the job queue and attempt to advance it.

    1. Unqueue jobs that are done, aborted or erroneous
    2. For running jobs, check if process is still running
    3. Run the next job in the queue if there are fewer running jobs than allowed

    For internal use only!
    """
    # Unqueue jobs that are done, aborted or erroneous
    registry.unqueue_inactive()

    # For running jobs, check if process is still running
    running_jobs, waiting_jobs = registry.get_running_waiting()
    app.logger.debug(f"Running jobs: {len(running_jobs)}  Waiting jobs: {len(waiting_jobs)}")
    for job in running_jobs:
        try:
            if not job.process_running():
                job.abort_sparv()
                registry.pop_from_queue(job)
        except Exception as e:
            app.logger.error(f"Failed to check if process is running for '{job.id}' {str(e)}")

    # Get running jobs again in case jobs were unqueued in the previous step
    running_jobs, waiting_jobs = registry.get_running_waiting()
    # If there are fewer running jobs than allowed, start the next one in the queue
    while waiting_jobs and len(running_jobs) < app.config.get("SPARV_WORKERS", 1):
        job = waiting_jobs.pop(0)
        try:
            if job.status.is_waiting():
                if job.current_process == ProcessName.sparv.name:
                    job.run_sparv()
                    app.logger.info(f"Started annotation process for '{job.id}'")
                elif job.current_process == ProcessName.korp.name:
                    job.install_korp()
                    app.logger.info(f"Started Korp installation process for '{job.id}'")
                elif job.current_process == ProcessName.strix.name:
                    job.install_strix()
                    app.logger.info(f"Started Strix installation process for '{job.id}'")
            running_jobs.append(job)
        except Exception as e:
            app.logger.error(f"Failed to run Sparv on '{job.id}' {str(e)}")

    return utils.response("Queue advancing completed", return_code="advanced_queue")


@bp.route("/resource-info", methods=["GET"])
@login.login(require_resource_id=False)
def resource_info(corpora: list):
    """Check the job status for all jobs belonging to a user or for a given resource."""
    # TODO: change param name from corpus_id to resource_id!
    resource_id = request.args.get("corpus_id") or request.form.get("corpus_id")
    if resource_id:
        try:
            # Check if corpus exists
            if resource_id not in corpora:
                return utils.response(f"Corpus '{resource_id}' does not exist or you do not have access to it",
                                      err=True, return_code="corpus_not_found"), 404
            info = registry.get(resource_id)
            if not info:
                return utils.response(f"There is no active job for '{resource_id}'", job_status=JobStatuses().serialize(),
                                      return_code="no_active_job")
            return make_status_response(info, admin=session.get("admin_mode", False))
        except Exception as e:
            return utils.response(f"Failed to get job status for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_getting_job_status"), 500

    try:
        # Get all job statuses for this user's corpora
        res_list = []
        resources = registry.filter_resources(corpora)
        for res in resources:
            resp = make_status_response(res, admin=session.get("admin_mode", False))
            if isinstance(resp, tuple):
                resp = resp[0]
            job_status = resp.get_json()
            res_list.append(job_status)
        return utils.response("Listing resource infos", resources=res_list, return_code="listing_jobs")
    except Exception as e:
        return utils.response("Failed to get job statuses", err=True, info=str(e),
                              return_code="failed_getting_job_statuses"), 500


@bp.route("/abort-job", methods=["POST"])
@login.login()
def abort_job(resource_id: str):
    """Try to abort a running job."""
    job = registry.get(resource_id).job
    # Syncing
    if job.status.is_syncing():
        return utils.response(f"Cannot abort job while syncing files", job_status=job.status.serialize(),
                              return_code="failed_aborting_job_syncing"), 503
    # Waiting
    if job.status.is_waiting():
        try:
            registry.pop_from_queue(job)
            job.set_status(Status.aborted)
            return utils.response(f"Successfully aborted job for '{resource_id}'", job_status=job.status.serialize(),
                                  return_code="aborted_job")
        except Exception as e:
            return utils.response(f"Failed to unqueue job for '{resource_id}'", err=True, info=str(e),
                                  return_code="failed_unqueuing_job"), 500
    # No running job
    if not job.status.is_running():
        return utils.response(f"No running job found for '{resource_id}'", return_code="no_running_job")
    # Running job, try to abort
    try:
        job.abort_sparv()
    except exceptions.ProcessNotRunning:
        return utils.response(f"No running job found for '{resource_id}'")
    except Exception as e:
        return utils.response(f"Failed to abort job for '{resource_id}'", err=True, info=str(e),
                              return_code="failed_aborting_job"), 500
    return utils.response(f"Successfully aborted job for '{resource_id}'", job_status=job.status.serialize(),
                          return_code="aborted_job")


@bp.route("/clear-annotations", methods=["DELETE"])
@login.login()
def clear_annotations(resource_id: str):
    """Remove annotation files from Sparv server."""
    # Check if there is an active job
    job = registry.get(resource_id).job
    if job.status.is_running():
        return utils.response("Cannot clear annotations while a job is running", err=True,
                              return_code="failed_clearing_annotations_job_running"), 503

    try:
        sparv_output = job.clean()
        return utils.response(f"Annotations for '{resource_id}' successfully removed", sparv_output=sparv_output,
                              return_code="removed_annotations")
    except Exception as e:
        return utils.response("Failed to clear annotations", err=True, info=str(e),
                              return_code="failed_clearing_annotations"), 500


@bp.route("/install-korp", methods=["PUT"])
@login.login()
def install_korp(resource_id: str):
    """Install a corpus in Korp with Sparv."""
    # Get info about whether the corpus should be scrambled in Korp. Default to not scrambling.
    scramble = request.args.get("scramble", "") or request.form.get("scramble", "")
    scramble = scramble.lower() == "true"

    # Get job, check for changes and remove exports if necessary
    try:
        old_job = registry.get(resource_id).job
        _, _, deleted_sources, changed_config = storage.get_file_changes(resource_id, old_job)
        if deleted_sources or changed_config:
            try:
                success, sparv_output = old_job.clean_export()
                assert success
            except Exception as e:
                return utils.response(f"Failed to remove export files from Sparv server for corpus '{resource_id}'. "
                                      "Cannot run Sparv safely", err=True, info=str(e), sparv_message=sparv_output,
                                      return_code="failed_removing_exports"), 500
    except exceptions.JobNotFound:
        pass
    except exceptions.CouldNotListSources as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    # Queue job
    info = registry.get(resource_id)
    job = info.job
    job.reset_time()
    job.set_install_scrambled(scramble)
    try:
        job = registry.add_to_queue(job)
    except Exception as e:
        return utils.response(f"Failed to queue job for '{resource_id}'", err=True, info=str(e),
                              return_code="failed_queuing"), 500

    job.set_status(Status.waiting, ProcessName.korp)

    # Wait a few seconds to check whether anything terminated early
    time.sleep(3)
    return make_status_response(info)


@bp.route("/install-strix", methods=["PUT"])
@login.login()
def install_strix(resource_id: str):
    """Install a corpus in Strix with Sparv."""
    # Get job, check for changes and remove exports if necessary
    try:
        old_job = registry.get(resource_id).job
        _, _, deleted_sources, changed_config = storage.get_file_changes(resource_id, old_job)
        if deleted_sources or changed_config:
            try:
                success, sparv_output = old_job.clean_export()
                assert success
            except Exception as e:
                return utils.response(f"Failed to remove export files from Sparv server for corpus '{resource_id}'. "
                                      "Cannot run Sparv safely", err=True, info=str(e), sparv_message=sparv_output,
                                      return_code="failed_removing_exports"), 500
    except exceptions.JobNotFound:
        pass
    except exceptions.CouldNotListSources as e:
        return utils.response(f"Failed to list source files in '{resource_id}'", err=True, info=str(e),
                              return_code="failed_listing_sources"), 500

    # Queue job
    info = registry.get(resource_id)
    job = info.job
    job.reset_time()
    try:
        job = registry.add_to_queue(job)
    except Exception as e:
        return utils.response(f"Failed to queue job for '{resource_id}'", err=True, info=str(e),
                              return_code="failed_queuing"), 500

    job.set_status(Status.waiting, ProcessName.strix)

    # Wait a few seconds to check whether anything terminated early
    time.sleep(3)
    return make_status_response(info)


def make_status_response(info, admin=False):
    """Check the annotation status for a given corpus and return response."""
    info_attrs = info.to_dict()

    if not admin:
        info_attrs.pop("owner")

    status = info.job.status

    if status.is_none():
        return utils.response(f"There is no active job for '{info.job.id}'", **info_attrs, return_code="no_active_job")

    if status.is_syncing():
        return utils.response("Files are being synced", **info_attrs, return_code="syncing_files")

    if status.is_waiting():
        return utils.response("Job has been queued", **info_attrs, return_code="job_queued")

    if status.is_aborted(info.job.current_process):
        return utils.response("Job was aborted by the user", **info_attrs, return_code="job_aborted_by_user")

    if status.is_running():
        return utils.response("Job is running", **info_attrs, return_code="job_running")

    # If done annotating, retrieve exports from Sparv
    if status.is_done(ProcessName.sparv) and not admin:
        try:
            info.job.sync_results()
        except Exception as e:
            return utils.response("Sparv was run successfully but exports failed to upload to the storage server",
                                  info=str(e), return_code="sparv_success_export_upload_fail")
        return utils.response("Sparv was run successfully! Starting to sync results", **info_attrs,
                              return_code="sparv_success_start_sync")

    if status.is_done(info.job.current_process):
        return utils.response("Job was completed successfully!", **info_attrs, return_code="job_completed")

    if status.is_error(info.job.current_process):
        app.logger.error(f"An error occurred during processing, warnings: {info_attrs['job']['warnings']}, errors: "
                         f"{info_attrs['job']['errors']}, sparv_output: {info_attrs['job']['sparv_output']}, "
                         f"job_attrs: {info_attrs}")
        return utils.response("An error occurred during processing", **info_attrs, return_code="processing_error")

    return utils.response("Cannot handle this Job status yet", **info_attrs, return_code="cannot_handle_status"), 501


@bp.route("/sparv-languages", methods=["GET"])
def sparv_languages():
    """List languages available in Sparv.

    Optional query parameter:
    - annotators=true: include per-language annotator information in the response.
    """
    include_annotators = (request.args.get("annotators") or "").lower() == "true"
    try:
        job = jobs.DefaultJob()
        languages = job.list_languages()
    except Exception as e:
        return utils.response("Failed listing languages", err=True, info=str(e),
                              return_code="failed_listing_languages"), 500

    if include_annotators:
        for lang in languages:
            try:
                lang_job = jobs.DefaultJob(language=lang["code"])
                lang["annotators"] = lang_job.list_annotators()
            except Exception as e:
                return utils.response("Failed listing annotators", err=True, info=str(e),
                                      return_code="failed_listing_annotators"), 500

    return utils.response("Listing languages available in Sparv", languages=languages,
                          return_code="listing_languages")


@bp.route("/sparv-exports", methods=["GET"])
def sparv_exports():
    """List available Sparv exports for current language (default: swe)."""
    language = request.args.get("language") or request.form.get("language") or "swe"
    try:
        job = jobs.DefaultJob(language=language)
        exports = job.list_exports()
    except Exception as e:
        return utils.response("Failed listing exports", err=True, info=str(e),
                              return_code="failed_listing_sparv_exports"), 500
    return utils.response("Listing exports available in Sparv", language=language, exports=exports,
                          return_code="listing_sparv_exports")
