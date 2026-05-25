"""Script for advancing the job queue with scheduled jobs.

This scheduler will make a call to the 'advance-queue' route of the mink API.
"""

import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib import error, parse, request

from apscheduler.schedulers.blocking import BlockingScheduler


def advance_queue(config):
    """Check the queue and run jobs if possible."""
    logging.debug("Calling '/advance-queue'...")
    base_url = config.get("MINK_INTERNAL_URL") or config.get("MINK_URL")
    url = f"{base_url}/advance-queue"
    try:
        data = parse.urlencode({"secret_key": config.get("MINK_SECRET_KEY")}).encode()
        req = request.Request(url, data=data, method="PUT")
        with request.urlopen(req) as f:
            logging.debug(f.read().decode("UTF-8"))
    except error.HTTPError as e:
        logging.error(f"Error advancing queue! {e}")


def ping_healthchecks(config):
    """Ping helthchecks (https://healthchecks.io/) to tell it that the queue manager is running."""
    url = config.get("HEALTHCHECKS_URL")
    if url:
        logging.debug("Sending ping to healthchecks")
        try:
            with request.urlopen(url) as f:
                logging.debug(f.read().decode("UTF-8"))
        except error.HTTPError as e:
            logging.error(f"Error pinging healthchecks! {e}")
    else:
        logging.debug("No health check URL found")


def import_config():
    """Import default and instance config."""
    import config
    my_config = {item: getattr(config, item) for item in dir(config) if item.isupper()}

    instance_config_path = Path("instance") / "config.py"
    if instance_config_path.is_file():
        from instance import config as instance_config
        Instance_Config = {item: getattr(instance_config, item) for item in dir(instance_config) if item.isupper()}
        my_config.update(Instance_Config)

    return my_config


if __name__ == '__main__':
    # Load config
    config = import_config()

    # Configure logger
    logfmt = "%(asctime)-15s - %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    if sys.stdin.isatty():
        # Script is run interactively: log to console on debug level
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=logfmt, datefmt=datefmt)
    else:
        # Log to file
        today = time.strftime("%Y-%m-%d")
        logdir = Path("instance") / "logs"
        logfile = logdir / f"queue-{today}.log"
        logdir.mkdir(exist_ok=True)
        # Create log file if it does not exist
        if not logfile.is_file():
            with logfile.open("w") as f:
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{now} CREATED DEBUG FILE\n\n")

        logging.basicConfig(filename=logfile, level=getattr(logging, config.get("LOG_LEVEL", "INFO").upper()),
                            format=logfmt, datefmt=datefmt)

    # Make apscheduler less chatty
    logging.getLogger("apscheduler").setLevel(logging.WARNING)

    # Start scheduler
    scheduler = BlockingScheduler()
    scheduler.add_executor("threadpool", max_workers=1)
    scheduler.add_job(advance_queue, "interval", [config], seconds=config.get("CHECK_QUEUE_FREQUENCY", 20))
    scheduler.add_job(ping_healthchecks, "interval", [config], minutes=config.get("PING_FREQUENCY", 60),
                      next_run_time=datetime.now())

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        pass
