import threading
import time
from google.auth.transport import requests
from .icache import icache
from .config import config
from .log import log


def transform(indicator):
    """Transform an indicator dictionary for comparison."""
    indicator.pop('_marker')
    for label in indicator.get('labels', []):
        label.pop('last_valid_on')
    for rel in indicator.get('relations', []):
        rel.pop('last_valid_date')
    return indicator


class FalconReaderThread(threading.Thread):
    """Thread that reads indicators from Falcon."""
    def __init__(self, falcon, queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.falcon = falcon
        self.queue = queue
        self.frequency = int(config.get('indicators', 'sync_frequency'))

    def run(self):
        """Read indicators from Falcon and put them in the queue."""
        initial_lookback = int(config.get('indicators', 'initial_sync_lookback'))
        ts = time.time() - initial_lookback
        log.debug("Starting FalconReaderThread with initial lookback of %d seconds (timestamp: %s)",
                  initial_lookback, ts)

        while True:
            log.debug("Starting new indicator fetch cycle")
            last_check_time = time.time()
            log.debug("Current time: %s", last_check_time)

            stats = {'received': 0, 'skipped': 0, 'sent': 0}
            for batch in self.falcon.get_indicators(ts):
                log.debug("Processing batch of %d indicators", len(batch))

                # Transform and check cache for each indicator - reduce per-indicator logging
                to_be_sent = []
                skipped_count = 0
                for i in batch:
                    transformed = transform(i)
                    exists = icache.exists(transformed)
                    if not exists:
                        to_be_sent.append(i)
                    else:
                        skipped_count += 1

                if skipped_count > 0:
                    log.debug("Skipped %d indicators that already exist in cache", skipped_count)

                log.debug("Putting %d indicators in queue", len(to_be_sent))
                self.queue.put(to_be_sent)

                # statistics
                bsize = len(batch)
                ssize = len(to_be_sent)
                stats['received'] += bsize
                stats['sent'] += ssize
                stats['skipped'] += (bsize - ssize)
                log.debug("Batch statistics - received: %d, sent: %d, skipped: %d",
                          bsize, ssize, bsize - ssize)

            log.info("Statistics: %s", stats)
            log.debug("Completed fetch cycle, updating timestamp to: %s", last_check_time)
            ts = last_check_time

            log.debug("Sleeping for %d seconds before next fetch cycle", self.frequency)
            time.sleep(self.frequency)


class ChronicleWriterThread(threading.Thread):
    """Thread that sends indicators to Chronicle."""
    def __init__(self, queue, chronicle, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = queue
        self.chronicle = chronicle

    def run(self):
        log.debug("Starting ChronicleWriterThread")
        while True:
            log.debug("Waiting for indicators from queue")
            indicators = self.queue.get()
            log.debug("Got %d indicators from queue", len(indicators))
            self._send_indicators(indicators)

    def _send_indicators(self, indicators):
        count = len(indicators)
        log.debug("Processing %d indicators for sending to Chronicle", count)

        # Chronicle has a limit of 250 indicators per request
        batch_size = 250
        num_batches = (count + batch_size - 1) // batch_size  # Ceiling division

        log.debug("Splitting into %d batches of maximum %d indicators each", num_batches, batch_size)

        for i in range(0, count, batch_size):
            batch = indicators[i:i + batch_size]
            log.debug("Sending batch %d/%d with %d indicators",
                      (i // batch_size) + 1, num_batches, len(batch))
            self._send_indicators_batch(batch)

    def _send_indicators_batch(self, batch):
        log.debug("Attempting to send batch of %d indicators to Chronicle", len(batch))

        for i in range(0, 30):
            try:
                log.debug("Sending batch to Chronicle (attempt %d/30)", i+1)
                self.chronicle.send_indicators(batch)
                log.debug("Successfully sent batch to Chronicle")
                return
            except Exception:  # pylint: disable=W0703
                log.exception("Error occurred while processing indicators batch (attempt %d/30)", i+1)
                # Use exponential backoff with a maximum delay of 60 seconds
                backoff_seconds = min(2 ** i, 60)
                log.info("Retrying in %d seconds...", backoff_seconds)
                log.debug("Using exponential backoff: 2^%d = %d seconds (capped at 60)", i, backoff_seconds)
                time.sleep(backoff_seconds)

                # For persistent failures, recreate the session
                if i == 5:
                    log.info("Recreating HTTP session...")
                    log.debug("Recreating HTTP session after 5 failed attempts")
                    # Refresh the session to handle potential stale connections
                    self.chronicle.http_session = requests.AuthorizedSession(self.chronicle.credentials)
                    log.debug("HTTP session recreated")

        log.critical("Could not transmit indicators to Chronicle")
        log.debug("Failed to send batch after 30 attempts, giving up")
