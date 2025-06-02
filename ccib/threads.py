import threading
import time
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
        ts = time.time() - int(config.get('indicators', 'initial_sync_lookback'))

        while True:
            last_check_time = time.time()

            stats = {'received': 0, 'skipped': 0, 'sent': 0}
            for batch in self.falcon.get_indicators(ts):
                to_be_sent = [i for i in batch if not icache.exists(transform(i))]
                self.queue.put(to_be_sent)

                # statistics
                bsize = len(batch)
                ssize = len(to_be_sent)
                stats['received'] += bsize
                stats['sent'] += ssize
                stats['skipped'] += (bsize - ssize)

            log.info("Statistics: %s", stats)
            ts = last_check_time
            time.sleep(self.frequency)


class ChronicleWriterThread(threading.Thread):
    """Thread that sends indicators to Chronicle."""
    def __init__(self, queue, chronicle, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = queue
        self.chronicle = chronicle

    def run(self):
        while True:
            indicators = self.queue.get()
            self._send_indicators(indicators)

    def _send_indicators(self, indicators):
        count = len(indicators)
        for i in range(0, count, 250):
            batch = indicators[i:i + 250]
            self._send_indicators_batch(batch)

    def _send_indicators_batch(self, batch):
        for i in range(0, 30):
            try:
                self.chronicle.send_indicators(batch)
                return
            except Exception:  # pylint: disable=W0703
                log.exception("Error occurred while processing indicators batch (attempt %d/30)", i+1)
                # Use exponential backoff with a maximum delay of 60 seconds
                backoff_seconds = min(2 ** i, 60)
                log.info("Retrying in %d seconds...", backoff_seconds)
                time.sleep(backoff_seconds)

                # For persistent failures, recreate the session
                if i == 5:
                    log.info("Recreating HTTP session...")
                    # Refresh the session to handle potential stale connections
                    from google.auth.transport import requests
                    self.chronicle.http_session = requests.AuthorizedSession(self.chronicle.credentials)

        log.critical("Could not transmit indicators to Chronicle")
