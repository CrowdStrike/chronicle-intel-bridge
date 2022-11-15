import threading
import time
from .icache import icache
from .config import config
from .log import log


def transform(indicator):
    indicator.pop('_marker')
    for label in indicator.get('labels', []):
        label.pop('last_valid_on')
    for rel in indicator.get('relations', []):
        rel.pop('last_valid_date')
    return indicator


class FalconReaderThread(threading.Thread):
    def __init__(self, falcon, queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.falcon = falcon
        self.queue = queue
        self.frequency = int(config.get('indicators', 'sync_frequency'))

    def run(self):
        ts = time.time() - 60 * 30 * 2 * 4

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
                log.exception("Error occurred while processing indicators batch")
                time.sleep(i)
        log.critical("Could not transmit indicators to Chronicle")
