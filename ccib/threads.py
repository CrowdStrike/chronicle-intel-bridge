import threading
import time
from .icache import icache
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

    def run(self):
        ts = time.time() - 60 * 30 * 2 * 4

        while True:
            last_check_time = time.time()

            outbound = []
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
            time.sleep(60)


class ChronicleWriterThread(threading.Thread):
    def __init__(self, queue, chronicle, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = queue
        self.chronicle = chronicle

    def run(self):
        while True:
            try:
                batch = self.queue.get()
                self.chronicle.send_indicators(batch)
            except Exception:  # pylint: disable=W0703
                log.exception("Error occurred while processing indicators batch")
