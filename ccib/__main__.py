from queue import Queue
from .falcon import FalconAPI
from .config import config
from .log import log
from .chronicle import Chronicle
from .threads import FalconReaderThread, ChronicleWriterThread
from . import __version__


if __name__ == "__main__":
    log.info("Starting CrowdStrike Chronicle Intel Bridge %s", __version__)

    config.validate()

    falcon = FalconAPI()
    queue = Queue(maxsize=10)
    chronicle = Chronicle(config.get('chronicle', 'customer_id'), config.get('chronicle', 'service_account'))

    FalconReaderThread(falcon, queue).start()
    ChronicleWriterThread(queue, chronicle).start()
