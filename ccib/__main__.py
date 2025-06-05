from queue import Queue
from .falcon import FalconAPI
from .config import config
from .log import log
from .chronicle import Chronicle
from .threads import FalconReaderThread, ChronicleWriterThread
from . import __version__


if __name__ == "__main__":
    log.info("Starting CrowdStrike Chronicle Intel Bridge %s", __version__)
    log.debug("Log level set to: %s", config.get('logging', 'level'))

    config.validate()
    log.debug("Configuration validated successfully")
    falcon = FalconAPI()
    log.debug("Falcon API client initialized with cloud region: %s", config.get('falcon', 'cloud_region'))

    queue = Queue(maxsize=10)
    log.debug("Created thread-safe queue with max size: 10")

    chronicle = Chronicle(config.get('chronicle', 'customer_id'), config.get('chronicle', 'service_account'), config.get('chronicle', 'region'))
    log.debug("Chronicle client initialized with customer ID: %s, region: %s",
              config.get('chronicle', 'customer_id'),
              config.get('chronicle', 'region') or "US (default)")

    log.debug("Starting Falcon Reader Thread")
    FalconReaderThread(falcon, queue).start()

    log.debug("Starting Chronicle Writer Thread")
    ChronicleWriterThread(queue, chronicle).start()
