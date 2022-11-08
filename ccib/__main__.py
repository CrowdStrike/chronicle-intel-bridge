from .falcon import FalconAPI
from .config import config
from .log import log
from . import __version__


if __name__ == "__main__":
    log.info("Starting CrowdStrike Chronicle Intel Bridge %s", __version__)

    # Central to the fig architecture is a message queue (falcon_events). GCPWorkerThread/s read the queue and process
    # each event. The events are put on queue by StreamingThread. StreamingThread is restarted by StreamManagementThread

    config.validate()

    falcon = FalconAPI()
    print(falcon.indicators())
