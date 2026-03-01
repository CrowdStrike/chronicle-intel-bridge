from functools import reduce
import time
import json
from falconpy import Intel
from .config import config
from .log import log
from .helper import thousands
from .version import __version__


class FalconAPI():
    """CrowdStrike Falcon API client."""
    CLOUD_REGIONS = {
        'us-1': 'api.crowdstrike.com',
        'us-2': 'api.us-2.crowdstrike.com',
        'eu-1': 'api.eu-1.crowdstrike.com',
        'us-gov-1': 'api.laggar.gcw.crowdstrike.com',
    }

    def __init__(self):
        base_url = self.__class__.base_url()
        log.debug("Initializing Falcon Intel API client with base URL: %s", base_url)
        self.intel = Intel(client_id=config.get('falcon', 'client_id'),
                           client_secret=config.get('falcon', 'client_secret'),
                           base_url=base_url,
                           user_agent=f"chronicle-intel-bridge/{__version__}"
                           )
        log.debug("Falcon Intel API client initialized successfully")

    @classmethod
    def base_url(cls):
        """Return the base URL for the CrowdStrike Falcon API."""
        return 'https://' + cls.CLOUD_REGIONS[config.get('falcon', 'cloud_region')]

    @property
    def request_size_limit(self):
        """The maximum number of indicators to request in a single API call."""
        return 1000

    def _fetch_indicators(self, marker):
        while True:
            try:
                log.debug("Fetching indicators from Falcon API with marker: %s, limit: %d",
                          marker, self.request_size_limit)

                resp_json = self.intel.query_indicator_entities(
                    sort="_marker.asc",
                    filter=f"_marker:>='{marker}'+deleted:false",
                    limit=self.request_size_limit,
                    include_deleted=False
                )
                status_code = resp_json.get('status_code', 200)
                body = resp_json['body']
                errors = body.get('errors', [])

                log.debug("Falcon API response status code: %d", status_code)
                if errors:
                    log.debug("Falcon API response errors: %s", json.dumps(errors))

                if status_code != 200 or errors:
                    raise Exception(f'Unexpected response status from CrowdStrike Falcon: {status_code} Errors: {errors}')

                log.debug("Successfully fetched indicators from Falcon API")
                return body
            except Exception:  # pylint: disable=W0703
                log.exception("Error occurred while processing indicators batch")
                log.debug("Retrying in 5 seconds...")
                time.sleep(5)

    def get_indicators(self, start_time):
        """Get all the indicators that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest indicator you want to pull
        """
        log.debug("Starting to fetch indicators updated after timestamp: %s", start_time)
        indicators_in_request = []
        first_run = True
        total_indicators_fetched = 0

        while len(indicators_in_request) == self.request_size_limit or first_run:
            first_run = False

            body = self._fetch_indicators(start_time)

            indicators_in_request = body.get('resources', [])
            if not indicators_in_request:
                log.debug("No indicators found in response")
                break

            total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                 "meta.pagination.total".split("."),
                                 body
                                 )

            batch_size = len(indicators_in_request)
            total_indicators_fetched += batch_size

            log.info(
                "Retrieved %s of %s remaining indicators.",
                thousands(batch_size),
                thousands(total_found))

            log.debug("Batch contains %d indicators, total fetched so far: %d",
                      batch_size, total_indicators_fetched)

            # Only log sample indicators if there's a reasonable number
            if 0 < batch_size <= 10:
                log.debug("Indicators in batch: %s",
                          ", ".join([i.get('id', 'unknown') for i in indicators_in_request]))
            elif batch_size > 10:
                log.debug("Sample indicators: %s, ..., %s",
                          indicators_in_request[0].get('id', 'unknown'),
                          indicators_in_request[-1].get('id', 'unknown'))

            last_marker = indicators_in_request[-1].get('_marker', '')
            log.debug("Last marker from batch: %s", last_marker)

            yield indicators_in_request

            if last_marker == '':
                log.debug("No more markers available, ending fetch cycle")
                break
            start_time = last_marker
            log.debug("Updating start time to: %s for next batch", start_time)
