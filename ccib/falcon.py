from functools import reduce
from falconpy import api_complete as FalconSDK
from .config import config
from .log import log
from .helper import thousands

from falconpy import Intel


class ApiError(Exception):
    pass


class FalconAPI():
    CLOUD_REGIONS = {
        'us-1': 'api.crowdstrike.com',
        'us-2': 'api.us-2.crowdstrike.com',
        'eu-1': 'api.eu-1.crowdstrike.com',
        'us-gov-1': 'api.laggar.gcw.crowdstrike.com',
    }

    def __init__(self):
        client_id = config.get('falcon', 'client_id')
        client_secret = config.get('falcon', 'client_secret')
        crowdstrike_url = self.__class__.base_url()
        self.intel = Intel(client_id=client_id, client_secret=client_secret, base_url=crowdstrike_url)

    @classmethod
    def base_url(cls):
        return 'https://' + cls.CLOUD_REGIONS[config.get('falcon', 'cloud_region')]

    @property
    def request_size_limit(self):
        return 1000

    def get_indicators(self, start_time):
        """Get all the indicators that were updated after a certain moment in time (UNIX).

        :param start_time: unix time of the oldest indicator you want to pull
        """
        indicators_in_request = []
        first_run = True

        while len(indicators_in_request) == self.request_size_limit or first_run:
            resp_json = self.intel.query_indicator_entities(
                sort="_marker.asc",
                filter=f"_marker:>='{start_time}'+deleted:false",
                limit=self.request_size_limit,
                include_deleted=False
            )
            if "body" in resp_json:
                resp_json = resp_json["body"]

            first_run = False

            indicators_in_request = resp_json.get('resources', [])
            if not indicators_in_request:
                break

            total_found = reduce(lambda d, key: d.get(key, None) if isinstance(d, dict) else None,
                                 "meta.pagination.total".split("."),
                                 resp_json
                                 )
            log.info(
                "Retrieved %s of %s remaining indicators.",
                thousands(
                    len(indicators_in_request)),
                thousands(total_found))

            last_marker = indicators_in_request[-1].get('_marker', '')

            yield indicators_in_request

            if last_marker == '':
                break
            start_time = last_marker
