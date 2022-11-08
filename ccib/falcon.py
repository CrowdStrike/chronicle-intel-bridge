from falconpy import api_complete as FalconSDK
from .config import config


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
        self.client = FalconSDK.APIHarness(creds={
            'client_id': config.get('falcon', 'client_id'),
            'client_secret': config.get('falcon', 'client_secret')},
            base_url=self.__class__.base_url())

    @classmethod
    def base_url(cls):
        return 'https://' + cls.CLOUD_REGIONS[config.get('falcon', 'cloud_region')]

    def indicators(self):
        return self._resources(action='QueryIntelIndicatorEntities')

    def _resources(self, *args, **kwargs):
        response = self._command(*args, **kwargs)
        body = response['body']
        if 'resources' not in body or not body['resources']:
            return []
        return body['resources']

    def _command(self, *args, **kwargs):
        response = self.client.command(*args, **kwargs)
        body = response['body']
        if 'errors' in body and body['errors'] is not None:
            if len(body['errors']) > 0:
                raise ApiError('Error received from CrowdStrike Falcon platform: {}'.format(body['errors']))
        if 'status_code' not in response or (response['status_code'] != 200 and response['status_code'] != 201):
            raise ApiError('Unexpected response code from Falcon API. Response was: {}'.format(response))
        return response
