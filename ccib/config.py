import os
import configparser


class FigConfig(configparser.SafeConfigParser):
    FALCON_CLOUD_REGIONS = {'us-1', 'us-2', 'eu-1', 'us-gov-1'}
    ENV_DEFAULTS = [
        ['logging', 'level', 'LOG_LEVEL'],
        ['falcon', 'cloud_region', 'FALCON_CLOUD_REGION'],
        ['falcon', 'client_id', 'FALCON_CLIENT_ID'],
        ['falcon', 'client_secret', 'FALCON_CLIENT_SECRET'],
        ['chronicle', 'service_account', 'GOOGLE_SERVICE_ACCOUNT_FILE'],
        ['chronicle', 'customer_id', 'CHRONICLE_CUSTOMER_ID'],
        ['chronicle', 'region', 'CHRONICLE_REGION']
    ]

    def __init__(self):
        super().__init__()
        self.read(['config/defaults.ini', 'config/config.ini', 'config/devel.ini'])
        self._override_from_env()

    def _override_from_env(self):
        for section, var, envvar in self.__class__.ENV_DEFAULTS:
            value = os.getenv(envvar)
            if value:
                self.set(section, var, value)

    def validate(self):
        for section, var, envvar in self.__class__.ENV_DEFAULTS:
            try:
                self.get(section, var)
            except configparser.NoOptionError as err:
                raise Exception(
                    f"Please provide environment variable {envvar} or configuration option {section}.{var}") from err

        self.validate_falcon()
        self.validate_chronicle()

        if int(self.get('indicators', 'sync_frequency')) not in range(1, 3600):
            raise Exception('Malformed configuration: expected indicators.sync_frequency to be in range 1-3600')

    def validate_falcon(self):
        if self.get('falcon', 'cloud_region') not in self.FALCON_CLOUD_REGIONS:
            raise Exception(
                f'Malformed configuration: expected falcon.cloud_region to be in {self.FALCON_CLOUD_REGIONS}'
            )
        if len(self.get('falcon', 'client_id')) == 0:
            raise Exception('Malformed Configuration: expected chronicle.client_id to be non-empty')
        if len(self.get('falcon', 'client_secret')) == 0:
            raise Exception('Malformed Configuration: expected chronicle.client_secret to be non-empty')

    def validate_chronicle(self):
        if len(self.get('chronicle', 'customer_id')) == 0:
            raise Exception('Malformed Configuration: expected chronicle.customer_id to be non-empty')


config = FigConfig()
