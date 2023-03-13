# Imports required for the sample - Google Auth and API Client Library Imports.
# Get these packages from https://pypi.org/project/google-api-python-client/ or
# run $ pip install google-api-python-client from your terminal
import datetime
import json
from google.auth.transport import requests
from google.oauth2 import service_account


class Chronicle:
    OAUTH2_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory',
                     'https://www.googleapis.com/auth/malachite-ingestion']
    INGEST_ENDPOINT = 'https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'

    def __init__(self, customer_id, service_account_file):
        self.customer_id = customer_id
        # Create a credential using Google Developer Service Account Credential and Chronicle # API Scope.
        self.credentials = service_account.Credentials.from_service_account_file(
            service_account_file, scopes=self.OAUTH2_SCOPES)
        # Build an HTTP session to make authorized OAuth requests.
        self.http_session = requests.AuthorizedSession(self.credentials)

    def send_indicators(self, indicators):
        ts = int(datetime.datetime.utcnow().timestamp() * 1000000)
        batch = [
            {
                "log_text": json.dumps(i),
                "ts_epoch_microseconds": ts
            }
            for i in indicators
        ]
        self._send(batch)

    def _send(self, entries):
        body = {
            'customer_id': self.customer_id,
            'log_type': "CROWDSTRIKE_IOC",
            'entries': entries,
        }
        response = self.http_session.post(self.INGEST_ENDPOINT, json=body)
        response.raise_for_status()
