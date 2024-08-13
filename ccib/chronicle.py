# Imports required for the sample - Google Auth and API Client Library Imports.
# Get these packages from https://pypi.org/project/google-api-python-client/ or
# run $ pip install google-api-python-client from your terminal
import datetime
import json
from google.auth.transport import requests
from google.oauth2 import service_account


class Chronicle:
    """Chronicle API client."""
    OAUTH2_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory',
                     'https://www.googleapis.com/auth/malachite-ingestion']

    def __init__(self, customer_id, service_account_file, region):
        self.customer_id = customer_id
        self.region = region
        # Create a credential using Google Developer Service Account Credential and Chronicle # API Scope.
        self.credentials = service_account.Credentials.from_service_account_file(
            service_account_file, scopes=self.OAUTH2_SCOPES)
        # Build an HTTP session to make authorized OAuth requests.
        self.http_session = requests.AuthorizedSession(self.credentials)
        # https://cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints
        # https://cloud.google.com/chronicle/docs/reference/ingestion-api#regional_endpoints
        # select region
        match self.region:
            case "EU":
                self.ingest_endpoint = 'https://europe-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'
            case "UK":
                self.ingest_endpoint = 'https://europe-west2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'
            case "IL":
                self.ingest_endpoint = 'https://me-west1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'
            case "AU":
                self.ingest_endpoint = 'https://australia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'
            case "SG":
                self.ingest_endpoint = 'https://asia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'
            case _:
                self.ingest_endpoint = 'https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate'

    def send_indicators(self, indicators):
        """Send a batch of indicators to Chronicle."""
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
        """Send a batch of log entries to Chronicle."""
        body = {
            'customer_id': self.customer_id,
            'log_type': "CROWDSTRIKE_IOC",
            'entries': entries,
        }
        response = self.http_session.post(self.ingest_endpoint, json=body)
        response.raise_for_status()
