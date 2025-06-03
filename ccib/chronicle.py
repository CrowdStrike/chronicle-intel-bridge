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

        # Map region codes to their endpoints
        # Make region case-insensitive
        region_upper = self.region.upper() if self.region else ""

        # Map of region codes to their endpoints
        region_endpoints = {
            # Legacy region codes
            "EU": "https://europe-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "UK": "https://europe-west2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "IL": "https://me-west1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "AU": "https://australia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "SG": "https://asia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",

            # New region codes based on Google Cloud regions
            "US": "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE": "https://europe-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE-WEST2": "https://europe-west2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE-WEST3": "https://europe-west3-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE-WEST6": "https://europe-west6-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE-WEST9": "https://europe-west9-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "EUROPE-WEST12": "https://europe-west12-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ME-WEST1": "https://me-west1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ME-CENTRAL1": "https://me-central1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ME-CENTRAL2": "https://me-central2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ASIA-SOUTH1": "https://asia-south1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ASIA-SOUTHEAST1": "https://asia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "ASIA-NORTHEAST1": "https://asia-northeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "AUSTRALIA-SOUTHEAST1": "https://australia-southeast1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "SOUTHAMERICA-EAST1": "https://southamerica-east1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
            "NORTHAMERICA-NORTHEAST2": "https://northamerica-northeast2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate",
        }

        # Default to US multi-region if region is not specified or not recognized
        self.ingest_endpoint = region_endpoints.get(region_upper, "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate")

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
        # Add explicit timeouts to prevent hanging connections
        response = self.http_session.post(
            self.ingest_endpoint,
            json=body,
            timeout=(10, 30)  # (connect timeout, read timeout) in seconds
        )
        response.raise_for_status()
