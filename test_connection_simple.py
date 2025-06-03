#!/usr/bin/env python3
"""
Simple test script for Chronicle connection resilience.
This script tests the connection handling without requiring root privileges.
"""

import time
import json
import datetime
import logging
import argparse
import random
from ssl import SSLEOFError
import requests
from urllib3.exceptions import MaxRetryError, SSLError
from google.auth.transport import requests as auth_requests
from ccib.chronicle import Chronicle

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to see more detailed information
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('connection_test_simple')

def create_test_indicators():
    """Create test indicators that match the format from Falcon API."""
    # Create indicators similar to what would come from Falcon API
    timestamp = int(time.time())
    indicators = []

    # Create a few different types of indicators
    indicators.append({
        "type": "domain",
        "value": f"test-{timestamp}.example.com",
        "created_on": timestamp,
        "last_updated": timestamp,
        "source": "test_script",
        "expiration_time": timestamp + 86400,  # 24 hours from now
        "confidence": "medium",
        "_marker": str(timestamp)  # This field is used by the main application
    })

    indicators.append({
        "type": "ip_address",
        "value": f"192.0.2.{timestamp % 255}",  # Using TEST-NET-1 range
        "created_on": timestamp,
        "last_updated": timestamp,
        "source": "test_script",
        "expiration_time": timestamp + 86400,
        "confidence": "high",
        "_marker": str(timestamp + 1)
    })

    return indicators

class UnreliableChronicle(Chronicle):
    """A Chronicle client that simulates connection issues."""

    # pylint: disable=too-many-positional-arguments
    def __init__(self, customer_id, service_account_file, region, failure_rate=0.3, timeout_rate=0.2):
        """Initialize with failure simulation parameters.

        Args:
            customer_id: Chronicle customer ID
            service_account_file: Path to service account JSON file
            region: Chronicle region
            failure_rate: Probability of simulating a connection failure (0-1)
            timeout_rate: Probability of simulating a timeout (0-1)
        """
        super().__init__(customer_id, service_account_file, region)
        self.failure_rate = failure_rate
        self.timeout_rate = timeout_rate
        self.original_post = self.http_session.post

        # Replace the post method with our unreliable version
        self.http_session.post = self._unreliable_post

    def _unreliable_post(self, *post_args, **kwargs):
        """Simulate an unreliable HTTP POST request."""
        # Simulate random failures
        if random.random() < self.failure_rate:
            logger.info("Simulating connection failure")

            # Simulate the same error as in the customer's logs
            ssl_error = SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:1028)')
            urllib3_ssl_error = SSLError(ssl_error)
            max_retry_error = MaxRetryError(None, post_args[0], urllib3_ssl_error)
            raise requests.exceptions.SSLError(max_retry_error)

        # Simulate timeouts
        if random.random() < self.timeout_rate:
            logger.info("Simulating connection timeout")
            time.sleep(2)  # Brief delay to simulate slow connection
            raise requests.exceptions.Timeout("Connection timed out")

        # Otherwise, proceed normally
        return self.original_post(*post_args, **kwargs)

# pylint: disable=too-many-positional-arguments
def test_connection_resilience(service_account_file, customer_id, region, iterations=20, delay=2,
                              failure_rate=0.3, timeout_rate=0.2):
    """Test the connection resilience using simulated failures."""
    logger.info("Starting connection resilience test with %d iterations", iterations)
    logger.info("Using customer_id: %s, region: %s", customer_id, region)
    logger.info("Service account file: %s", service_account_file)
    logger.info("Failure rate: %.2f, Timeout rate: %.2f", failure_rate, timeout_rate)

    # Create unreliable Chronicle client
    chronicle = UnreliableChronicle(
        customer_id=customer_id,
        service_account_file=service_account_file,
        region=region,
        failure_rate=failure_rate,
        timeout_rate=timeout_rate
    )
    logger.info("Chronicle endpoint: %s", chronicle.ingest_endpoint)

    success_count = 0
    failure_count = 0

    for i in range(iterations):
        logger.info("Iteration %d/%d: Starting test", i+1, iterations)

        # Create test indicators
        indicators = create_test_indicators()
        logger.debug("Indicators: %s", indicators)

        # Send the indicators through our wrapper function that handles retries
        success = send_with_retries(chronicle, indicators)

        if success:
            success_count += 1
            logger.info("Iteration %d/%d: Successfully sent indicators", i+1, iterations)
        else:
            failure_count += 1
            logger.info("Iteration %d/%d: Failed to send indicators after retries", i+1, iterations)

        # Wait between iterations
        if i < iterations - 1:
            logger.info("Waiting %d seconds before next iteration", delay)
            time.sleep(delay)

    logger.info("Test completed: %d successes, %d failures", success_count, failure_count)
    return success_count, failure_count

def send_with_retries(chronicle, indicators, max_retries=5):
    """Send indicators with retries, simulating our production retry logic."""
    for attempt in range(max_retries):
        try:
            # Format indicators for Chronicle in the same way as the main application
            ts = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000000)
            entries = [
                {
                    "log_text": json.dumps(indicator),
                    "ts_epoch_microseconds": ts
                }
                for indicator in indicators
            ]
            logger.debug("Formatted entries: %s", entries)

            # Prepare the request
            body = {
                'customer_id': chronicle.customer_id,
                'log_type': "CROWDSTRIKE_IOC",  # Use the same log type as in the main application
                'entries': entries,
            }
            logger.debug("Request body: %s", json.dumps(body))

            # Send request with timeout
            response = chronicle.http_session.post(
                chronicle.ingest_endpoint,
                json=body,
                timeout=(10, 30)  # (connect timeout, read timeout) in seconds
            )

            # Log the response details before raising for status
            logger.debug("Response status: %d", response.status_code)
            logger.debug("Response headers: %s", response.headers)

            try:
                response_json = response.json()
                logger.debug("Response content: %s", json.dumps(response_json))
            except ValueError:
                logger.debug("Response content (not JSON): %s", response.text[:1000])

            response.raise_for_status()

            # If we get here, the request was successful
            return True

        except requests.exceptions.RequestException as e:
            logger.error("Attempt %d/%d failed: %s: %s", attempt+1, max_retries, type(e).__name__, str(e))

            # Get more details about the error
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    logger.error("Error details: %s", json.dumps(error_detail))
                except ValueError:
                    logger.error("Error response: %s", e.response.text[:1000])

            # Use exponential backoff
            backoff_seconds = min(2 ** attempt, 60)
            logger.info("Retrying in %d seconds...", backoff_seconds)
            time.sleep(backoff_seconds)

            # For persistent failures, recreate the session
            if attempt == 3:
                logger.info("Recreating HTTP session...")
                # This simulates what our production code does
                chronicle.http_session = auth_requests.AuthorizedSession(chronicle.credentials)

        except Exception as e:  # pylint: disable=broad-except
            logger.error("Attempt %d/%d failed with unexpected error: %s: %s",
                        attempt+1, max_retries, type(e).__name__, str(e))

            # Use exponential backoff
            backoff_seconds = min(2 ** attempt, 60)
            logger.info("Retrying in %d seconds...", backoff_seconds)
            time.sleep(backoff_seconds)

    # If we get here, all retries failed
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Chronicle connection resilience')
    parser.add_argument('--service-account', required=True, help='Path to service account JSON file')
    parser.add_argument('--customer-id', required=True, help='Chronicle customer ID')
    parser.add_argument('--region', default='', help='Chronicle region (EU, UK, etc.)')
    parser.add_argument('--iterations', type=int, default=20, help='Number of test iterations')
    parser.add_argument('--delay', type=int, default=2, help='Delay between iterations in seconds')
    parser.add_argument('--failure-rate', type=float, default=0.3, help='Simulated failure rate (0-1)')
    parser.add_argument('--timeout-rate', type=float, default=0.2, help='Simulated timeout rate (0-1)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Set log level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    test_connection_resilience(
        service_account_file=args.service_account,
        customer_id=args.customer_id,
        region=args.region,
        iterations=args.iterations,
        delay=args.delay,
        failure_rate=args.failure_rate,
        timeout_rate=args.timeout_rate
    )
