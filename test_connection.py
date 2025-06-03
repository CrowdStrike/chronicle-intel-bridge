#!/usr/bin/env python3
"""
Test script for Chronicle connection resilience.
This script simulates various network conditions to test the connection handling.
"""

import time
import json
import datetime
import logging
import argparse
import requests
from ccib.chronicle import Chronicle

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to see more detailed information
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('connection_test')

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

def test_connection_resilience(service_account_file, customer_id, region, iterations=10, delay=2):
    """Test the connection resilience by sending multiple requests."""
    logger.info("Starting connection resilience test with %d iterations", iterations)
    logger.info("Using customer_id: %s, region: %s", customer_id, region)
    logger.info("Service account file: %s", service_account_file)

    # Create Chronicle client
    chronicle = Chronicle(customer_id, service_account_file, region)
    logger.info("Chronicle endpoint: %s", chronicle.ingest_endpoint)

    success_count = 0
    failure_count = 0

    for i in range(iterations):
        try:
            logger.info("Iteration %d/%d: Sending test indicators", i+1, iterations)

            # Create test indicators
            indicators = create_test_indicators()
            logger.debug("Indicators: %s", indicators)

            # Format indicators for Chronicle in the same way as the main application
            ts = int(datetime.datetime.utcnow().timestamp() * 1000000)
            entries = [
                {
                    "log_text": json.dumps(indicator),
                    "ts_epoch_microseconds": ts
                }
                for indicator in indicators
            ]
            logger.debug("Formatted entries: %s", entries)

            # Send the entries
            body = {
                'customer_id': customer_id,
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

            logger.info("Iteration %d/%d: Success - Status code: %d", i+1, iterations, response.status_code)
            success_count += 1

        except requests.exceptions.RequestException as e:
            logger.error("Iteration %d/%d: Failed - %s: %s", i+1, iterations, type(e).__name__, str(e))

            # Get more details about the error
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    logger.error("Error details: %s", json.dumps(error_detail))
                except ValueError:
                    logger.error("Error response: %s", e.response.text[:1000])

            failure_count += 1
        except Exception as e:
            logger.error("Iteration %d/%d: Failed with unexpected error - %s: %s",
                        i+1, iterations, type(e).__name__, str(e))
            failure_count += 1

        # Wait between requests
        if i < iterations - 1:
            logger.info("Waiting %d seconds before next request", delay)
            time.sleep(delay)

    logger.info("Test completed: %d successes, %d failures", success_count, failure_count)
    return success_count, failure_count

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Chronicle connection resilience')
    parser.add_argument('--service-account', required=True, help='Path to service account JSON file')
    parser.add_argument('--customer-id', required=True, help='Chronicle customer ID')
    parser.add_argument('--region', default='', help='Chronicle region (EU, UK, etc.)')
    parser.add_argument('--iterations', type=int, default=10, help='Number of test iterations')
    parser.add_argument('--delay', type=int, default=2, help='Delay between requests in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Set log level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    test_connection_resilience(
        args.service_account,
        args.customer_id,
        args.region,
        args.iterations,
        args.delay
    )
