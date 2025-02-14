# CrowdStrike to Chronicle Intel Bridge

[![Python Lint](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/linting.yml)
[![Container Build on Quay](https://quay.io/repository/crowdstrike/chronicle-intel-bridge/status "Docker Repository on Quay")](https://quay.io/repository/crowdstrike/chronicle-intel-bridge)

CrowdStrike to Chronicle Intel Bridge forwards CrowdStrike Falcon Intelligence Indicators to Chronicle.

## Prerequisites

- Create new API key pair at [CrowdStrike Falcon](https://falcon.crowdstrike.com/support/api-clients-and-keys). This key pair will be used to read falcon events and supplementary information from CrowdStrike Falcon.

   Make sure only the following permissions are assigned to the key pair:
  - **Indicators (Falcon Intelligence)**: READ

- Obtain a Chronicle Service Account file and Chronicle Customer ID.
  > A (JSON file) that contains the necessary credentials to authenticate with Chronicle.
  >
  > Your Chronicle Support representative should be able to provide you with your Chronicle Customer ID and Service Account JSON file.

## Deployment Instructions

Set the following environment variables:

```bash
export FALCON_CLOUD_REGION=YOUR_CLOUD_REGION (e.g., us-1, us-2, eu-1)
export FALCON_CLIENT_ID=YOUR_CLIENT_ID
export FALCON_CLIENT_SECRET=YOUR_CLIENT_SECRET
export CHRONICLE_CUSTOMER_ID=YOUR_CUSTOMER_ID
```

Run the bridge application

```bash
docker run -it --rm \
      -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
      -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
      -e FALCON_CLOUD="$FALCON_CLOUD" \
      -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
      -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
      -v ~/my/path/to/service/account/file/sa.json:/gcloud/ \
      quay.io/crowdstrike/chronicle-intel-bridge:latest
```

### Advanced Configuration

Please refer to the [config.ini](./config/config.ini) file for advanced configuration options and customization.

1. Download/Copy the `config/config.ini` file from this repository to use as a template
1. Make any necessary changes to suit your needs
1. Pass the config file to the container using the volume mount flag:

    ```bash
        -v config.ini:/ccib/config.ini
    ```

### Developer instructions

- Build container

   ```bash
   docker build . -t ccib:latest
   ```

- Run the Bridge

   ```bash
   docker run -it --rm \
          -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
          -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
          -e FALCON_CLOUD="$FALCON_CLOUD" \
          -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
          -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
          -v ~/my/path/to/service/account/file/sa.json:/gcloud/ \
          ccib:latest
   ```

## Statement of Support

This project is a community-driven, open source project designed to forward CrowdStrike Falcon Intelligence Indicators to Chronicle.

While not a formal CrowdStrike product, this project is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT](SUPPORT.md) file.
