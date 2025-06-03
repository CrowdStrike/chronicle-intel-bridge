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

## Configuration

### Environment Variables

Set the following environment variables:

```bash
export FALCON_CLOUD_REGION=YOUR_CLOUD_REGION (e.g., us-1, us-2, eu-1)
export FALCON_CLIENT_ID=YOUR_CLIENT_ID
export FALCON_CLIENT_SECRET=YOUR_CLIENT_SECRET
export CHRONICLE_CUSTOMER_ID=YOUR_CUSTOMER_ID
export CHRONICLE_REGION=YOUR_CHRONICLE_REGION (optional, defaults to US multi-region)
```

### Chronicle Region Configuration

The `CHRONICLE_REGION` environment variable specifies which Chronicle regional endpoint to use. The following values are supported:

- **Legacy region codes**: EU, UK, IL, AU, SG
- **Google Cloud region codes**: US, EUROPE, EUROPE-WEST2, EUROPE-WEST3, EUROPE-WEST6, EUROPE-WEST9, EUROPE-WEST12, ME-WEST1, ME-CENTRAL1, ME-CENTRAL2, ASIA-SOUTH1, ASIA-SOUTHEAST1, ASIA-NORTHEAST1, AUSTRALIA-SOUTHEAST1, SOUTHAMERICA-EAST1, NORTHAMERICA-NORTHEAST2
- If not specified or if an unrecognized value is provided, it defaults to the US multi-region endpoint

> [!NOTE]
> Region codes are case-insensitive, so "eu", "EU", and "Eu" are all treated the same.

### Advanced Configuration

Please refer to the [config.ini](./config/config.ini) file for advanced configuration options and customization.

1. Download/Copy the `config/config.ini` file from this repository to use as a template
1. Make any necessary changes to suit your needs
1. Pass the config file to the container using the volume mount flag:

    ```bash
    -v /path/to/your/config.ini:/ccib/config.ini:ro
    ```

## Deployment Instructions

Run the bridge application

### Interactive mode (foreground)

```bash
docker run -it --rm \
      --name chronicle-intel-bridge \
      -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
      -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
      -e FALCON_CLOUD_REGION="$FALCON_CLOUD_REGION" \
      -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
      -e CHRONICLE_REGION="$CHRONICLE_REGION" \
      -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
      -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
      quay.io/crowdstrike/chronicle-intel-bridge:latest
```

### Detached mode (background with restart policy)

```bash
docker run -d --restart unless-stopped \
      --name chronicle-intel-bridge \
      -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
      -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
      -e FALCON_CLOUD_REGION="$FALCON_CLOUD_REGION" \
      -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
      -e CHRONICLE_REGION="$CHRONICLE_REGION" \
      -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
      -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
      quay.io/crowdstrike/chronicle-intel-bridge:latest
```


### Developer instructions

If you want to build the container locally:

1. Clone the repository
1. Make any changes (ie `config.ini`) needed
1. Build container

    ```bash
    docker build . -t ccib:latest
    ```

1. Run the Bridge

    **Interactive mode (foreground)**

    ```bash
    docker run -it --rm \
        --name chronicle-intel-bridge \
        -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
        -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
        -e FALCON_CLOUD_REGION="$FALCON_CLOUD_REGION" \
        -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
        -e CHRONICLE_REGION="$CHRONICLE_REGION" \
        -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
        -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
        ccib:latest
    ```

    **Detached mode (background with restart policy)**

    ```bash
    docker run -d --restart unless-stopped \
        --name chronicle-intel-bridge \
        -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
        -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
        -e FALCON_CLOUD_REGION="$FALCON_CLOUD_REGION" \
        -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
        -e CHRONICLE_REGION="$CHRONICLE_REGION" \
        -e GOOGLE_SERVICE_ACCOUNT_FILE=/gcloud/sa.json \
        -v /path/to/your/service-account.json:/gcloud/sa.json:ro \
        ccib:latest
    ```

## Statement of Support

This project is a community-driven, open source project designed to forward CrowdStrike Falcon Intelligence Indicators to Chronicle.

While not a formal CrowdStrike product, this project is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT](SUPPORT.md) file.
