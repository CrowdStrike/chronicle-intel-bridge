# CrowdStrike to Chronicle Intel Bridge

[![Python Lint](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/linting.yml/badge.svg)](https://github.com/CrowdStrike/chronicle-intel-bridge/actions/workflows/linting.yml)
[![Container Build on Quay](https://quay.io/repository/crowdstrike/chronicle-intel-bridge/status "Docker Repository on Quay")](https://quay.io/repository/crowdstrike/chronicle-intel-bridge)

CrowdStrike to Chronicle Intel Bridge forwards CrowdStrike Falcon Intelligence Indicators to Chronicle.

### Deployment Instructions

 - Create new API key pair at [CrowdStrike Falcon](https://falcon.crowdstrike.com/support/api-clients-and-keys). This key pair will be used to read falcon events and supplementary information from CrowdStrike Falcon.

   Make sure only the following permissions are assigned to the key pair:
    * Indicators (Falcon Intelligence): READ

 - Obtain Chronicle Service Account file. Your Chronicle Support representative will provide you Chronicle Customer ID and Service Account JSON file. 

 - Run the bridge application

   ```
   docker run -it --rm \
          -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
          -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
          -e FALCON_CLOUD="$FALCON_CLOUD" \
          -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
          -e GOOGLE_APPLICATION_CREDENTIALS=/gcloud/sa.json \
          -v ~/my/path/to/service/account/file/sa.json:/gcloud/ \
          quay.io/crowdstrike/chronicle-intel-bridge:latest
   ```

### Advanced Configuration

 - Consult [configuration file template](config/config.ini) for available configuration options:
 - Modify template to suite your needs
 - Mount configuration file to the container
   ```
       -v config.ini:/ccib/config.ini
   ```


### Developer instructions

 - Build container
   ```
   docker build . -t ccib:latest
   ```
 - Run the Bridge
   ```
   docker run -it --rm \
          -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
          -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
          -e FALCON_CLOUD="$FALCON_CLOUD" \
          -e CHRONICLE_CUSTOMER_ID="$CHRONICLE_CUSTOMER_ID" \
          -e GOOGLE_APPLICATION_CREDENTIALS=/gcloud/sa.json \
          -v ~/my/path/to/service/account/file/sa.json:/gcloud/ \
          ccib:latest
   ```

## Statement of Support
Chronicle Intel Bridge is an open source project, not CrowdStrike product. As such it carries no formal support, expressed or implied.
