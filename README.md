# CrowdStrike Chronicle Intel Bridge


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
