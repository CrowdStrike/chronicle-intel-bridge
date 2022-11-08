FROM docker.io/python:3-slim-bullseye

RUN : \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade --no-install-recommends --assume-yes \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /ccib ccibuser
WORKDIR /ccib

COPY requirements.txt .
RUN pip install -r ./requirements.txt

COPY . .

USER ccibuser

CMD [ "python3", "-m" , "ccib"]