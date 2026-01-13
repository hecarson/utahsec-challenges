FROM debian:trixie

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install python3 python3-pip python3-venv python-is-python3 xxd chromium chromium-driver

RUN mkdir /app
WORKDIR /app
COPY app .

RUN python -m venv env
ENV PATH="/app/env/bin:$PATH"
RUN pip install -U -r requirements.txt

RUN useradd -m -s /bin/bash app
RUN chown -R app:app /app
USER app

EXPOSE 10000
CMD ["./init.sh"]
