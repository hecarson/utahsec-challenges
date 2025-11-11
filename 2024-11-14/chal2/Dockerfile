FROM ubuntu:22.04 AS srv
FROM pwn.red/jail

COPY --from=srv / /srv

COPY app/* /srv/app/
RUN mv /srv/app/chal2 /srv/app/run

ENV JAIL_TIME=1800
