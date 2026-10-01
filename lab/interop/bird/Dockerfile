# Simulated BIRD edge for the router interop matrix (#53). Lab only.
# BIRD is Debian's package: bird2 (2.17) or bird3 (3.x, with BMP).
FROM debian:trixie-slim
ARG BIRD=bird3
RUN apt-get update \
	&& apt-get install -y --no-install-recommends "${BIRD}" \
	&& rm -rf /var/lib/apt/lists/* \
	&& mkdir -p /run/bird
ENV BIRD_CONF=bird.conf
CMD ["sh", "-c", "bird --version && exec bird -f -c /etc/bird/$BIRD_CONF -s /run/bird/bird.ctl"]
