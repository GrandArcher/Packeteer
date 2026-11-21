# The relying party of the herd lab (lab/e2e-herd.sh, #708): rpki-client
# from Debian. The RIR trust anchor locators the package pulls in are
# removed, so the only trust anchor is the lab one given with -t, and the
# lab runs it with no network.
FROM debian:trixie-slim
RUN apt-get update \
	&& apt-get install -y --no-install-recommends rpki-client \
	&& rm -rf /var/lib/apt/lists/* /etc/tals/*.tal
