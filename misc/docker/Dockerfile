##############################
# DEPENDENCY STEP
####

FROM node:23.9-bookworm AS bootstrap

WORKDIR /opt/app

COPY service ./

RUN addgroup \
    --gid "1001" \
    "rrr" \
&&  adduser \
    --disabled-password \
    --gecos "" \
    --home "$(pwd)" \
    --ingroup "rrr" \
    --no-create-home \
    --uid "1001" \
    rrr

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends git bash \
	autoconf automake libtool make \
	gcc \
	g++ \
	libevent-dev libssl-dev libjemalloc-dev libnode-dev libperl-dev libjson-c-dev zlib1g-dev \
	node-typescript expect \
	s6

##############################
# RRR BUILD STEP
####
FROM bootstrap AS build

# Clone and build RRR
RUN ./build.sh /tmp

##############################
# RRR INSTALLATION STEP
####
FROM build AS install

# Switch to privileged user to install RRR
WORKDIR /tmp/rrr
USER root
RUN make V=1 install && ldconfig

# Make runtime and link install directories
RUN mkdir -p /var/lib/rrr && \
	mkdir -p /var/run/rrr && \
	mkdir -p /var/run/s6 && \
	chown -R rrr:rrr /var/run/rrr /var/run/s6

# Cleanup build files
RUN rm -rf /tmp/rrr

##############################
# COMPLETION STEP
####
FROM install AS de-escalate

# Switch user and go to application directory
USER rrr
WORKDIR /opt/app

# Entrypoint
ENTRYPOINT [ "./run.sh" ]
