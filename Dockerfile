FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH quarkengine.QuarkEngine

USER root

# Install any service dependencies here
RUN apt-get update && apt-get install -y git
RUN python3.7 -m pip install -U quark-engine
RUN chown -R assemblyline:assemblyline /opt/al_service/

RUN mkdir -p /opt/al_support/quark-rules
RUN git clone https://github.com/quark-engine/quark-rules /opt/al_support/quark-rules
# Switch to assemblyline user
USER assemblyline


# Copy mobsf service code
WORKDIR /opt/al_service
COPY . .
