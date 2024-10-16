FROM golang:1.22 as plugin-builder

RUN mkdir /go-plugins
COPY ./ /go-plugins/kong-waf/
RUN cd /go-plugins/kong-waf/ && \
    go mod tidy && \
    go build


FROM kong:3.8.0-ubuntu

USER root
RUN mkdir -p /opt/logs/plugins/kong-waf &&  \
    chown -R kong:kong /opt/logs/
COPY --from=plugin-builder /go-plugins/kong-waf/kong-waf /usr/local/bin/kong-waf

USER kong
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 8000 8443 8001 8444
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=10s --retries=10 CMD kong health
CMD ["kong", "docker-start"]
