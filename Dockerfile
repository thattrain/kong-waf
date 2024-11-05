FROM golang:1.22 as plugin-builder

RUN mkdir /go-plugins
COPY ./ /go-plugins/kong-waf/
RUN cd /go-plugins/kong-waf/ && \
    go mod tidy && \
    go build


FROM kong:3.8.0-ubuntu

USER root
RUN mkdir -p /opt/logs/plugins/kong-waf &&  \
    mkdir -p /opt/logs/access/ && \
    mkdir -p /opt/logs/error/ && \
    chown -R kong:kong /opt/logs/ && \\
    touch opt/logs/access/proxy.log opt/logs/access/admin.log opt/logs/access/admin-gui.log opt/logs/access/portal-api.log opt/logs/access/status.log opt/logs/access/proxy-stream.log && \\
    touch opt/logs/error/proxy.log opt/logs/error/admin.log opt/logs/error/admin-gui.log opt/logs/error/portal-api.log opt/logs/error/status.log opt/logs/error/proxy-stream.log
COPY --from=plugin-builder /go-plugins/kong-waf/kong-waf /usr/local/bin/kong-waf

USER kong
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 8000 8443 8001 8444
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=10s --retries=10 CMD kong health
CMD ["kong", "docker-start"]
