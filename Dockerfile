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
    cd  /opt/logs/access/ && \\
    touch proxy.log admin.log admin-gui.log portal-api.log status.log proxy-stream.log && \\
    cd /opt/logs/error/ && \\
   touch proxy.log admin.log admin-gui.log portal-api.log status.log proxy-stream.log
COPY --from=plugin-builder /go-plugins/kong-waf/kong-waf /usr/local/bin/kong-waf

USER kong
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 8000 8443 8001 8444
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=10s --retries=10 CMD kong health
CMD ["kong", "docker-start"]
