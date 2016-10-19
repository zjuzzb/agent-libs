FROM redis:alpine
# This config file adds a password for accessing redis instance
ADD redis.conf /
ENV SYSDIG_AGENT_CONF {app_checks: [{ name: redisdb, pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }] }

ENTRYPOINT ["redis-server"]
CMD [ "/redis.conf" ]
