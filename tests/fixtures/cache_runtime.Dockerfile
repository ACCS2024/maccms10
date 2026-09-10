# Optional native cache integration fixture. AUDIT_BASE must provide PHP 8.3/8.4,
# Composer project requirements, php-redis and docker-php-ext-enable.
ARG AUDIT_BASE
FROM ${AUDIT_BASE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmemcached-dev zlib1g-dev libsasl2-dev memcached sasl2-bin redis-server libsasl2-modules \
 && pecl install memcache-8.2 \
 && printf '\n\n\n\n\n\n\n\n\n' | pecl install memcached-3.3.0 \
 && docker-php-ext-enable memcache memcached \
 && rm -rf /var/lib/apt/lists/*
