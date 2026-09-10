ARG PHP_VERSION=8.4
FROM php:${PHP_VERSION}-apache

# 扩展:gd/zip/curl/mbstring/pdo_mysql/mysqli/opcache(性能)+ redis(缓存/会话/计数缓冲)
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcurl4-openssl-dev libfreetype6-dev libjpeg62-turbo-dev libonig-dev libpng-dev libzip-dev default-mysql-client \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" curl gd mbstring zip pdo_mysql mysqli opcache \
 && pecl install redis \
 && docker-php-ext-enable redis \
 && a2enmod rewrite \
 && rm -rf /var/lib/apt/lists/*

# Default HTTP boundary lives in the image, not a writable repository .htaccess.
COPY apache/maccms.conf /etc/apache2/sites-available/000-default.conf

# 生产推荐 OPcache 配置(zz- 前缀确保覆盖默认)
COPY php/opcache.ini /usr/local/etc/php/conf.d/zz-opcache.ini
