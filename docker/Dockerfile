ARG PHP_VERSION=8.4
FROM php:${PHP_VERSION}-apache

# GD 用于普通位图，Imagick 保留 GIF 合成/时序并支持 WebP。
# 扩展:gd/imagick/zip/curl/mbstring/pdo_mysql/mysqli/opcache + redis
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcurl4-openssl-dev libfreetype6-dev libjpeg62-turbo-dev libonig-dev libpng-dev libzip-dev libmagickwand-dev default-mysql-client \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" curl gd mbstring zip pdo_mysql mysqli opcache \
 && pecl install redis imagick-3.8.1 \
 && docker-php-ext-enable redis imagick \
 && a2enmod rewrite \
 && rm -rf /var/lib/apt/lists/*

# Default HTTP boundary lives in the image, not a writable repository .htaccess.
COPY apache/maccms.conf /etc/apache2/sites-available/000-default.conf

# 生产推荐 OPcache 配置(zz- 前缀确保覆盖默认)
COPY php/opcache.ini /usr/local/etc/php/conf.d/zz-opcache.ini
