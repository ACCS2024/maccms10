FROM php:7.4-apache

# 扩展:gd/zip/pdo_mysql/mysqli/opcache(性能)+ redis(缓存/会话/计数缓冲)
RUN apt-get update && apt-get install -y --no-install-recommends \
      libfreetype6-dev libjpeg62-turbo-dev libpng-dev libzip-dev default-mysql-client \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" gd zip pdo_mysql mysqli opcache \
 && pecl install redis \
 && docker-php-ext-enable redis \
 && a2enmod rewrite \
 && printf '%s\n' '<Directory /var/www/html>' '  AllowOverride All' '  Require all granted' '</Directory>' > /etc/apache2/conf-available/maccms.conf \
 && a2enconf maccms \
 && rm -rf /var/lib/apt/lists/*

# 生产推荐 OPcache 配置(zz- 前缀确保覆盖默认)
COPY php/opcache.ini /usr/local/etc/php/conf.d/zz-opcache.ini
