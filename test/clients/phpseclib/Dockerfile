# The phpseclib client for sftpit's integration tests, so that running them
# needs Docker but not PHP. The tests run each script as
# "docker run <image> <script> <arguments>". The same scripts run with
# either major version of phpseclib: DEPS names the directory of its
# Composer files, and PHP_VERSION the PHP that runs it.
#   v3 with PHP 8.5: phpseclib 3, with Laravel's filesystem on top of it.
#   v2 with PHP 8.1: phpseclib 2, on a PHP as old as the code that uses it,
#   which raises no deprecations in it.
ARG PHP_VERSION=8.5

FROM composer:2.8 AS deps
ARG DEPS=v3
WORKDIR /client
COPY ${DEPS}/composer.json ${DEPS}/composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --classmap-authoritative

FROM php:${PHP_VERSION}-cli
# phpseclib's big-integer arithmetic is far faster with gmp.
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends libgmp-dev \
	&& docker-php-ext-install gmp \
	&& rm -rf /var/lib/apt/lists/*
WORKDIR /client
COPY --from=deps /client/vendor vendor
COPY *.php ./
ENTRYPOINT ["php"]
