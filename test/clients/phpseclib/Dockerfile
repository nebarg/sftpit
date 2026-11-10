# The phpseclib client for sftpit's integration tests, with Laravel's
# filesystem on top of it, so that running them needs Docker but not PHP.
# The tests run each script as "docker run <image> <script> <arguments>".
FROM composer:2.8 AS deps
WORKDIR /client
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --classmap-authoritative

FROM php:8.5-cli
# phpseclib's big-integer arithmetic is far faster with gmp.
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends libgmp-dev \
	&& docker-php-ext-install gmp \
	&& rm -rf /var/lib/apt/lists/*
WORKDIR /client
COPY --from=deps /client/vendor vendor
COPY *.php ./
ENTRYPOINT ["php"]
