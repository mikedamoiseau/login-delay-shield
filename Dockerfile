# syntax=docker/dockerfile:1
# Dev/test image for the Login Delay Shield plugin.
#
# NOTE: the `# syntax=` directive above MUST stay on line 1 (no comment or blank
# line before it) so BuildKit loads the stable frontend that understands the
# `COPY <<'EOF'` heredocs below. Without it, older/legacy builders parse the
# heredoc body (`set -e`) as a Dockerfile instruction and fail with
# `unknown instruction: SET`.
#
# Bundles PHP 8.2, Composer, WP-CLI, MariaDB, a working WordPress
# install, the WordPress phpunit test harness, and the official
# `plugin-check` plugin. Used by bin/test.sh, bin/plugin-check.sh,
# and bin/check.sh. Not shipped with the plugin.
#
# Why a single image (not docker-compose):
#   - One command (`./bin/test.sh`) runs anywhere with Docker.
#   - No host PHP / MySQL / WP-CLI required.
#   - No external compose project to keep in sync.
#
# Why PHP 8.2 (not the latest):
#   PHP 8.5+ has Mockery/Patchwork compatibility issues that surface
#   in WordPress test harnesses. Pin to 8.2 — the minimum LDS targets
#   in `wp-login-delay.php` is PHP 7.x, so 8.2 is well within range.

FROM php:8.2-cli

ENV WP_PATH=/var/www/html
ENV WP_TESTS_DIR=/tmp/wordpress-tests-lib
ENV WP_CORE_DIR=/tmp/wordpress
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV DEBIAN_FRONTEND=noninteractive

# System packages: git/unzip/curl for composer + harness install,
# mariadb-server for the phpunit-WordPress test harness,
# subversion for the WP test-lib download.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        unzip \
        less \
        ca-certificates \
        curl \
        subversion \
        mariadb-server \
        default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# PHP extensions used by WordPress + the test harness.
# pcntl is required by PHPUnit's php-invoker so that `enforceTimeLimit` in the
# phpunit configs actually aborts a hung test (without pcntl it silently
# no-ops). It is test-infra only and never shipped to wordpress.org.
RUN docker-php-ext-install mysqli pdo_mysql pcntl

# Bump memory limit — WP-CLI's zip extraction and `wp plugin check`
# both routinely exceed the default 128M.
RUN echo 'memory_limit = 512M' > /usr/local/etc/php/conf.d/memory-limit.ini

# Composer + WP-CLI.
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN curl -sSLo /usr/local/bin/wp \
        https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x /usr/local/bin/wp

# Helper: start mariadbd in the background and block until the server
# answers a ping. `service mariadb start` returns before the socket is
# accepting connections; without this wait, the very next `mysql -e ...`
# can race the daemon. Same script is used by the runtime entrypoint.
COPY <<'EOF' /usr/local/bin/mysql-start.sh
#!/usr/bin/env bash
set -e
mkdir -p /run/mysqld /var/lib/mysql
chown -R mysql:mysql /run/mysqld /var/lib/mysql

# Initialise the system tables on first run only.
if [ ! -d /var/lib/mysql/mysql ]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql --skip-test-db >/dev/null
fi

# Start mariadbd detached. The `--skip-networking=0` keeps TCP open so
# WP-CLI's `--dbhost=localhost` (which uses TCP, not the socket) works.
mariadbd --user=mysql --datadir=/var/lib/mysql \
    --socket=/run/mysqld/mysqld.sock \
    --skip-networking=0 \
    --bind-address=127.0.0.1 >/var/log/mariadb-startup.log 2>&1 &

for _ in $(seq 1 60); do
    if mysqladmin ping --silent >/dev/null 2>&1; then
        exit 0
    fi
    sleep 0.5
done

echo "mariadbd failed to become ready in 30s" >&2
cat /var/log/mariadb-startup.log >&2 || true
exit 1
EOF
RUN chmod +x /usr/local/bin/mysql-start.sh

# Install WordPress core + the official `plugin-check` plugin into the
# image so `wp plugin check` works offline on container run.
# bin/plugin-check.sh mounts the packaged plugin under wp-content at run time.
RUN /usr/local/bin/mysql-start.sh \
 && mysql -e "CREATE DATABASE wordpress; CREATE DATABASE wordpress_test; CREATE OR REPLACE USER 'root'@'localhost' IDENTIFIED BY 'root'; CREATE OR REPLACE USER 'root'@'127.0.0.1' IDENTIFIED BY 'root'; GRANT ALL ON *.* TO 'root'@'localhost' WITH GRANT OPTION; GRANT ALL ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION; FLUSH PRIVILEGES;" \
 && mkdir -p "$WP_PATH" \
 && wp --allow-root core download --path="$WP_PATH" \
 && wp --allow-root config create \
        --path="$WP_PATH" \
        --dbname=wordpress \
        --dbuser=root \
        --dbpass=root \
        --dbhost=127.0.0.1 \
        --skip-check \
 && wp --allow-root core install \
        --path="$WP_PATH" \
        --url=http://localhost \
        --title="Login Delay Shield Test" \
        --admin_user=admin \
        --admin_password=admin \
        --admin_email=admin@example.com \
        --skip-email \
 && wp --allow-root plugin install plugin-check --path="$WP_PATH" \
 && mysqladmin shutdown -uroot -proot

# Pre-install the WordPress phpunit test harness so integration tests
# (extending WP_UnitTestCase) work out of the box. Skip DB creation —
# wordpress_test already exists from the previous step.
COPY bin/install-wp-tests.sh /usr/local/bin/install-wp-tests.sh
RUN chmod +x /usr/local/bin/install-wp-tests.sh \
 && /usr/local/bin/mysql-start.sh \
 && /usr/local/bin/install-wp-tests.sh wordpress_test root root 127.0.0.1 latest true \
 && mysqladmin shutdown -uroot -proot

# Entrypoint: starts MariaDB, waits for readiness, then exec's the
# command. A single `docker run` boots the DB, runs phpunit, and tears
# down with the container.
COPY <<'EOF' /usr/local/bin/entrypoint.sh
#!/usr/bin/env bash
set -e
/usr/local/bin/mysql-start.sh
exec "$@"
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
