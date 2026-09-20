#!/bin/bash
set -e

ENV_FILE="/var/www/html/storage/.env"

mkdir -p /var/www/html/storage
mkdir -p /var/www/html/public/attachments
mkdir -p /var/www/html/storage/backups

# Make sure Render has all required secrets/settings
required_vars=(
  DATABASE_HOST
  DATABASE_PORT
  DATABASE_DATABASE
  DATABASE_USER
  DATABASE_PASSWORD
  DATABASE_ENCRYPTION_KEY
  REDIS_HOST
  REDIS_PORT
  REDIS_USER
  REDIS_PASSWORD
)

for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: Missing required environment variable: $var"
    exit 1
  fi
done

cat > "$ENV_FILE" <<EOF
DATABASE_HOST=${DATABASE_HOST}
DATABASE_PORT=${DATABASE_PORT}
DATABASE_DATABASE=${DATABASE_DATABASE}
DATABASE_USER=${DATABASE_USER}
DATABASE_PASSWORD=${DATABASE_PASSWORD}
DATABASE_ENCRYPTION="xchacha20"
DATABASE_ENCRYPTION_KEY="${DATABASE_ENCRYPTION_KEY}"

DATABASE_SSL=true
DATABASE_SSL_CA=/var/www/html/ca.pem

REDIS_HOST=${REDIS_HOST}
REDIS_PORT=${REDIS_PORT}
REDIS_USER=${REDIS_USER}
REDIS_PASSWORD=${REDIS_PASSWORD}
REDIS_TLS=true

XALIX_SETUP_MODE=${XALIX_SETUP_MODE:-false}
firewall_enabled=false
EOF

echo "Waiting for Aiven MySQL at ${DATABASE_HOST}:${DATABASE_PORT}..."

connected=false

for attempt in $(seq 1 30); do
    if bash -c "</dev/tcp/${DATABASE_HOST}/${DATABASE_PORT}" 2>/dev/null; then
        echo "Aiven MySQL is reachable!"
        connected=true
        break
    fi

    echo "Waiting for MySQL... ($attempt/30)"
    sleep 2
done

if [ "$connected" != "true" ]; then
    echo "ERROR: Could not reach Aiven MySQL."
    exit 1
fi

echo "Installing Composer dependencies..."
COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader

echo "Checking patched PHP files..."

php -d display_errors=1 \
    -d display_startup_errors=1 \
    -l /var/www/html/app/Chat/Database.php

php -d display_errors=1 \
    -d display_startup_errors=1 \
    -l /var/www/html/app/FastChat/Redis.php

php -d display_errors=1 \
    -d display_startup_errors=1 \
    -l /var/www/html/app/Api/User/Auth/Register.php

php -d display_errors=1 \
    -d display_startup_errors=1 \
    -l /var/www/html/app/Api/User/Auth/Login.php

echo "Xalix setup mode: ${XALIX_SETUP_MODE:-false}"
echo "Checking PDO MySQL SSL support..."

php -r '
echo "pdo_mysql loaded: " . (extension_loaded("pdo_mysql") ? "YES" : "NO") . PHP_EOL;
echo "MYSQL_ATTR_SSL_CA available: " . (defined("PDO::MYSQL_ATTR_SSL_CA") ? "YES" : "NO") . PHP_EOL;
echo "CA certificate readable: " . (is_readable("/var/www/html/ca.pem") ? "YES" : "NO") . PHP_EOL;
'

echo "Running MythicalDash migrations..."

php \
    -d display_errors=1 \
    -d display_startup_errors=1 \
    -d log_errors=0 \
    /var/www/html/cli migrate

echo "Setting permissions..."

mkdir -p /var/www/html/backend/storage/logs
mkdir -p /var/www/html/storage/logs

touch /var/www/html/backend/storage/logs/mythicaldash-v3.log
touch /var/www/html/backend/storage/logs/mythicaldash.log
touch /var/www/html/storage/logs/mythicaldash-v3.log
touch /var/www/html/storage/logs/mythicaldash.log

chown -R www-data:www-data \
    /var/www/html/storage \
    /var/www/html/backend/storage \
    /var/www/html/public/attachments

find /var/www/html/storage /var/www/html/backend/storage /var/www/html/public/attachments \
    -type d -exec chmod 775 {} \;

find /var/www/html/storage /var/www/html/backend/storage /var/www/html/public/attachments \
    -type f -exec chmod 664 {} \;

echo "Setting up cron..."
/usr/local/bin/setup-cron.sh

chown -R www-data:www-data \
    /var/www/html/storage \
    /var/www/html/backend/storage \
    /var/www/html/public/attachments

rm -f /var/www/html/index.nginx-debian.html

echo ""
echo "🚀 XalixCloud MythicalDash backend starting..."
echo ""

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
