# ====================================================================
# UAIP GATEWAY CONFIGURATION
# Copy this file to .env and customize for your environment
# ====================================================================

# ====================================================================
# CRITICAL SECURITY SETTINGS
# ====================================================================

# ADMIN_KEY - Used for approving high-value transactions in dashboard
# SECURITY: Must be minimum 32 characters, use a strong random string
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
ADMIN_KEY=change-this-to-a-secure-random-string-minimum-32-characters

# ====================================================================
# DATABASE CONFIGURATION
# ====================================================================

# Path to SQLite database file
# Default: ./uaip_vault.db (relative to gateway.py)
# Production: Use absolute path like /var/lib/uaip/uaip_vault.db
DB_PATH=uaip_vault.db

# ====================================================================
# NETWORK & CORS SETTINGS
# ====================================================================

# Allowed origins for CORS (comma-separated, no spaces)
# Add your frontend URLs here
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000,https://yourdomain.com

# Allowed hosts for TrustedHostMiddleware (comma-separated, no spaces)
# Use wildcards for subdomains: *.uaip.io
ALLOWED_HOSTS=localhost,127.0.0.1,*.uaip.io

# Trusted proxy IPs (comma-separated, no spaces)
# Only set if behind reverse proxy (nginx, cloudflare, etc.)
# Leave empty if running directly
TRUSTED_PROXIES=

# ====================================================================
# SETTLEMENT CONFIGURATION
# ====================================================================

# Settlement provider identifier
# Used for tracking which provider processed transactions
SETTLEMENT_PROVIDER=provider_01

# ====================================================================
# OPTIONAL: LOGGING CONFIGURATION
# ====================================================================

# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
# Default: INFO
# LOG_LEVEL=INFO

# Log directory (defaults to current directory)
# LOG_DIR=./logs

# ====================================================================
# OPTIONAL: RATE LIMITING
# ====================================================================

# Maximum requests per minute per IP
# Default: 100
# RATE_LIMIT_MAX_REQUESTS=100

# Rate limit window in seconds
# Default: 60
# RATE_LIMIT_WINDOW=60

# ====================================================================
# OPTIONAL: SECURITY TIMEOUTS
# ====================================================================

# Nonce expiry in seconds (prevent replay attacks)
# Default: 120 (2 minutes)
# NONCE_EXPIRY_SECONDS=120

# Timestamp tolerance in seconds (clock skew tolerance)
# Default: 30
# TIMESTAMP_TOLERANCE=30

# Lockout duration after failed attempts (seconds)
# Default: 300 (5 minutes)
# LOCKOUT_DURATION=300

# Maximum failed attempts before lockout
# Default: 5
# MAX_FAILED_ATTEMPTS=5

# ====================================================================
# DEVELOPMENT SETTINGS (DO NOT USE IN PRODUCTION)
# ====================================================================

# Enable debug mode (verbose logging, detailed errors)
# WARNING: Never enable in production!
# DEBUG=False

# Disable SSL verification (for testing only)
# WARNING: Never disable in production!
# VERIFY_SSL=True

# ====================================================================
# NOTES FOR PRODUCTION DEPLOYMENT
# ====================================================================

# 1. Generate strong ADMIN_KEY:
#    python -c "import secrets; print(secrets.token_urlsafe(48))"
#
# 2. Use environment-specific .env files:
#    .env.development
#    .env.staging
#    .env.production
#
# 3. Never commit .env to version control (.gitignore includes it)
#
# 4. Use secrets management in production:
#    - AWS Secrets Manager
#    - HashiCorp Vault
#    - Kubernetes Secrets
#
# 5. Enable HTTPS in production:
#    - Use nginx/caddy as reverse proxy
#    - Obtain SSL certificate (Let's Encrypt)
#
# 6. Monitor logs:
#    - ./uaip_gateway.log
#    - ./uaip_forensic_records.json
#    - ./uaip_settlements.jsonl
#
# ====================================================================