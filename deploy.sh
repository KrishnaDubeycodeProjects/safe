#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────────
# deploy.sh — SAFE Platform Production Deployment Script
#
# What it does:
#   1. Validates required environment variables
#   2. Generates admin gate password hash
#   3. Builds Astro frontend (static)
#   4. Builds Docker images for both backends
#   5. Starts nginx + certbot + backends via docker-compose
#   6. Runs smoke tests on all endpoints
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh
#
# Requirements:
#   - Node.js 18+, npm
#   - Docker + Docker Compose v2
#   - Your domain's DNS A record pointing to this server
# ────────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()    { echo -e "${BLUE}[DEPLOY]${NC} $1"; }
ok()     { echo -e "${GREEN}[  OK  ]${NC} $1"; }
warn()   { echo -e "${YELLOW}[ WARN ]${NC} $1"; }
error()  { echo -e "${RED}[ERROR ]${NC} $1"; exit 1; }
section(){ echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$DEPLOY_DIR/SecuritySafe"
MAIN_BACKEND_DIR="$DEPLOY_DIR/security-safe-chat/security-safe-chat-backend"
AI_BACKEND_DIR="$DEPLOY_DIR/Digital-arrest-detector"

# ─────────────────────────────────────────────────────────────────────────────
section "Step 1 — Pre-flight checks"
# ─────────────────────────────────────────────────────────────────────────────

command -v node   >/dev/null 2>&1 || error "Node.js is not installed."
command -v npm    >/dev/null 2>&1 || error "npm is not installed."
command -v docker >/dev/null 2>&1 || error "Docker is not installed."
command -v docker-compose >/dev/null 2>&1 || (docker compose version >/dev/null 2>&1) || error "Docker Compose is not installed."
ok "All required tools found."

# ─────────────────────────────────────────────────────────────────────────────
section "Step 2 — Validate environment files"
# ─────────────────────────────────────────────────────────────────────────────

FRONTEND_ENV="$FRONTEND_DIR/.env"
MAIN_ENV="$MAIN_BACKEND_DIR/.env"
AI_ENV="$AI_BACKEND_DIR/.env"

[[ -f "$FRONTEND_ENV" ]] || error "Missing: $FRONTEND_ENV  — copy .env.example and fill in values."
[[ -f "$MAIN_ENV"     ]] || error "Missing: $MAIN_ENV  — copy .env.example and fill in values."
[[ -f "$AI_ENV"       ]] || error "Missing: $AI_ENV  — create .env for AI backend."

# Required frontend vars
for var in PUBLIC_MAIN_API_URL PUBLIC_AI_API_URL PUBLIC_ADMIN_KEY PUBLIC_ADMIN_PATH; do
    grep -q "^${var}=" "$FRONTEND_ENV" || warn "Missing $var in $FRONTEND_ENV"
done

# Required backend vars
for var in ADMIN_BLOG_KEY CORS_ORIGINS APP_ENV; do
    grep -q "^${var}=" "$MAIN_ENV" 2>/dev/null || grep -qi "^${var}=" "$MAIN_ENV" || warn "Missing $var in $MAIN_ENV"
done

# Check APP_ENV=production
if grep -qi "APP_ENV=production" "$MAIN_ENV"; then
    ok "Backend APP_ENV=production confirmed."
    # Enforce CORS is not wildcard in production
    CORS_VAL=$(grep -i "CORS_ORIGINS=" "$MAIN_ENV" | cut -d= -f2- | tr -d '"' | tr -d "'")
    if [[ "$CORS_VAL" == "*" ]]; then
        error "CORS_ORIGINS=* is not allowed in production. Set it to your domain(s)."
    fi
else
    warn "APP_ENV is not 'production' in $MAIN_ENV. Set APP_ENV=production for security hardening."
fi

ok "Environment files validated."

# ─────────────────────────────────────────────────────────────────────────────
section "Step 3 — Generate admin gate password hash"
# ─────────────────────────────────────────────────────────────────────────────

GATE_HASH_LINE=$(grep "PUBLIC_ADMIN_GATE_HASH=" "$FRONTEND_ENV" || true)
GATE_HASH_VAL=$(echo "$GATE_HASH_LINE" | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs)

if [[ -z "$GATE_HASH_VAL" ]]; then
    warn "PUBLIC_ADMIN_GATE_HASH is not set."
    echo ""
    read -s -p "  Enter your admin gate password (will be hashed, not stored plaintext): " GATE_PASS
    echo ""

    if [[ -n "$GATE_PASS" ]]; then
        HASH=$(node -e "
const { createHash } = require('crypto');
const hash = createHash('sha256').update('$GATE_PASS').digest('hex');
console.log(hash);
        ")
        # Update the .env file
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^PUBLIC_ADMIN_GATE_HASH=.*/PUBLIC_ADMIN_GATE_HASH=$HASH/" "$FRONTEND_ENV"
        else
            sed -i "s/^PUBLIC_ADMIN_GATE_HASH=.*/PUBLIC_ADMIN_GATE_HASH=$HASH/" "$FRONTEND_ENV"
        fi
        ok "Admin gate hash written to .env: ${HASH:0:16}..."
    else
        warn "Skipped — admin panel will fall back to direct key comparison."
    fi
else
    ok "Admin gate hash already configured."
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Step 4 — Build Astro frontend"
# ─────────────────────────────────────────────────────────────────────────────

log "Installing frontend dependencies..."
cd "$FRONTEND_DIR"
npm ci --prefer-offline 2>/dev/null || npm install

log "Building Astro static site..."
npm run build

DIST_DIR="$FRONTEND_DIR/dist"
[[ -d "$DIST_DIR" ]] || error "Frontend build failed — dist/ not found."
FILE_COUNT=$(find "$DIST_DIR" -type f | wc -l)
ok "Frontend built — $FILE_COUNT files in dist/."

# Copy dist to where nginx expects it
mkdir -p "$DEPLOY_DIR/frontend"
cp -r "$DIST_DIR"/* "$DEPLOY_DIR/frontend/"
ok "Frontend copied to $DEPLOY_DIR/frontend/"

# ─────────────────────────────────────────────────────────────────────────────
section "Step 5 — Build Docker images"
# ─────────────────────────────────────────────────────────────────────────────

cd "$DEPLOY_DIR"

log "Building main backend image..."
docker build -t safe-main-backend:latest "$MAIN_BACKEND_DIR"
ok "Main backend image built."

log "Building AI backend image..."
docker build -t safe-ai-backend:latest "$AI_BACKEND_DIR"
ok "AI backend image built."

# ─────────────────────────────────────────────────────────────────────────────
section "Step 6 — SSL Certificate (Let's Encrypt)"
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN=$(grep "PUBLIC_MAIN_API_URL=" "$FRONTEND_ENV" | cut -d= -f2- | sed 's|https://||' | sed 's|http://||' | cut -d: -f1 | tr -d '"' | xargs)
CERTBOT_DIR="$DEPLOY_DIR/certbot"
mkdir -p "$CERTBOT_DIR/conf" "$CERTBOT_DIR/www"

if [[ -d "$CERTBOT_DIR/conf/live/$DOMAIN" ]]; then
    ok "SSL certificate already exists for $DOMAIN."
else
    warn "No SSL certificate found. Running certbot..."
    warn "Make sure your domain $DOMAIN points to this server's IP."
    docker run --rm \
        -v "$CERTBOT_DIR/conf:/etc/letsencrypt" \
        -v "$CERTBOT_DIR/www:/var/www/certbot" \
        -p 80:80 \
        certbot/certbot certonly \
        --standalone \
        --agree-tos \
        --no-eff-email \
        -d "$DOMAIN" \
        --email "admin@$DOMAIN" || warn "Certbot failed. Update nginx.conf to use HTTP-only temporarily."
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Step 7 — Start services"
# ─────────────────────────────────────────────────────────────────────────────

log "Stopping any existing containers..."
docker compose -f docker-compose.prod.yml down --remove-orphans 2>/dev/null || true

log "Starting production stack..."
docker compose -f docker-compose.prod.yml up -d --build

ok "All services started."

# ─────────────────────────────────────────────────────────────────────────────
section "Step 8 — Smoke tests"
# ─────────────────────────────────────────────────────────────────────────────

log "Waiting 15s for services to initialize..."
sleep 15

MAIN_URL="http://localhost:8000"
AI_URL="http://localhost:8001"
PASS=0; FAIL=0

smoke_test() {
    local label="$1"; local url="$2"; local expected="$3"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "$expected" ]]; then
        ok "$label → HTTP $code"
        ((PASS++))
    else
        warn "$label → Expected $expected, got HTTP $code"
        ((FAIL++))
    fi
}

smoke_test "Main backend /health"          "$MAIN_URL/health"          "200"
smoke_test "Main backend /api/blogs"       "$MAIN_URL/api/blogs"       "200"
smoke_test "AI backend /health"            "$AI_URL/health"            "200"
smoke_test "AI backend /api/community/stats" "$AI_URL/api/community/stats" "200"
smoke_test "Docs hidden in prod"           "$MAIN_URL/docs"            "404"

echo ""
echo -e "${GREEN}  Passed: $PASS${NC}  ${RED}Failed: $FAIL${NC}"

# ─────────────────────────────────────────────────────────────────────────────
section "Deployment complete!"
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${GREEN}"
echo "  ✅  Frontend:      https://$DOMAIN"
echo "  ✅  Main API:      https://$DOMAIN/api/"
echo "  ✅  AI API:        https://$DOMAIN/api/community/"
echo "  🔒  Admin panel:   https://$DOMAIN/$(grep 'PUBLIC_ADMIN_PATH=' "$FRONTEND_ENV" | cut -d= -f2 | tr -d '"')"
echo ""
echo "  Useful commands:"
echo "    docker compose -f docker-compose.prod.yml logs -f        # stream logs"
echo "    docker compose -f docker-compose.prod.yml ps             # status"
echo "    docker compose -f docker-compose.prod.yml restart nginx  # reload nginx"
echo -e "${NC}"
