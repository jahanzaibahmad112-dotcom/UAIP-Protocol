# 🐳 UAIP Deployment

## Quick Deploy with Docker
```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env and set ADMIN_KEY
nano .env

# 3. Start services
docker-compose up -d

# 4. Check health
curl http://localhost:8000/health
```

## Files

- **Dockerfile** - Container image definition
- **docker-compose.yml** - Multi-container setup
- **env_example.sh** - Environment variable template

## Production Deployment

See [Architecture Guide](../docs/ARCHITECTURE.md#deployment-architecture) for production setup.