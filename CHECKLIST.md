# Maritime ZTA - Installation & Deployment Checklist

## 📋 **PRE-INSTALLATION (Do This First)**

### System Requirements Check
- [ ] Ubuntu Server 22.04+ or compatible Linux distribution
- [ ] 4+ CPU cores (2 minimum)
- [ ] 8GB+ RAM (6GB minimum)
- [ ] 40GB+ available disk space
- [ ] Docker 24.0+ installed
- [ ] Docker Compose 2.20+ installed
- [ ] Python 3.11+ installed
- [ ] Internet connectivity for downloading images

### Verify Installations
```bash
# Check Docker
docker --version
docker compose version

# Check Python
python3 --version

# Check disk space
df -h
```

## 📥 **STEP 1: Project Setup**

### Download Project
- [ ] Download `maritime-zta.tar.gz`
- [ ] Extract to appropriate location
- [ ] Navigate to project directory

```bash
tar -xzf maritime-zta.tar.gz
cd maritime-zta
```

### Install Poetry (if not installed)
- [ ] Install Poetry package manager

```bash
curl -sSL https://install.python-poetry.org | python3 -
export PATH="$HOME/.local/bin:$PATH"
poetry --version
```

### Install Python Dependencies
- [ ] Install project dependencies

```bash
# Development environment
poetry install

# OR production only
poetry install --without dev,test
```

## 🔐 **STEP 2: Security Configuration**

### Environment Variables
- [ ] Copy `.env.example` to `.env`
- [ ] Generate strong passwords
- [ ] Update all `CHANGE_ME_*` values

```bash
cp .env.example .env

# Generate random password
openssl rand -base64 32

# Generate UUID for Splunk HEC token
python3 -c "import uuid; print(uuid.uuid4())"
```

### Critical .env Values to Change:
- [ ] `MONGO_ROOT_PASSWORD`
- [ ] `SPLUNK_PASSWORD`
- [ ] `SPLUNK_HEC_TOKEN`

### Generate PKI Certificates
- [ ] Run certificate generation script
- [ ] Verify certificates created

```bash
# Generate all certificates
make init-certs

# OR manually
poetry run python scripts/generate_certs.py

# Verify
ls -la certs/ca/
ls -la certs/server/
ls -la certs/clients/
```

**CRITICAL**: Certificates should be generated:
- [ ] `certs/ca/ca.crt` (Certificate Authority)
- [ ] `certs/ca/ca.key` (CA Private Key)
- [ ] `certs/server/envoy.crt` (Envoy certificate)
- [ ] `certs/server/mongodb.crt` (MongoDB certificate)
- [ ] `certs/clients/*/client.crt` (5 client certificates)

## 🔧 **STEP 3: Configuration Validation**

### Validate Configurations
- [ ] Run configuration validator

```bash
make validate-config

# Check individual configs
make validate-opa
make validate-envoy
```

### Review Configuration Files
- [ ] Review `configs/envoy/envoy.yaml`
- [ ] Review `configs/opa/policies/authz.rego`
- [ ] Review `configs/mongodb/mongod.conf`
- [ ] Review `configs/nftables/rules.nft`

## 🐳 **STEP 4: Docker Setup**

### Build Images (Optional - can skip, will build on up)
- [ ] Build all Docker images

```bash
make build

# OR without cache
make build-no-cache
```

### Start Core Services
- [ ] Start all core services
- [ ] Verify services are healthy

```bash
# Start services
make up

# OR
docker compose up -d

# Check status
make ps
docker compose ps
```

**Expected Output**: All services should show status "Up" and "healthy"

### Verify Service Health
```bash
# Splunk
curl http://localhost:8088/services/collector/health

# OPA
curl http://localhost:8181/health

# Envoy
curl http://localhost:9901/ready
```

## 📊 **STEP 5: Verification & Testing**

### Access Web Interfaces
- [ ] **Splunk SIEM**: http://localhost:8000
  - Login with credentials from `.env`
  - Verify indexes created
  - Check for initial logs

- [ ] **Envoy Admin**: http://localhost:9901
  - View /stats
  - Check /clusters health

### Run Test Suite
- [ ] Run unit tests
- [ ] Run integration tests
- [ ] Run security tests

```bash
# All tests
make test-all

# Individual test categories
make test                # Unit tests
make test-integration    # Integration tests
make test-security       # Security tests
```

### Test mTLS Connection
- [ ] Test mTLS from client

```bash
# Start testing clients
docker compose --profile testing up -d

# Test from corporate client
docker exec -it client_corporate bash

# Inside container:
curl --cacert /certs/ca.crt \
     --cert /certs/client.crt \
     --key /certs/client.key \
     https://pep_gateway:8443/health
```

### Verify Zero Trust Policies
- [ ] Test allowed access (corporate client)
- [ ] Test denied access (public client)
- [ ] Verify OPA decision logs
- [ ] Check Splunk alerts

```bash
# View OPA decisions
docker compose logs pdp_engine | grep decision

# View Splunk events
# Go to http://localhost:8000
# Search: index=maritime_*
```

## 📝 **STEP 6: Documentation Review**

### Read Documentation
- [ ] Read `README.md` completely
- [ ] Read `SECURITY.md`
- [ ] Review `docs/architecture.md`
- [ ] Review `docs/security-model.md`

### Understand Workflows
- [ ] Review `.github/workflows/ci.yml`
- [ ] Understand deployment process
- [ ] Review backup procedures

## 🔒 **STEP 7: Security Hardening (Production)**

### Before Production Deployment
- [ ] Change ALL default passwords
- [ ] Rotate certificates (generate fresh)
- [ ] Enable audit logging
- [ ] Configure log rotation
- [ ] Set up backups
- [ ] Configure monitoring alerts
- [ ] Review firewall rules
- [ ] Enable rate limiting
- [ ] Test incident response procedures

### Security Scans
- [ ] Run container vulnerability scan

```bash
make scan-images
```

- [ ] Run security audit

```bash
make audit
```

### Production Checklist
- [ ] Use `docker-compose.prod.yml`
- [ ] Enable TLS for all web interfaces
- [ ] Configure external secrets management
- [ ] Set up log forwarding to external SIEM
- [ ] Enable automated backups
- [ ] Document recovery procedures
- [ ] Set up monitoring and alerting
- [ ] Configure network segmentation
- [ ] Implement certificate rotation
- [ ] Enable intrusion prevention (not just detection)

## 📊 **STEP 8: Monitoring Setup**

### Configure Dashboards
- [ ] Set up Splunk dashboards
- [ ] Configure alerts
- [ ] Set up notifications
- [ ] Test alert delivery

### Configure Monitoring
- [ ] Set up health checks
- [ ] Configure resource monitoring
- [ ] Set up log aggregation
- [ ] Configure metrics collection

## 🧹 **Maintenance**

### Regular Tasks
- [ ] Review logs daily
- [ ] Check for security updates weekly
- [ ] Rotate certificates before expiration
- [ ] Review access policies monthly
- [ ] Update documentation as needed

### Cleanup Commands
```bash
# Stop services
make down

# Stop and remove volumes
make down-volumes

# Clean temporary files
make clean

# Deep clean (includes certs)
make clean-all
```

## ❓ **Troubleshooting**

### Common Issues

**Issue**: Containers not starting
```bash
# Check logs
make logs

# Check specific service
docker compose logs <service_name>
```

**Issue**: Certificate errors
```bash
# Regenerate certificates
make clean-all
make init-certs
```

**Issue**: Port already in use
```bash
# Find process using port
sudo lsof -i :8443

# Change port in docker-compose.yml if needed
```

**Issue**: Low memory
```bash
# Check Docker memory usage
docker stats

# Start only essential services
# Comment out non-essential services in docker-compose.yml
```

## ✅ **Final Verification**

Before considering deployment complete:

- [ ] All services running and healthy
- [ ] All tests passing
- [ ] mTLS working correctly
- [ ] Policies enforcing correctly
- [ ] Logs appearing in Splunk
- [ ] IDS detecting test attacks
- [ ] Firewall blocking unauthorized access
- [ ] Documentation reviewed
- [ ] Team trained on system
- [ ] Incident response plan in place
- [ ] Backup and recovery tested

## 📞 **Support**

If you encounter issues:

1. Check logs: `make logs`
2. Review documentation: `README.md`, `SECURITY.md`
3. Run diagnostics: `make validate-config`
4. Check GitHub issues (if public repo)
5. Contact security team (if internal)

---

**Last Updated**: 2026-05-08
**Version**: 1.0.0
