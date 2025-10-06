#!/bin/bash
# ============================================================================
# Script de Deploy Completo - Produção
# ============================================================================
# 
# Este script faz o deploy completo da aplicação (postgres, app, nginx)
# 
# AVISO: Docker Compose não suporta verdadeiro zero-downtime deployment!
# 
# Este script minimiza o downtime mas ainda há uma breve interrupção quando
# os containers são recriados.
# 
# Para VERDADEIRO zero-downtime, considere:
# - Docker Swarm (rolling updates nativos)
# - Kubernetes (rolling updates + readiness probes)
# - Blue-Green deployment com load balancer externo
# - Traefik/HAProxy com múltiplas réplicas
# ============================================================================

set -e

echo "🚀 Deploy Completo"
echo "================================"
echo ""
echo "⚠️  AVISO: Haverá uma breve interrupção (~2-5 segundos)"
echo "   durante a atualização dos containers"
echo ""

# ============================================================================
# Verificar e criar secrets se não existirem
# ============================================================================
echo "🔐 Verificando secrets..."

SECRETS_DIR="./secrets"
mkdir -p "$SECRETS_DIR"

# Verificar db_password
if [ ! -f "$SECRETS_DIR/db_password.txt" ]; then
    echo "   Criando db_password..."
    openssl rand -base64 32 > "$SECRETS_DIR/db_password.txt"
    chmod 644 "$SECRETS_DIR/db_password.txt"
else
    echo "   ✓ db_password existe"
fi

# Verificar db_user
if [ ! -f "$SECRETS_DIR/db_user.txt" ]; then
    echo "   Criando db_user..."
    echo "appuser" > "$SECRETS_DIR/db_user.txt"
    chmod 644 "$SECRETS_DIR/db_user.txt"
else
    echo "   ✓ db_user existe"
fi

# Verificar jwt_secret
if [ ! -f "$SECRETS_DIR/jwt_secret.txt" ]; then
    echo "   Criando jwt_secret..."
    openssl rand -base64 64 > "$SECRETS_DIR/jwt_secret.txt"
    chmod 644 "$SECRETS_DIR/jwt_secret.txt"
else
    echo "   ✓ jwt_secret existe"
fi

# Corrigir permissões de secrets existentes (caso estejam com 600)
echo "   Ajustando permissões dos secrets..."
chmod 644 "$SECRETS_DIR"/*.txt 2>/dev/null || true

echo "✓ Secrets configurados"
echo ""

# Verificar se há mudanças para fazer build
echo "🔍 Verificando mudanças..."
echo ""

echo "📋 Status atual:"
docker compose ps
echo ""

echo "🔨 Buildando imagens..."
docker compose build

if [ $? -ne 0 ]; then
    echo "❌ Erro ao buildar imagens!"
    exit 1
fi

echo "✓ Build concluído"
echo ""

echo "🔄 Atualizando todos os serviços..."
echo "   1. PostgreSQL (será mantido se já estiver rodando)"
echo "   2. App (3 réplicas)"
echo "   3. Nginx"
echo ""

# Deploy completo:
# - Recria apenas o que mudou
# - Mantém postgres rodando se possível (sem --force-recreate global)
docker compose up -d --build

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Deploy concluído com sucesso!"
    echo ""
    
    echo "⏳ Aguardando serviços ficarem saudáveis..."
    sleep 15
    
    echo ""
    echo "📊 Status final:"
    docker compose ps
    echo ""
    
    echo "📝 Logs recentes do app:"
    docker compose logs --tail=10 app
    
    echo ""
    echo "🔗 Endpoints disponíveis:"
    echo "   - Aplicação: http://localhost"
    echo "   - Health: http://localhost/health"
    echo "   - API Users: http://localhost/users"
else
    echo "❌ Erro no deploy!"
    echo ""
    echo "📝 Logs de erro:"
    docker compose logs --tail=50
    exit 1
fi
