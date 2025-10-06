-- ============================================================================
-- Script de Inicialização do Banco de Dados - Produção
-- ============================================================================
-- 
-- Este script é executado automaticamente quando o container do PostgreSQL
-- é iniciado pela primeira vez
-- ============================================================================

-- Criar extensões úteis
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- TABELA DE USUÁRIOS (exemplo)
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índice para busca por email
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================================================
-- INSERIR DADOS DE EXEMPLO
-- ============================================================================
INSERT INTO users (name, email) VALUES
    ('Alice Silva', 'alice@example.com'),
    ('Bob Santos', 'bob@example.com'),
    ('Carlos Oliveira', 'carlos@example.com')
ON CONFLICT (email) DO NOTHING;

-- ============================================================================
-- FUNÇÃO PARA ATUALIZAR updated_at AUTOMATICAMENTE
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger para atualizar updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- PERMISSÕES
-- ============================================================================
-- Garantir que o usuário da aplicação tem as permissões necessárias
GRANT CONNECT ON DATABASE appdb TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO CURRENT_USER;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO CURRENT_USER;

-- Configurar permissões padrão para objetos futuros
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO CURRENT_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO CURRENT_USER;

-- ============================================================================
COMMENT ON TABLE users IS 'Tabela de usuários da aplicação';

