/**
 * ============================================================================
 * Servidor Node.js para Produção - Produção
 * ============================================================================
 * 
 * Este servidor demonstra:
 * - Logging estruturado
 * - Healthchecks robustos
 * - Conexão com PostgreSQL
 * - Leitura de secrets
 * - Graceful shutdown
 */

const express = require('express');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// ============================================================================
// CONFIGURAÇÃO DE LOGGING
// ============================================================================
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { 
    service: 'production-app',
    environment: process.env.NODE_ENV,
    version: '1.0.0'
  },
  transports: [
    // Log para arquivo (persistência local)
    new winston.transports.File({ 
      filename: '/app/logs/error.log', 
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: '/app/logs/combined.log',
      maxsize: 10485760,
      maxFiles: 5
    }),
    // Log para console (coletado pelo Docker)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ============================================================================
// LEITURA DE SECRETS
// ============================================================================
function readSecret(secretName) {
  try {
    const secretPath = path.join('/run/secrets', secretName);
    if (fs.existsSync(secretPath)) {
      const secret = fs.readFileSync(secretPath, 'utf8').trim();
      logger.info(`Secret '${secretName}' loaded successfully`);
      return secret;
    } else {
      logger.warn(`Secret file not found: ${secretPath}. Using environment variable.`);
      return process.env[secretName.toUpperCase()];
    }
  } catch (error) {
    logger.error(`Error reading secret '${secretName}': ${error.message}`);
    return process.env[secretName.toUpperCase()];
  }
}

// ============================================================================
// CONFIGURAÇÃO DO BANCO DE DADOS
// ============================================================================
const dbUser = readSecret('db_user');
const dbPassword = readSecret('db_password');

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'appdb',
  user: dbUser,
  password: dbPassword,
  max: 20, // Máximo de conexões no pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Event listener para erros
pool.on('error', (err) => {
  logger.error('Unexpected error on idle database client', { error: err.message });
});

// ============================================================================
// CONFIGURAÇÃO DO EXPRESS
// ============================================================================
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware de parsing
app.use(express.json());

// Middleware de logging de requisições
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    
    // Log estruturado
    logger.info('HTTP Request', {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: duration,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });
  });
  
  next();
});

// ============================================================================
// ROTAS DA APLICAÇÃO
// ============================================================================

// Rota principal
app.get('/', (req, res) => {
  res.json({
    message: 'Docker Production App - Produção',
    version: '1.0.0',
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Rota de health check
app.get('/health', async (req, res) => {
  try {
    // Verificar conexão com banco
    const result = await pool.query('SELECT NOW()');
    
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: {
        connected: true,
        timestamp: result.rows[0].now
      },
      memory: process.memoryUsage()
    };
    
    logger.debug('Health check passed', health);
    res.json(health);
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Rota de readiness (para Kubernetes ou load balancers)
app.get('/ready', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).send('OK');
  } catch (error) {
    logger.error('Readiness check failed', { error: error.message });
    res.status(503).send('Service Unavailable');
  }
});

// Rota de exemplo com banco de dados
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, created_at FROM users ORDER BY id');
    res.json({
      count: result.rowCount,
      users: result.rows
    });
  } catch (error) {
    logger.error('Error fetching users', { error: error.message });
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Criar novo usuário
app.post('/users', async (req, res) => {
  const { name, email } = req.body;
  
  if (!name || !email) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Name and email are required'
    });
  }
  
  try {
    const result = await pool.query(
      'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *',
      [name, email]
    );
    
    logger.info('User created', { userId: result.rows[0].id, email });
    
    res.status(201).json({
      message: 'User created successfully',
      user: result.rows[0]
    });
  } catch (error) {
    logger.error('Error creating user', { error: error.message, name, email });
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Rota 404
app.use((req, res) => {
  logger.warn('Route not found', { path: req.path, method: req.method });
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found'
  });
});

// Error handler global
app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    path: req.path
  });
  
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message
  });
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================
let server;

function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  // Parar de aceitar novas conexões
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Fechar pool de conexões do banco
    pool.end(() => {
      logger.info('Database pool closed');
      logger.info('Graceful shutdown completed');
      process.exit(0);
    });
  });
  
  // Forçar shutdown após 30 segundos
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
}

// Capturar sinais de shutdown
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Capturar erros não tratados
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason, promise });
});

// ============================================================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================================================
async function startServer() {
  try {
    // Verificar conexão com banco antes de iniciar
    logger.info('Testing database connection...');
    await pool.query('SELECT NOW()');
    logger.info('Database connection successful');
    
    // Iniciar servidor
    server = app.listen(PORT, '0.0.0.0', () => {
      logger.info(`Server started successfully`, {
        port: PORT,
        environment: process.env.NODE_ENV,
        nodeVersion: process.version,
        pid: process.pid
      });
    });
    
  } catch (error) {
    logger.error('Failed to start server', { error: error.message });
    process.exit(1);
  }
}

// Iniciar aplicação
startServer();

module.exports = app; // Para testes
