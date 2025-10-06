/**
 * ============================================================================
 * Healthcheck Script - Produção
 * ============================================================================
 * 
 * Script usado pelo Docker HEALTHCHECK para verificar a saúde da aplicação
 * 
 */

const http = require('http');

const options = {
  host: 'localhost',
  port: process.env.PORT || 3000,
  path: '/health',
  timeout: 2000,
  method: 'GET'
};

const request = http.request(options, (res) => {
  console.log(`Healthcheck status: ${res.statusCode}`);
  
  let body = '';
  res.on('data', (chunk) => {
    body += chunk;
  });
  
  res.on('end', () => {
    try {
      const health = JSON.parse(body);
      
      if (res.statusCode === 200 && health.status === 'healthy') {
        console.log('✓ Healthcheck passed');
        process.exit(0);
      } else {
        console.error('✗ Healthcheck failed:', body);
        process.exit(1);
      }
    } catch (error) {
      console.error('✗ Invalid healthcheck response:', error.message);
      process.exit(1);
    }
  });
});

request.on('error', (err) => {
  console.error('✗ Healthcheck error:', err.message);
  process.exit(1);
});

request.on('timeout', () => {
  console.error('✗ Healthcheck timeout');
  request.destroy();
  process.exit(1);
});

request.end();
