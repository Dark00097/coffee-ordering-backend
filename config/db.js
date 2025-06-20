const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../logger');

let pool;

try {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'mysql.railway.internal',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'fclJLNegMkdavkJQkQjrbUTLYWmwFSYQ',
    database: process.env.DB_NAME || 'railway',
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  pool.getConnection()
    .then(() => logger.info('Database connected successfully'))
    .catch((err) => {
      logger.error('Database connection failed', {
        error: err.message,
        host: process.env.DB_HOST || 'mysql.railway.internal',
        user: process.env.DB_USER || 'root',
        database: process.env.DB_NAME || 'railway',
      });
      throw err;
    });
} catch (err) {
  logger.error('Error initializing database pool', {
    error: err.message,
    host: process.env.DB_HOST || 'mysql.railway.internal',
    user: process.env.DB_USER || 'root',
    database: process.env.DB_NAME || 'railway',
  });
  throw err;
}

module.exports = pool;