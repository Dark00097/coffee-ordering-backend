const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../logger');

let pool;

async function initializePool(retries = 5, delay = 3000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      pool = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 3306,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
      });

      await pool.getConnection();
      logger.info('Database connected successfully');
      return pool;
    } catch (err) {
      logger.error(`Database connection attempt ${attempt} failed`, {
        error: err.message,
      });
      if (attempt === retries) {
        logger.error('Max retries reached. Database connection failed', {
          error: err.message,
        });
        throw err;
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

try {
  module.exports = initializePool();
} catch (err) {
  logger.error('Error initializing database pool', { error: err.message });
  throw err;
}
