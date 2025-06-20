const mysql = require('mysql2/promise');
require('dotenv').config();
const logger = require('../logger');

let pool;

try {
  const dbUrl = process.env.MYSQL_PUBLIC_URL || 'mysql://root:fclJLNegMkdavkJQkQjrbUTLYWmwFSYQ@caboose.proxy.rlwy.net:29085/railway';
  const { hostname: host, username: user, password, pathname } = new URL(dbUrl);
  const database = pathname.replace('/', '');
  const port = parseInt(dbUrl.split(':')[4], 10) || 29085;

  pool = mysql.createPool({
    host: host,
    user: user,
    password: password.split('@')[0],
    database: database,
    port: port,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  pool.getConnection()
    .then(() => logger.info('Database connected successfully'))
    .catch((err) => {
      logger.error('Database connection failed', {
        error: err.message,
        host: host,
        user: user,
        database: database,
      });
      throw err;
    });
} catch (err) {
  logger.error('Error initializing database pool', {
    error: err.message,
    host: host || 'caboose.proxy.rlwy.net',
    user: user || 'root',
    database: database || 'railway',
  });
  throw err;
}

module.exports = pool;