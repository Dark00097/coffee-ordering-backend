const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const logger = require('./logger');
const db = require('./config/db');
const validate = require('./middleware/validate');

const app = express();
const server = http.createServer(app);

// Configure CORS for production
const allowedOrigins = [
  process.env.CLIENT_URL || 'http://localhost:5173',
  'https://coffee-ordering-frontend-production.up.railway.app',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn('CORS blocked', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id', 'Cookie'],
};

app.use(cors(corsOptions));

const io = new Server(server, { 
  cors: {
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  }
});

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST || 'mysql.railway.internal',
  port: parseInt(process.env.DB_PORT, 10) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'fclJLNegMkdavkJQkQjrbUTLYWmwFSYQ',
  database: process.env.DB_NAME || 'railway',
  clearExpired: true,
  checkExpirationInterval: 900000,
  expiration: 86400000,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { 
  setHeaders: (res) => {
    res.set('Access-Control-Allow-Origin', allowedOrigins[1]);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
}));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  logger.error('SESSION_SECRET is not set in the environment');
  process.exit(1);
}

app.use(
  session({
    key: 'session_cookie_name',
    secret: sessionSecret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    },
  })
);

app.use((req, res, next) => {
  logger.info('Incoming request', {
    method: req.method,
    url: req.url,
    user: req.session.user ? req.session.user.id : 'anonymous',
    sessionID: req.sessionID,
    origin: req.headers.origin,
    cookies: req.cookies,
  });
  next();
});

// Public routes (no auth required)
app.use('/api/login', (req, res, next) => next());
app.use('/api/check-auth', (req, res, next) => next());
app.use('/api/menu-items', (req, res, next) => next());
app.use('/api/categories', (req, res, next) => next());
app.use('/api/banners', (req, res, next) => next());
app.use('/api/breakfasts', (req, res, next) => next());
app.use('/api/promotions', (req, res, next) => next());

// Apply auth middleware to protected routes
app.use('/api', authMiddleware);

// Apply admin middleware to admin-only routes
app.use('/api/analytics-overview', adminMiddleware);
app.use('/api/notifications', adminMiddleware);
app.use('/api/users', adminMiddleware);
app.use('/api/tables', adminMiddleware);
app.use('/api/orders', adminMiddleware);
app.use('/api/reservations', adminMiddleware);

// Route imports
const authRoutes = require('./routes/authRoutes');
const menuRoutes = require('./routes/menuRoutes');
const orderRoutes = require('./routes/orderRoutes')(io);
const reservationRoutes = require('./routes/reservationRoutes')(io);
const promotionRoutes = require('./routes/promotionRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const bannerRoutes = require('./routes/bannerRoutes');
const breakfastRoutes = require('./routes/breakfastRoutes');

app.use('/api', authRoutes);
app.use('/api', menuRoutes);
app.use('/api', orderRoutes);
app.use('/api', reservationRoutes);
app.use('/api', promotionRoutes);
app.use('/api', analyticsRoutes);
app.use('/api', notificationRoutes);
app.use('/api', bannerRoutes);
app.use('/api', breakfastRoutes);

app.use('/api', (req, res, next) => {
  if (
    req.method === 'POST' ||
    req.method === 'PUT' ||
    req.method === 'DELETE' ||
    (req.method === 'GET' && (
      req.path.includes('/menu-items') ||
      req.path.includes('/categories') ||
      req.path.includes('/ratings') ||
      req.path.includes('/tables') ||
      req.path.includes('/notifications') ||
      req.path.includes('/banners') ||
      req.path.includes('/breakfasts')
    ))
  ) {
    if (req.path.includes('/menu-items') || req.path.includes('/categories') || req.path.includes('/banners') || req.path.includes('/breakfasts')) {
      if (req.headers['content-type']?.includes('multipart/form-data')) {
        return next();
      }
    }
    return validate(req, res, next);
  }
  next();
});

function logRoutes() {
  app._router?.stack?.forEach((layer) => {
    if (layer.route) {
      logger.info('Registered route', {
        method: layer.route.stack[0].method.toUpperCase(),
        path: layer.route.path,
      });
    } else if (layer.name === 'router' && layer.handle.stack) {
      const prefix = layer.regexp.source
        .replace(/\\\//g, '/')
        .replace(/^\/\^/, '')
        .replace(/\/\?\(\?=\/\|\$\)/, '');
      layer.handle.stack.forEach((handler) => {
        if (handler.route) {
          logger.info('Registered route', {
            method: handler.route.stack[0].method.toUpperCase(),
            path: prefix + handler.route.path,
          });
        }
      });
    }
  });
}

logRoutes();

app.use((err, req, res, next) => {
  logger.error('Server error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
    user: req.session.user ? req.session.user.id : 'anonymous',
    origin: req.headers.origin,
  });
  res.status(500).json({ error: err.message || 'Internal server error' });
});

app.use((req, res) => {
  logger.warn('Route not found', {
    method: req.method,
    url: req.url,
    user: req.session.user ? req.session.user.id : 'anonymous',
    origin: req.headers.origin,
  });
  res.status(404).json({ error: 'Not found' });
});

io.on('connection', (socket) => {
  logger.info('New socket connection', { id: socket.id });

  socket.on('join-session', async (sessionId) => {
    socket.join(sessionId);
    logger.info('Socket joined session room', { socketId: socket.id, sessionId });

    try {
      const [sessionData] = await db.query('SELECT data FROM sessions WHERE session_id = ?', [sessionId]);
      if (sessionData.length > 0) {
        const session = JSON.parse(sessionData[0].data);
        if (session.user && ['admin', 'server'].includes(session.user.role)) {
          socket.join('staff-notifications');
          logger.info('Socket joined staff-notifications room', { socketId: socket.id, sessionId, role: session.user.role });
        }
      }
    } catch (error) {
      logger.error('Error checking session for staff role', { error: error.message, sessionId });
    }
  });

  socket.on('disconnect', () => {
    logger.info('Socket disconnected', { socketId: socket.id });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', async () => {
  try {
    await db.getConnection();
    logger.info(`Server running on port ${PORT}`);
  } catch (error) {
    logger.error('Failed to connect to database', { error: error.message, stack: error.stack });
    process.exit(1);
  }
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason.message || reason, promise, stack: (reason.stack || '').toString() });
});
