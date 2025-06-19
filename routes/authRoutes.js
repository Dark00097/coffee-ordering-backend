const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const bcrypt = require('bcrypt');

const checkAdmin = async (userId) => {
  if (!userId) return false;
  const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
  return rows.length > 0 && rows[0].role === 'admin';
};

// Check authentication
router.get('/check-auth', async (req, res) => {
  try {
    if (!req.session.user) {
      logger.info('No session user found', { path: req.path });
      return res.status(401).json({ error: 'Not authenticated' });
    }
    logger.info('Session user found', { user: req.session.user });
    res.json(req.session.user);
  } catch (error) {
    logger.error('Error checking auth', { error: error.message });
    res.status(500).json({ error: 'Failed to check auth' });
  }
});

// User login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  logger.debug('Login attempt', { email });
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      logger.warn('Invalid credentials: User not found', { email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logger.warn('Invalid credentials: Password mismatch', { email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, email: user.email, role: user.role };
    logger.info('User logged in successfully', { userId: user.id, email: user.email, role: user.role });
    res.json({ message: 'Logged in', user: req.session.user });
  } catch (error) {
    logger.error('Error during login', { error: error.message, email });
    res.status(500).json({ error: 'Failed to login' });
  }
});

// User logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Error destroying session', { error: err.message });
      return res.status(500).json({ error: 'Failed to logout' });
    }
    logger.info('User logged out');
    res.json({ message: 'Logged out' });
  });
});

// Create staff
router.post('/staff', async (req, res) => {
  const { user_id, email, password, role } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add staff', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (role !== 'server') {
      logger.warn('Invalid role', { role });
      return res.status(400).json({ error: 'Invalid role' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await db.query('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)', [email, password_hash, role]);
    logger.info('Server added', { id: result.insertId, email });
    res.status(201).json({ message: 'Server added', id: result.insertId });
  } catch (error) {
    logger.error('Error adding staff', { error: error.message });
    res.status(500).json({ error: 'Failed to add staff' });
  }
});

// Update staff
router.put('/users/:id', async (req, res) => {
  const { user_id, email, password, role } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update user', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const userId = parseInt(id);
    if (isNaN(userId) || userId <= 0) {
      logger.warn('Invalid user ID', { id });
      return res.status(400).json({ error: 'Valid user ID is required' });
    }
    if (role !== 'server' && role !== 'admin') {
      logger.warn('Invalid role', { role });
      return res.status(400).json({ error: 'Invalid role' });
    }
    const [existing] = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
    if (existing.length === 0) {
      logger.warn('User not found', { id: userId });
      return res.status(404).json({ error: 'User not found' });
    }
    const updates = [];
    const values = [];
    if (email) {
      updates.push('email = ?');
      values.push(email);
    }
    if (password) {
      const password_hash = await bcrypt.hash(password, 10);
      updates.push('password_hash = ?');
      values.push(password_hash);
    }
    if (role) {
      updates.push('role = ?');
      values.push(role);
    }
    if (updates.length === 0) {
      logger.warn('No fields to update', { id: userId });
      return res.status(400).json({ error: 'No fields to update' });
    }
    values.push(userId);
    const [result] = await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values);
    if (result.affectedRows === 0) {
      logger.warn('No rows updated', { id: userId });
      return res.status(404).json({ error: 'User not found' });
    }
    logger.info('User updated', { id: userId, email });
    res.json({ message: 'User updated' });
  } catch (error) {
    logger.error('Error updating user', { error: error.message });
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete staff
router.delete('/users/:id', async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete user', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const userId = parseInt(id);
    if (isNaN(userId) || userId <= 0) {
      logger.warn('Invalid user ID', { id });
      return res.status(400).json({ error: 'Valid user ID is required' });
    }
    const [existing] = await db.query('SELECT id FROM users WHERE id = ?', [userId]);
    if (existing.length === 0) {
      logger.warn('User not found', { id: userId });
      return res.status(404).json({ error: 'User not found' });
    }
    const [result] = await db.query('DELETE FROM users WHERE id = ?', [userId]);
    if (result.affectedRows === 0) {
      logger.warn('No rows deleted', { id: userId });
      return res.status(404).json({ error: 'User not found' });
    }
    logger.info('User deleted', { id: userId });
    res.json({ message: 'User deleted' });
  } catch (error) {
    logger.error('Error deleting user', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Fetch all users
router.get('/users', async (req, res) => {
  try {
    if (!req.session.user || !await checkAdmin(req.session.user.id)) {
      logger.warn('Unauthorized attempt to fetch users', { sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const [rows] = await db.query('SELECT id, email, role, created_at FROM users');
    logger.info('Users fetched successfully', { count: rows.length });
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching users', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Fetch single user
router.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    if (!req.session.user || !await checkAdmin(req.session.user.id)) {
      logger.warn('Unauthorized attempt to fetch user', { sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const userId = parseInt(id);
    if (isNaN(userId) || userId <= 0) {
      logger.warn('Invalid user ID', { id });
      return res.status(400).json({ error: 'Valid user ID is required' });
    }
    const [rows] = await db.query('SELECT id, email, role, created_at FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) {
      logger.warn('User not found', { id: userId });
      return res.status(404).json({ error: 'User not found' });
    }
    logger.info('User fetched', { id: userId });
    res.json(rows[0]);
  } catch (error) {
    logger.error('Error fetching user', { error: error.message, id });
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

module.exports = router;