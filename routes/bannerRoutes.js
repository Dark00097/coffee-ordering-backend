// routes/bannerRoutes.js
const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Image must be JPEG or PNG'), false);
    }
  },
}).single('image');

const checkAdmin = async (userId) => {
  if (!userId) return false;
  const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
  return rows.length > 0 && rows[0].role === 'admin';
};

// Create banner
router.post('/banners', upload, async (req, res) => {
  const { user_id, link, is_enabled } = req.body;
  const image = req.file;
  logger.info('Parsed banner creation request', {
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
    sessionUser: req.session.user,
  });
  try {
    if (!req.session.user) {
      logger.warn('No session user found', { user_id });
      return res.status(403).json({ error: 'Admin access required: No session user' });
    }
    if (req.session.user.id !== parseInt(user_id)) {
      logger.warn('User ID mismatch', { user_id, sessionUserId: req.session.user.id });
      return res.status(403).json({ error: 'Admin access required: User ID mismatch' });
    }
    if (!await checkAdmin(user_id)) {
      logger.warn('User is not admin', { user_id, role: req.session.user.role });
      return res.status(403).json({ error: 'Admin access required: Not an admin' });
    }
    if (!link || !link.trim()) {
      logger.warn('Missing banner link', { user_id });
      return res.status(400).json({ error: 'Banner link is required' });
    }
    if (!image) {
      logger.warn('Missing banner image', { user_id });
      return res.status(400).json({ error: 'Banner image is required' });
    }
    const image_url = `/Uploads/${image.filename}`;
    const parsedIsEnabled = is_enabled === 'true' || is_enabled === true;
    const [result] = await db.query(
      'INSERT INTO banners (image_url, link, is_enabled, admin_id) VALUES (?, ?, ?, ?)',
      [image_url, link.trim(), parsedIsEnabled, user_id]
    );
    logger.info('Banner created', { id: result.insertId, link, image_url });
    res.status(201).json({ message: 'Banner created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating banner', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to create banner' });
  }
});

// Update banner
router.put('/banners/:id', upload, async (req, res) => {
  const { user_id, link, is_enabled } = req.body;
  const image = req.file;
  const { id } = req.params;
  logger.info('Parsed banner update request', {
    params: { id },
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
    sessionUser: req.session.user,
  });
  try {
    if (!req.session.user) {
      logger.warn('No session user found', { user_id });
      return res.status(403).json({ error: 'Admin access required: No session user' });
    }
    if (req.session.user.id !== parseInt(user_id)) {
      logger.warn('User ID mismatch', { user_id, sessionUserId: req.session.user.id });
      return res.status(403).json({ error: 'Admin access required: User ID mismatch' });
    }
    if (!await checkAdmin(user_id)) {
      logger.warn('User is not admin', { user_id, role: req.session.user.role });
      return res.status(403).json({ error: 'Admin access required: Not an admin' });
    }
    const bannerId = parseInt(id);
    if (isNaN(bannerId) || bannerId <= 0) {
      logger.warn('Invalid banner ID', { id });
      return res.status(400).json({ error: 'Valid banner ID is required' });
    }
    if (!link || !link.trim()) {
      logger.warn('Missing banner link', { user_id });
      return res.status(400).json({ error: 'Banner link is required' });
    }
    const parsedIsEnabled = is_enabled === 'true' || is_enabled === true;
    const updateFields = [link.trim(), parsedIsEnabled, user_id];
    let query = 'UPDATE banners SET link = ?, is_enabled = ?, admin_id = ?';
    if (image) {
      const image_url = `/Uploads/${image.filename}`;
      query += ', image_url = ?';
      updateFields.push(image_url);
    }
    updateFields.push(bannerId);
    const [result] = await db.query(query + ' WHERE id = ?', updateFields);
    if (result.affectedRows === 0) {
      logger.warn('Banner not found for update', { id: bannerId });
      return res.status(404).json({ error: 'Banner not found' });
    }
    logger.info('Banner updated', { id: bannerId, link });
    res.json({ message: 'Banner updated' });
  } catch (error) {
    logger.error('Error updating banner', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to update banner' });
  }
});

// Delete banner
router.delete('/banners/:id', async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  logger.info('Parsed banner deletion request', { params: { id }, body: req.body, sessionUser: req.session.user });
  try {
    if (!req.session.user) {
      logger.warn('No session user found', { user_id });
      return res.status(403).json({ error: 'Admin access required: No session user' });
    }
    if (req.session.user.id !== parseInt(user_id)) {
      logger.warn('User ID mismatch', { user_id, sessionUserId: req.session.user.id });
      return res.status(403).json({ error: 'Admin access required: User ID mismatch' });
    }
    if (!await checkAdmin(user_id)) {
      logger.warn('User is not admin', { user_id, role: req.session.user.role });
      return res.status(403).json({ error: 'Admin access required: Not an admin' });
    }
    const bannerId = parseInt(id);
    if (isNaN(bannerId) || bannerId <= 0) {
      logger.warn('Invalid banner ID', { id });
      return res.status(400).json({ error: 'Valid banner ID is required' });
    }
    const [result] = await db.query('DELETE FROM banners WHERE id = ?', [bannerId]);
    if (result.affectedRows === 0) {
      logger.warn('Banner not found for deletion', { id: bannerId });
      return res.status(404).json({ error: 'Banner not found' });
    }
    logger.info('Banner deleted', { id: bannerId });
    res.json({ message: 'Banner deleted' });
  } catch (error) {
    logger.error('Error deleting banner', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete banner' });
  }
});

// Fetch all banners (admin only)
router.get('/banners', async (req, res) => {
  const { user_id } = req.query;
  logger.info('Parsed banners fetch request', { query: req.query, sessionUser: req.session.user });
  try {
    if (!req.session.user) {
      logger.warn('No session user found', { user_id });
      return res.status(403).json({ error: 'Admin access required: No session user' });
    }
    if (req.session.user.id !== parseInt(user_id)) {
      logger.warn('User ID mismatch', { user_id, sessionUserId: req.session.user.id });
      return res.status(403).json({ error: 'Admin access required: User ID mismatch' });
    }
    if (!await checkAdmin(user_id)) {
      logger.warn('User is not admin', { user_id, role: req.session.user.role });
      return res.status(403).json({ error: 'Admin access required: Not an admin' });
    }
    const [rows] = await db.query('SELECT id, image_url, link, is_enabled, created_at, updated_at, admin_id FROM banners');
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching banners', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch banners' });
  }
});

// Fetch enabled banners (public)
router.get('/banners/enabled', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, image_url, link FROM banners WHERE is_enabled = 1');
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching enabled banners', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch enabled banners' });
  }
});

module.exports = router;