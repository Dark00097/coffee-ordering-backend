const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', 'public', 'Uploads'));
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
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

const logFormData = (req, res, next) => {
  if (req.headers['content-type']?.includes('multipart/form-data')) {
    logger.info('Raw FormData request', {
      headers: req.headers,
      method: req.method,
      url: req.url,
    });
  }
  next();
};

// Create breakfast
router.post('/breakfasts', logFormData, upload, async (req, res) => {
  const { user_id, name, description, price, availability, category_id } = req.body;
  const image = req.file;
  logger.info('Parsed breakfast creation request', {
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add breakfast', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const parsedPrice = parseFloat(price);
    const parsedAvailability = availability === 'true' || availability === true;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    if (!name || !name.trim()) {
      logger.warn('Missing name', { user_id });
      return res.status(400).json({ error: 'Name is required' });
    }
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      logger.warn('Invalid price', { price });
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    if (parsedCategoryId && (isNaN(parsedCategoryId) || parsedCategoryId <= 0)) {
      logger.warn('Invalid category ID', { category_id });
      return res.status(400).json({ error: 'Valid category ID is required' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const [result] = await db.query(
      'INSERT INTO breakfasts (name, description, price, image_url, availability, category_id) VALUES (?, ?, ?, ?, ?, ?)',
      [name.trim(), description || null, parsedPrice, image_url, parsedAvailability, parsedCategoryId]
    );
    logger.info('Breakfast created', { id: result.insertId, name, image_url, category_id: parsedCategoryId });
    res.status(201).json({ message: 'Breakfast created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating breakfast', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to create breakfast' });
  }
});

// Update breakfast
router.put('/breakfasts/:id', logFormData, upload, async (req, res) => {
  const { user_id, name, description, price, availability, category_id } = req.body;
  const image = req.file;
  const { id } = req.params;
  logger.info('Parsed breakfast update request', {
    params: { id },
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update breakfast', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(id);
    const parsedPrice = parseFloat(price);
    const parsedAvailability = availability === 'true' || availability === true;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (!name || !name.trim()) {
      logger.warn('Missing name', { user_id });
      return res.status(400).json({ error: 'Name is required' });
    }
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      logger.warn('Invalid price', { price });
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    if (parsedCategoryId && (isNaN(parsedCategoryId) || parsedCategoryId <= 0)) {
      logger.warn('Invalid category ID', { category_id });
      return res.status(400).json({ error: 'Valid category ID is required' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const updateFields = [name.trim(), description || null, parsedPrice, parsedAvailability, parsedCategoryId];
    let query = 'UPDATE breakfasts SET name = ?, description = ?, price = ?, availability = ?, category_id = ?';
    if (image_url) {
      query += ', image_url = ?';
      updateFields.push(image_url);
    }
    updateFields.push(breakfastId);
    const [result] = await db.query(query + ' WHERE id = ?', updateFields);
    if (result.affectedRows === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    logger.info('Breakfast updated', { id: breakfastId, name, image_url, category_id: parsedCategoryId });
    res.json({ message: 'Breakfast updated' });
  } catch (error) {
    logger.error('Error updating breakfast', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to update breakfast' });
  }
});

// Delete breakfast
router.delete('/breakfasts/:id', async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete breakfast', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [result] = await db.query('DELETE FROM breakfasts WHERE id = ?', [breakfastId]);
    if (result.affectedRows === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    logger.info('Breakfast deleted', { id: breakfastId });
    res.json({ message: 'Breakfast deleted' });
  } catch (error) {
    logger.error('Error deleting breakfast', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete breakfast' });
  }
});

// Fetch all breakfasts
router.get('/breakfasts', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, description, price, image_url, availability, category_id FROM breakfasts');
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching breakfasts', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch breakfasts' });
  }
});

// Fetch single breakfast
router.get('/breakfasts/:id', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, name, description, price, image_url, availability, category_id FROM breakfasts WHERE id = ?',
      [req.params.id]
    );
    if (rows.length === 0) {
      logger.warn('Breakfast not found', { id: req.params.id });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    logger.error('Error fetching breakfast', { error: error.message, id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch breakfast' });
  }
});

// Create option group
router.post('/breakfasts/:id/option-groups', async (req, res) => {
  const { user_id, title } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add option group', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (!title || !title.trim()) {
      logger.warn('Missing title', { user_id });
      return res.status(400).json({ error: 'Title is required' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [existingGroup] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ? AND title = ?', [breakfastId, title.trim()]);
    if (existingGroup.length > 0) {
      logger.warn('Duplicate option group title', { title, breakfast_id: breakfastId });
      return res.status(400).json({ error: 'Option group title already exists for this breakfast' });
    }
    const [result] = await db.query(
      'INSERT INTO breakfast_option_groups (breakfast_id, title) VALUES (?, ?)',
      [breakfastId, title.trim()]
    );
    logger.info('Option group created', { id: result.insertId, breakfast_id: breakfastId, title });
    res.status(201).json({ message: 'Option group created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating option group', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to create option group' });
  }
});

// Update option group
router.put('/breakfasts/:breakfastId/option-groups/:groupId', async (req, res) => {
  const { user_id, title } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update option group', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const groupId = parseInt(req.params.groupId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(groupId) || groupId <= 0) {
      logger.warn('Invalid group ID', { id: req.params.groupId });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!title || !title.trim()) {
      logger.warn('Missing title', { user_id });
      return res.status(400).json({ error: 'Title is required' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [groupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: groupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [existingGroup] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ? AND title = ? AND id != ?', [breakfastId, title.trim(), groupId]);
    if (existingGroup.length > 0) {
      logger.warn('Duplicate option group title', { title, breakfast_id: breakfastId });
      return res.status(400).json({ error: 'Option group title already exists for this breakfast' });
    }
    const [result] = await db.query(
      'UPDATE breakfast_option_groups SET title = ? WHERE id = ?',
      [title.trim(), groupId]
    );
    logger.info('Option group updated', { id: groupId, breakfast_id: breakfastId, title });
    res.json({ message: 'Option group updated' });
  } catch (error) {
    logger.error('Error updating option group', { error: error.message, breakfast_id: req.params.breakfastId, group_id: req.params.groupId });
    res.status(500).json({ error: 'Failed to update option group' });
  }
});

// Delete option group
router.delete('/breakfasts/:breakfastId/option-groups/:groupId', async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete option group', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const groupId = parseInt(req.params.groupId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(groupId) || groupId <= 0) {
      logger.warn('Invalid group ID', { id: req.params.groupId });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [result] = await db.query(
      'DELETE FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?',
      [groupId, breakfastId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Option group not found', { id: groupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    logger.info('Option group deleted', { id: groupId, breakfast_id: breakfastId });
    res.json({ message: 'Option group deleted' });
  } catch (error) {
    logger.error('Error deleting option group', { error: error.message, breakfast_id: req.params.breakfastId, group_id: req.params.groupId });
    res.status(500).json({ error: 'Failed to delete option group' });
  }
});

// Fetch option groups
router.get('/breakfasts/:id/option-groups', async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [rows] = await db.query(
      'SELECT id, title FROM breakfast_option_groups WHERE breakfast_id = ?',
      [breakfastId]
    );
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching option groups', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch option groups' });
  }
});

// Create breakfast option
router.post('/breakfasts/:id/options', async (req, res) => {
  const { user_id, group_id, option_type, option_name, additional_price } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add breakfast option', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.id);
    const parsedGroupId = parseInt(group_id);
    const parsedAdditionalPrice = additional_price ? parseFloat(additional_price) : 0;
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(parsedGroupId) || parsedGroupId <= 0) {
      logger.warn('Invalid group ID', { group_id });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!option_type || !option_name) {
      logger.warn('Missing required fields', { fields: { option_type, option_name } });
      return res.status(400).json({ error: 'Option type and name are required' });
    }
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [parsedGroupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: parsedGroupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [result] = await db.query(
      'INSERT INTO breakfast_options (breakfast_id, group_id, option_type, option_name, additional_price) VALUES (?, ?, ?, ?, ?)',
      [breakfastId, parsedGroupId, option_type, option_name, parsedAdditionalPrice]
    );
    logger.info('Breakfast option created', { id: result.insertId, breakfast_id: breakfastId, group_id: parsedGroupId });
    res.status(201).json({ message: 'Breakfast option created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating breakfast option', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to create breakfast option' });
  }
});

// Update breakfast option
router.put('/breakfasts/:breakfastId/options/:optionId', async (req, res) => {
  const { user_id, group_id, option_type, option_name, additional_price } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update breakfast option', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const optionId = parseInt(req.params.optionId);
    const parsedGroupId = parseInt(group_id);
    const parsedAdditionalPrice = additional_price ? parseFloat(additional_price) : 0;
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(optionId) || optionId <= 0) {
      logger.warn('Invalid option ID', { id: req.params.optionId });
      return res.status(400).json({ error: 'Valid option ID is required' });
    }
    if (isNaN(parsedGroupId) || parsedGroupId <= 0) {
      logger.warn('Invalid group ID', { group_id });
      return res.status(400).json({ error: 'Valid group ID is required' });
    }
    if (!option_type || !option_name) {
      logger.warn('Missing required fields', { fields: { option_type, option_name } });
      return res.status(400).json({ error: 'Option type and name are required' });
    }
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [breakfast] = await db.query('SELECT id FROM breakfasts WHERE id = ?', [breakfastId]);
    if (breakfast.length === 0) {
      logger.warn('Breakfast not found', { id: breakfastId });
      return res.status(404).json({ error: 'Breakfast not found' });
    }
    const [group] = await db.query('SELECT id FROM breakfast_option_groups WHERE id = ? AND breakfast_id = ?', [parsedGroupId, breakfastId]);
    if (group.length === 0) {
      logger.warn('Option group not found', { id: parsedGroupId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Option group not found' });
    }
    const [option] = await db.query('SELECT id FROM breakfast_options WHERE id = ? AND breakfast_id = ?', [optionId, breakfastId]);
    if (option.length === 0) {
      logger.warn('Breakfast option not found', { id: optionId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Breakfast option not found' });
    }
    const [result] = await db.query(
      'UPDATE breakfast_options SET group_id = ?, option_type = ?, option_name = ?, additional_price = ? WHERE id = ?',
      [parsedGroupId, option_type, option_name, parsedAdditionalPrice, optionId]
    );
    logger.info('Breakfast option updated', { id: optionId, breakfast_id: breakfastId, group_id: parsedGroupId });
    res.json({ message: 'Breakfast option updated' });
  } catch (error) {
    logger.error('Error updating breakfast option', { error: error.message, breakfast_id: req.params.breakfastId, option_id: req.params.optionId });
    res.status(500).json({ error: 'Failed to update breakfast option' });
  }
});

// Delete breakfast option
router.delete('/breakfasts/:breakfastId/options/:optionId', async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete breakfast option', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const breakfastId = parseInt(req.params.breakfastId);
    const optionId = parseInt(req.params.optionId);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.breakfastId });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    if (isNaN(optionId) || optionId <= 0) {
      logger.warn('Invalid option ID', { id: req.params.optionId });
      return res.status(400).json({ error: 'Valid option ID is required' });
    }
    const [result] = await db.query(
      'DELETE FROM breakfast_options WHERE id = ? AND breakfast_id = ?',
      [optionId, breakfastId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Breakfast option not found', { id: optionId, breakfast_id: breakfastId });
      return res.status(404).json({ error: 'Breakfast option not found' });
    }
    logger.info('Breakfast option deleted', { id: optionId, breakfast_id: breakfastId });
    res.json({ message: 'Breakfast option deleted' });
  } catch (error) {
    logger.error('Error deleting breakfast option', { error: error.message, breakfast_id: req.params.breakfastId, option_id: req.params.optionId });
    res.status(500).json({ error: 'Failed to delete breakfast option' });
  }
});

// Fetch breakfast options
router.get('/breakfasts/:id/options', async (req, res) => {
  try {
    const breakfastId = parseInt(req.params.id);
    if (isNaN(breakfastId) || breakfastId <= 0) {
      logger.warn('Invalid breakfast ID', { id: req.params.id });
      return res.status(400).json({ error: 'Valid breakfast ID is required' });
    }
    const [rows] = await db.query(
      'SELECT bo.id, bo.group_id, bo.option_type, bo.option_name, bo.additional_price, bog.title as group_title ' +
      'FROM breakfast_options bo ' +
      'JOIN breakfast_option_groups bog ON bo.group_id = bog.id ' +
      'WHERE bo.breakfast_id = ?',
      [breakfastId]
    );
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching breakfast options', { error: error.message, breakfast_id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch breakfast options' });
  }
});

module.exports = router; 