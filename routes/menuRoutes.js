const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const multer = require('multer');
const path = require('path');

// Configure multer for file uploads
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

// Middleware to log raw FormData
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

// Create category
router.post('/categories', logFormData, upload, async (req, res) => {
  const { user_id, name, description, is_top } = req.body;
  const image = req.file;
  logger.info('Parsed category creation request', {
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add category', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!name || !name.trim()) {
      logger.warn('Missing category name', { user_id });
      return res.status(400).json({ error: 'Category name is required' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const parsedIsTop = is_top === 'true' || is_top === true ? 1 : 0;
    const [result] = await db.query(
      'INSERT INTO categories (name, description, image_url, is_top) VALUES (?, ?, ?, ?)',
      [name.trim(), description || null, image_url, parsedIsTop]
    );
    logger.info('Category created', { id: result.insertId, name, image_url, is_top: parsedIsTop });
    res.status(201).json({ message: 'Category created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating category', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to create category' });
  }
});

// Update category
router.put('/categories/:id', logFormData, upload, async (req, res) => {
  const { user_id, name, description, is_top } = req.body;
  const image = req.file;
  const { id } = req.params;
  logger.info('Parsed category update request', {
    params: { id },
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update category', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const categoryId = parseInt(id);
    if (isNaN(categoryId) || categoryId <= 0) {
      logger.warn('Invalid category ID', { id });
      return res.status(400).json({ error: 'Valid category ID is required' });
    }
    if (!name || !name.trim()) {
      logger.warn('Missing category name', { user_id });
      return res.status(400).json({ error: 'Category name is required' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const parsedIsTop = is_top === 'true' || is_top === true ? 1 : 0;
    const updateFields = [name.trim(), description || null, parsedIsTop];
    let query = 'UPDATE categories SET name = ?, description = ?, is_top = ?';
    if (image_url) {
      query += ', image_url = ?';
      updateFields.push(image_url);
    }
    updateFields.push(categoryId);
    const [result] = await db.query(query + ' WHERE id = ?', updateFields);
    if (result.affectedRows === 0) {
      logger.warn('Category not found for update', { id: categoryId });
      return res.status(404).json({ error: 'Category not found' });
    }
    logger.info('Category updated', { id: categoryId, name, image_url, is_top: parsedIsTop });
    res.json({ message: 'Category updated' });
  } catch (error) {
    logger.error('Error updating category', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// Delete category
router.delete('/categories/:id', async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete category', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const categoryId = parseInt(id);
    if (isNaN(categoryId) || categoryId <= 0) {
      logger.warn('Invalid category ID', { id });
      return res.status(400).json({ error: 'Valid category ID is required' });
    }
    const [result] = await db.query('DELETE FROM categories WHERE id = ?', [categoryId]);
    if (result.affectedRows === 0) {
      logger.warn('Category not found for deletion', { id: categoryId });
      return res.status(404).json({ error: 'Category not found' });
    }
    logger.info('Category deleted', { id: categoryId });
    res.json({ message: 'Category deleted' });
  } catch (error) {
    logger.error('Error deleting category', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// Fetch all categories
router.get('/categories', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, image_url, description, is_top FROM categories');
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching categories', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Fetch top categories
router.get('/categories/top', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, image_url, description FROM categories WHERE is_top = 1');
    logger.info('Top categories fetched', { count: rows.length });
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching top categories', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch top categories' });
  }
});

// Fetch single category
router.get('/categories/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, image_url, description, is_top FROM categories WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      logger.warn('Category not found', { id: req.params.id });
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    logger.error('Error fetching category', { error: error.message, id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch category' });
  }
});

// Menu item creation
router.post('/menu-items', logFormData, upload, async (req, res) => {
  const { user_id, name, description, regular_price, sale_price, category_id, availability, dietary_tags } = req.body;
  const image = req.file;
  logger.info('Parsed menu item creation request', {
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add menu item', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const parsedRegularPrice = parseFloat(regular_price);
    const parsedSalePrice = sale_price ? parseFloat(sale_price) : null;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    const parsedAvailability = availability === 'true' || availability === true;
    let parsedDietaryTags = [];
    if (dietary_tags) {
      try {
        parsedDietaryTags = Array.isArray(dietary_tags)
          ? dietary_tags
          : JSON.parse(dietary_tags);
        if (!Array.isArray(parsedDietaryTags)) {
          throw new Error('Dietary tags must be an array');
        }
      } catch (error) {
        parsedDietaryTags = dietary_tags.split(',').map(tag => tag.trim()).filter(tag => tag);
      }
    }
    if (!name || !name.trim()) {
      logger.warn('Missing name', { user_id });
      return res.status(400).json({ error: 'Name is required' });
    }
    if (isNaN(parsedRegularPrice) || parsedRegularPrice <= 0) {
      logger.warn('Invalid regular price', { regular_price });
      return res.status(400).json({ error: 'Regular price must be a positive number' });
    }
    if (parsedSalePrice !== null && (isNaN(parsedSalePrice) || parsedSalePrice < 0)) {
      logger.warn('Invalid sale price', { sale_price });
      return res.status(400).json({ error: 'Sale price must be a non-negative number' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const [result] = await db.query(
      'INSERT INTO menu_items (name, description, regular_price, sale_price, category_id, image_url, availability, dietary_tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name.trim(), description || null, parsedRegularPrice, parsedSalePrice, parsedCategoryId, image_url, parsedAvailability, JSON.stringify(parsedDietaryTags)]
    );
    logger.info('Menu item created', { id: result.insertId, name, image_url });
    res.status(201).json({ message: 'Menu item created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating menu item', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to create menu item' });
  }
});

// Menu item update
router.put('/menu-items/:id', logFormData, upload, async (req, res) => {
  const { id } = req.params;
  const { user_id, name, description, regular_price, sale_price, category_id, availability, dietary_tags } = req.body;
  const image = req.file;
  logger.info('Parsed menu item update request', {
    params: { id },
    body: req.body,
    file: image ? { name: image.filename, path: image.path } : null,
  });
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update menu item', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const itemId = parseInt(id);
    const parsedRegularPrice = parseFloat(regular_price);
    const parsedSalePrice = sale_price ? parseFloat(sale_price) : null;
    const parsedCategoryId = category_id ? parseInt(category_id) : null;
    const parsedAvailability = availability === 'true' || availability === true;
    let parsedDietaryTags = [];
    if (dietary_tags) {
      try {
        parsedDietaryTags = Array.isArray(dietary_tags)
          ? dietary_tags
          : JSON.parse(dietary_tags);
        if (!Array.isArray(parsedDietaryTags)) {
          throw new Error('Dietary tags must be an array');
        }
      } catch (error) {
        parsedDietaryTags = dietary_tags.split(',').map(tag => tag.trim()).filter(tag => tag);
      }
    }
    if (isNaN(itemId) || itemId <= 0) {
      logger.warn('Invalid item ID', { id });
      return res.status(400).json({ error: 'Valid item ID is required' });
    }
    if (!name || !name.trim()) {
      logger.warn('Missing name', { user_id });
      return res.status(400).json({ error: 'Name is required' });
    }
    if (isNaN(parsedRegularPrice) || parsedRegularPrice <= 0) {
      logger.warn('Invalid regular price', { regular_price });
      return res.status(400).json({ error: 'Regular price must be a positive number' });
    }
    if (parsedSalePrice !== null && (isNaN(parsedSalePrice) || parsedSalePrice < 0)) {
      logger.warn('Invalid sale price', { sale_price });
      return res.status(400).json({ error: 'Sale price must be a non-negative number' });
    }
    const image_url = image ? `/Uploads/${image.filename}` : null;
    const [existing] = await db.query('SELECT id FROM menu_items WHERE id = ?', [itemId]);
    if (existing.length === 0) {
      logger.warn('Menu item not found', { id: itemId });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const updateFields = [
      name.trim(),
      description || null,
      parsedRegularPrice,
      parsedSalePrice,
      parsedCategoryId,
      parsedAvailability,
      JSON.stringify(parsedDietaryTags),
    ];
    let query = 'UPDATE menu_items SET name = ?, description = ?, regular_price = ?, sale_price = ?, category_id = ?, availability = ?, dietary_tags = ?';
    if (image_url) {
      query += ', image_url = ?';
      updateFields.push(image_url);
    }
    updateFields.push(itemId);
    const [result] = await db.query(query + ' WHERE id = ?', updateFields);
    if (result.affectedRows === 0) {
      logger.warn('No rows updated', { id: itemId });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    logger.info('Menu item updated', { id: itemId, name, image_url });
    res.json({ message: 'Menu item updated' });
  } catch (error) {
    logger.error('Error updating menu item', { error: error.message, body: req.body });
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Menu item deletion
router.delete('/menu-items/:id', async (req, res) => {
  const { user_id } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete menu item', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const itemId = parseInt(id);
    if (isNaN(itemId) || itemId <= 0) {
      logger.warn('Invalid item ID', { id });
      return res.status(400).json({ error: 'Valid item ID is required' });
    }
    const [existing] = await db.query('SELECT id FROM menu_items WHERE id = ?', [itemId]);
    if (existing.length === 0) {
      logger.warn('Menu item not found', { id: itemId });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [result] = await db.query('DELETE FROM menu_items WHERE id = ?', [itemId]);
    if (result.affectedRows === 0) {
      logger.warn('No rows deleted', { id: itemId });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    logger.info('Menu item deleted', { id: itemId });
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    logger.error('Error deleting menu item', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Menu item availability update
router.put('/menu-items/:id/availability', async (req, res) => {
  const { user_id, availability } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update availability', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const itemId = parseInt(id);
    if (isNaN(itemId) || itemId <= 0) {
      logger.warn('Invalid item ID', { id });
      return res.status(400).json({ error: 'Valid item ID is required' });
    }
    const parsedAvailability = availability === 'true' || availability === true;
    await db.query('UPDATE menu_items SET availability = ? WHERE id = ?', [parsedAvailability, itemId]);
    logger.info('Menu item availability updated', { itemId, availability: parsedAvailability });
    res.json({ message: 'Availability updated' });
  } catch (error) {
    logger.error('Error updating availability', { error: error.message });
    res.status(500).json({ error: 'Failed to update availability' });
  }
});

// Search menu items
router.get('/menu-items/search', async (req, res) => {
  try {
    const { query } = req.query;
    if (!query || !query.trim()) {
      return res.json([]); // Return empty array for empty query
    }
    const searchTerm = `%${query.trim()}%`;
    const [rows] = await db.query(
      `SELECT mi.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM menu_items mi
       LEFT JOIN categories c ON mi.category_id = c.id
       LEFT JOIN ratings r ON mi.id = r.item_id
       WHERE mi.name LIKE ? OR mi.description LIKE ?
       GROUP BY mi.id`,
      [searchTerm, searchTerm]
    );
    const sanitizedRows = rows.map(item => ({
      ...item,
      dietary_tags: item.dietary_tags && typeof item.dietary_tags === 'string' && item.dietary_tags.match(/^\[.*\]$/)
        ? item.dietary_tags
        : '[]',
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    logger.info('Menu items searched', { query, count: rows.length });
    res.json(sanitizedRows);
  } catch (error) {
    logger.error('Error searching menu items', { error: error.message, query: req.query.query });
    res.status(500).json({ error: 'Failed to search menu items' });
  }
});

// Fetch single menu item
router.get('/menu-items/:id', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT mi.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM menu_items mi 
       LEFT JOIN categories c ON mi.category_id = c.id
       LEFT JOIN ratings r ON mi.id = r.item_id 
       WHERE mi.id = ?
       GROUP BY mi.id`,
      [req.params.id]
    );
    if (rows.length === 0) {
      logger.warn('Product not found', { id: req.params.id });
      return res.status(404).json({ error: 'Product not found' });
    }
    const product = rows[0];
    product.dietary_tags = product.dietary_tags && typeof product.dietary_tags === 'string' && product.dietary_tags.match(/^\[.*\]$/)
      ? product.dietary_tags
      : '[]';
    product.average_rating = parseFloat(product.average_rating).toFixed(1);
    product.review_count = parseInt(product.review_count);
    res.json(product);
  } catch (error) {
    logger.error('Error fetching product details', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch product details' });
  }
});

// Fetch all menu items
router.get('/menu-items', async (req, res) => {
  try {
    const { category_id } = req.query;
    let query = `
      SELECT mi.*, c.name AS category_name,
             COALESCE(AVG(r.rating), 0) AS average_rating,
             COUNT(r.id) AS review_count
      FROM menu_items mi
      LEFT JOIN categories c ON mi.category_id = c.id
      LEFT JOIN ratings r ON mi.id = r.item_id
    `;
    const params = [];
    if (category_id) {
      query += ' WHERE mi.category_id = ?';
      params.push(category_id);
    }
    query += ' GROUP BY mi.id';
    const [rows] = await db.query(query, params);
    const sanitizedRows = rows.map(item => ({
      ...item,
      dietary_tags: item.dietary_tags && typeof item.dietary_tags === 'string' && item.dietary_tags.match(/^\[.*\]$/)
        ? item.dietary_tags
        : '[]',
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    res.json(sanitizedRows);
  } catch (error) {
    logger.error('Error fetching menu items', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Fetch related menu items
router.get('/menu-items/:id/related', async (req, res) => {
  try {
    const [product] = await db.query(
      'SELECT category_id FROM menu_items WHERE id = ?',
      [req.params.id]
    );
    if (!product.length) {
      return res.status(404).json({ error: 'Product not found' });
    }
    const [rows] = await db.query(
      `SELECT mi.*, c.name AS category_name,
              COALESCE(AVG(r.rating), 0) AS average_rating,
              COUNT(r.id) AS review_count
       FROM menu_items mi 
       LEFT JOIN categories c ON mi.category_id = c.id
       LEFT JOIN ratings r ON mi.id = r.item_id 
       WHERE mi.category_id = ? AND mi.id != ?
       GROUP BY mi.id
       LIMIT 4`,
      [product[0].category_id, req.params.id]
    );
    const sanitizedRows = rows.map(item => ({
      ...item,
      dietary_tags: item.dietary_tags && typeof item.dietary_tags === 'string' && item.dietary_tags.match(/^\[.*\]$/)
        ? item.dietary_tags
        : '[]',
      average_rating: parseFloat(item.average_rating).toFixed(1),
      review_count: parseInt(item.review_count),
    }));
    res.json(sanitizedRows);
  } catch (error) {
    logger.error('Error fetching related products', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch related products' });
  }
});

// Create supplement
router.post('/supplements', async (req, res) => {
  const { name, price } = req.body;
  const user_id = req.session.user?.id;
  try {
    if (!user_id || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to add supplement', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!name || !price) {
      logger.warn('Missing required fields', { fields: { name, price } });
      return res.status(400).json({ error: 'Name and price are required' });
    }
    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      logger.warn('Invalid price', { price });
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    const [result] = await db.query(
      'INSERT INTO supplements (name, price) VALUES (?, ?)',
      [name, parsedPrice]
    );
    logger.info('Supplement created', { id: result.insertId, name });
    res.status(201).json({ message: 'Supplement created', id: result.insertId });
  } catch (error) {
    logger.error('Error creating supplement', { error: error.message, name, price });
    res.status(500).json({ error: 'Failed to create supplement' });
  }
});

// Update supplement
router.put('/supplements/:id', async (req, res) => {
  const { user_id, name, price } = req.body;
  const { id } = req.params;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update supplement', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const supplementId = parseInt(id);
    if (isNaN(supplementId) || supplementId <= 0) {
      logger.warn('Invalid supplement ID', { id });
      return res.status(400).json({ error: 'Valid supplement ID is required' });
    }
    if (!name || !name.trim()) {
      logger.warn('Missing name', { user_id });
      return res.status(400).json({ error: 'Name is required' });
    }
    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      logger.warn('Invalid price', { price });
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    const [existing] = await db.query('SELECT id FROM supplements WHERE id = ?', [supplementId]);
    if (existing.length === 0) {
      logger.warn('Supplement not found', { id: supplementId });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    const [result] = await db.query(
      'UPDATE supplements SET name = ?, price = ? WHERE id = ?',
      [name.trim(), parsedPrice, supplementId]
    );
    if (result.affectedRows === 0) {
      logger.warn('No rows updated', { id: supplementId });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    logger.info('Supplement updated', { id: supplementId, name });
    res.json({ message: 'Supplement updated' });
  } catch (error) {
    logger.error('Error updating supplement', { error: error.message, id });
    res.status(500).json({ error: 'Failed to update supplement' });
  }
});

// Delete supplement
router.delete('/supplements/:id', async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete supplement', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const [result] = await db.query('DELETE FROM supplements WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      logger.warn('Supplement not found', { id: req.params.id });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    logger.info('Supplement deleted', { id: req.params.id });
    res.json({ message: 'Supplement deleted' });
  } catch (error) {
    logger.error('Error deleting supplement', { error: error.message, id });
    res.status(500).json({ error: 'Failed to delete supplement' });
  }
});

// Assign supplement to menu item
router.post('/menu-items/:id/supplements', async (req, res) => {
  const { supplement_id, additional_price, name } = req.body;
  const user_id = req.session.user?.id;
  try {
    if (!user_id || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to assign supplement', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!supplement_id || !additional_price || !name) {
      logger.warn('Missing required fields', { fields: { supplement_id, additional_price, name } });
      return res.status(400).json({ error: 'Supplement ID, name, and additional price are required' });
    }
    const parsedAdditionalPrice = parseFloat(additional_price);
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [menuItem] = await db.query('SELECT id FROM menu_items WHERE id = ?', [req.params.id]);
    if (menuItem.length === 0) {
      logger.warn('Menu item not found', { id: req.params.id });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [supplement] = await db.query('SELECT id FROM supplements WHERE id = ?', [supplement_id]);
    if (supplement.length === 0) {
      logger.warn('Supplement not found', { supplement_id });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    const [result] = await db.query(
      'INSERT INTO menu_item_supplements (menu_item_id, supplement_id, name, additional_price) VALUES (?, ?, ?, ?)',
      [req.params.id, supplement_id, name, parsedAdditionalPrice]
    );
    logger.info('Supplement assigned to menu item', { id: result.insertId, menu_item_id: req.params.id, supplement_id });
    res.status(201).json({ message: 'Supplement assigned', id: result.insertId });
  } catch (error) {
    logger.error('Error assigning supplement', { error: error.message, menu_item_id: req.params.id, supplement_id });
    res.status(500).json({ error: 'Failed to assign supplement' });
  }
});

// Update supplement assignment
router.put('/menu-items/:menuItemId/supplements/:supplementId', async (req, res) => {
  const { user_id, name, additional_price } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to update supplement assignment', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!name || additional_price === undefined) {
      logger.warn('Missing required fields', { fields: { name, additional_price } });
      return res.status(400).json({ error: 'Name and additional price are required' });
    }
    const parsedAdditionalPrice = parseFloat(additional_price);
    if (isNaN(parsedAdditionalPrice) || parsedAdditionalPrice < 0) {
      logger.warn('Invalid additional price', { additional_price });
      return res.status(400).json({ error: 'Additional price must be a non-negative number' });
    }
    const [menuItem] = await db.query('SELECT id FROM menu_items WHERE id = ?', [req.params.menuItemId]);
    if (menuItem.length === 0) {
      logger.warn('Menu item not found', { id: req.params.menuItemId });
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [supplement] = await db.query('SELECT id FROM supplements WHERE id = ?', [req.params.supplementId]);
    if (supplement.length === 0) {
      logger.warn('Supplement not found', { supplement_id: req.params.supplementId });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    const [result] = await db.query(
      'UPDATE menu_item_supplements SET name = ?, additional_price = ? WHERE menu_item_id = ? AND supplement_id = ?',
      [name, parsedAdditionalPrice, req.params.menuItemId, req.params.supplementId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Supplement assignment not found', { menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
      return res.status(404).json({ error: 'Supplement assignment not found' });
    }
    logger.info('Supplement assignment updated', { menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
    res.json({ message: 'Supplement assignment updated' });
  } catch (error) {
    logger.error('Error updating supplement assignment', { error: error.message, menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
    res.status(500).json({ error: 'Failed to update supplement assignment' });
  }
});

// Delete supplement assignment
router.delete('/menu-items/:menuItemId/supplements/:supplementId', async (req, res) => {
  const { user_id } = req.body;
  try {
    if (!req.session.user || req.session.user.id !== parseInt(user_id) || !await checkAdmin(user_id)) {
      logger.warn('Unauthorized attempt to delete supplement assignment', { user_id, sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const [result] = await db.query(
      'DELETE FROM menu_item_supplements WHERE menu_item_id = ? AND supplement_id = ?',
      [req.params.menuItemId, req.params.supplementId]
    );
    if (result.affectedRows === 0) {
      logger.warn('Supplement assignment not found', { menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
      return res.status(404).json({ error: 'Supplement assignment not found' });
    }
    logger.info('Supplement assignment deleted', { menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
    res.json({ message: 'Supplement assignment deleted' });
  } catch (error) {
    logger.error('Error deleting supplement assignment', { error: error.message, menu_item_id: req.params.menuItemId, supplement_id: req.params.supplementId });
    res.status(500).json({ error: 'Failed to delete supplement assignment' });
  }
});

// Fetch supplements for a menu item
router.get('/menu-items/:id/supplements', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT mis.id, mis.supplement_id, mis.name, mis.additional_price, s.price AS base_price FROM menu_item_supplements mis JOIN supplements s ON mis.supplement_id = s.id WHERE mis.menu_item_id = ?',
      [req.params.id]
    );
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching supplements for menu item', { error: error.message, menu_item_id: req.params.id });
    res.status(500).json({ error: 'Failed to fetch supplements' });
  }
});

// Fetch all supplements
router.get('/supplements', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id, name, price FROM supplements');
    logger.info('Supplements fetched', { count: rows.length });
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching supplements', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch supplements' });
  }
});

// Fetch single supplement
router.get('/supplements/:id', async (req, res) => {
  const { id } = req.params;
  try {
    if (!req.session.user || !await checkAdmin(req.session.user.id)) {
      logger.warn('Unauthorized attempt to fetch supplement', { sessionUser: req.session.user });
      return res.status(403).json({ error: 'Admin access required' });
    }
    const supplementId = parseInt(id);
    if (isNaN(supplementId) || supplementId <= 0) {
      logger.warn('Invalid supplement ID', { id });
      return res.status(400).json({ error: 'Valid supplement ID is required' });
    }
    const [rows] = await db.query('SELECT id, name, price FROM supplements WHERE id = ?', [supplementId]);
    if (rows.length === 0) {
      logger.warn('Supplement not found', { id: supplementId });
      return res.status(404).json({ error: 'Supplement not found' });
    }
    logger.info('Supplement fetched', { id: supplementId });
    res.json(rows[0]);
  } catch (error) {
    logger.error('Error fetching supplement', { error: error.message, id });
    res.status(500).json({ error: 'Failed to fetch supplement' });
  }
});

// Submit rating
router.post('/ratings', [
  require('express-validator').body('item_id').isInt({ min: 1 }).withMessage('Valid item ID is required'),
  require('express-validator').body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
], async (req, res) => {
  const errors = require('express-validator').validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation errors for rating', { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }
  const { item_id, rating } = req.body;
  const sessionId = req.sessionID;
  try {
    const [item] = await db.query('SELECT id FROM menu_items WHERE id = ?', [item_id]);
    if (item.length === 0) {
      logger.warn('Item not found for rating', { item_id });
      return res.status(404).json({ error: 'Item not found' });
    }
    const [existingRating] = await db.query(
      'SELECT id FROM ratings WHERE item_id = ? AND session_id = ?',
      [item_id, sessionId]
    );
    if (existingRating.length > 0) {
      logger.warn('Rating already exists for this item in session', { item_id, sessionId });
      return res.status(400).json({ error: 'You have already rated this item' });
    }
    const [result] = await db.query(
      'INSERT INTO ratings (item_id, rating, session_id, created_at) VALUES (?, ?, ?, NOW())',
      [item_id, rating, sessionId]
    );
    await db.query(
      `UPDATE menu_items
       SET average_rating = (SELECT AVG(rating) FROM ratings WHERE item_id = ?),
           review_count = (SELECT COUNT(*) FROM ratings WHERE item_id = ?)
       WHERE id = ?`,
      [item_id, item_id, item_id]
    );
    res.status(201).json({ message: 'Rating submitted', id: result.insertId });
  } catch (error) {
    logger.error('Error submitting rating', { error: error.message, item_id, rating });
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// Fetch ratings by item
router.get('/ratings', [
  require('express-validator').query('item_id').isInt({ min: 1 }).withMessage('Valid item ID is required'),
], async (req, res) => {
  const errors = require('express-validator').validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Validation errors for fetching ratings', { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }
  const { item_id } = req.query;
  const sessionId = req.sessionID;
  try {
    const [rows] = await db.query(
      'SELECT id, item_id, rating, created_at FROM ratings WHERE item_id = ? AND session_id = ?',
      [item_id, sessionId]
    );
    logger.info('Ratings fetched successfully', { item_id, sessionId, count: rows.length });
    res.json(rows);
  } catch (error) {
    logger.error('Error fetching ratings', { error: error.message, item_id });
    res.status(500).json({ error: 'Failed to fetch ratings' });
  }
});

module.exports = router;