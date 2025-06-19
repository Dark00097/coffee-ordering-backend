const express = require('express');
const router = express.Router();
const db = require('../config/db');
const logger = require('../logger');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const recentRequests = new Map();

const checkAdminOrServer = async (userId) => {
  if (!userId) return false;
  const [rows] = await db.query('SELECT role FROM users WHERE id = ?', [userId]);
  return rows.length > 0 && ['admin', 'server'].includes(rows[0].role);
};

module.exports = (io) => {
  router.post('/orders', async (req, res) => {
    const { items, breakfastItems, total_price, order_type, delivery_address, promotion_id, table_id, request_id } = req.body;
    const sessionID = req.headers['x-session-id'] || req.sessionID;
    const timestamp = new Date().toISOString();

    logger.info('Received order request', {
      raw_body: req.body,
      items: items?.length || 0,
      breakfastItems: breakfastItems?.length || 0,
      request_id,
      table_id,
      supplements: items?.map(i => ({ item_id: i.item_id, supplement_id: i.supplement_id })) || [],
      sessionID,
      timestamp,
    });

    try {
      if (!request_id || typeof request_id !== 'string' || !request_id.match(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)) {
        logger.warn('Invalid or missing request_id', { request_id, sessionID, timestamp });
        return res.status(400).json({ error: 'Valid request_id is required' });
      }

      const orderHash = crypto
        .createHash('sha256')
        .update(JSON.stringify({ items, breakfastItems, table_id, order_type, total_price, request_id }))
        .digest('hex');
      if (recentRequests.has(orderHash)) {
        logger.warn('Duplicate order submission detected', { request_id, orderHash, sessionID, timestamp });
        return res.status(429).json({ error: 'Duplicate order detected. Please wait a moment.' });
      }
      recentRequests.set(orderHash, timestamp);
      setTimeout(() => recentRequests.delete(orderHash), 15000);

      if ((!items || !Array.isArray(items) || items.length === 0) && (!breakfastItems || !Array.isArray(breakfastItems) || breakfastItems.length === 0)) {
        logger.warn('Invalid or empty items', { sessionID, timestamp });
        return res.status(400).json({ error: 'Items or breakfast items array is required and non-empty' });
      }
      if (!order_type || !['local', 'delivery'].includes(order_type)) {
        logger.warn('Invalid order_type', { order_type, sessionID, timestamp });
        return res.status(400).json({ error: 'Invalid order type' });
      }
      if (order_type === 'local' && (!table_id || isNaN(parseInt(table_id)))) {
        logger.warn('Invalid table_id', { table_id, sessionID, timestamp });
        return res.status(400).json({ error: 'Table ID required for local orders' });
      }
      if (order_type === 'delivery' && (!delivery_address || !delivery_address.trim())) {
        logger.warn('Missing delivery address', { sessionID, timestamp });
        return res.status(400).json({ error: 'Delivery address required' });
      }

      let calculatedTotal = 0;

      if (items && Array.isArray(items)) {
        for (const item of items) {
          const { item_id, quantity, unit_price, supplement_id } = item;
          if (!item_id || isNaN(item_id) || item_id <= 0) {
            logger.warn('Invalid item_id', { item_id, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid item_id: ${item_id}` });
          }
          if (!quantity || isNaN(quantity) || quantity <= 0) {
            logger.warn('Invalid quantity', { item_id, quantity, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid quantity for item ${item_id}` });
          }
          if (!unit_price || isNaN(parseFloat(unit_price)) || parseFloat(unit_price) <= 0) {
            logger.warn('Invalid unit_price', { item_id, unit_price, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid unit_price for item ${item_id}` });
          }

          const [menuItem] = await db.query('SELECT availability, regular_price, sale_price FROM menu_items WHERE id = ?', [item_id]);
          if (menuItem.length === 0 || !menuItem[0].availability) {
            logger.warn('Item unavailable', { item_id, sessionID, timestamp });
            return res.status(400).json({ error: `Item ${item_id} is unavailable` });
          }
          let expectedPrice = menuItem[0].sale_price !== null ? parseFloat(menuItem[0].sale_price) : parseFloat(menuItem[0].regular_price);
          let itemTotal = expectedPrice;

          if (supplement_id) {
            const [supplement] = await db.query(
              'SELECT additional_price FROM menu_item_supplements WHERE menu_item_id = ? AND supplement_id = ?',
              [item_id, supplement_id]
            );
            if (supplement.length === 0) {
              logger.warn('Invalid supplement', { item_id, supplement_id, sessionID, timestamp });
              return res.status(400).json({ error: `Invalid supplement ID ${supplement_id} for item ${item_id}` });
            }
            itemTotal += parseFloat(supplement[0].additional_price);
          }

          if (Math.abs(parseFloat(unit_price) - itemTotal) > 0.01) {
            logger.warn('Price mismatch', { item_id, provided: unit_price, expected: itemTotal, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid unit_price for item ${item_id}. Expected ${itemTotal}, got ${unit_price}` });
          }
          calculatedTotal += itemTotal * quantity;
        }
      }

      const breakfastMap = new Map();
      if (breakfastItems && Array.isArray(breakfastItems)) {
        for (const item of breakfastItems) {
          const { breakfast_id, quantity, unit_price, option_ids } = item;
          if (!breakfast_id || isNaN(breakfast_id) || breakfast_id <= 0) {
            logger.warn('Invalid breakfast_id', { breakfast_id, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid breakfast_id: ${breakfast_id}` });
          }
          if (!quantity || isNaN(quantity) || quantity <= 0) {
            logger.warn('Invalid quantity', { breakfast_id, quantity, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid quantity for breakfast ${breakfast_id}` });
          }
          if (!unit_price || isNaN(parseFloat(unit_price)) || parseFloat(unit_price) <= 0) {
            logger.warn('Invalid unit_price', { breakfast_id, unit_price, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid unit_price for breakfast ${breakfast_id}` });
          }

          const [breakfast] = await db.query('SELECT availability, price FROM breakfasts WHERE id = ?', [breakfast_id]);
          if (breakfast.length === 0 || !breakfast[0].availability) {
            logger.warn('Breakfast unavailable', { breakfast_id, sessionID, timestamp });
            return res.status(400).json({ error: `Breakfast ${breakfast_id} is unavailable` });
          }
          let expectedPrice = parseFloat(breakfast[0].price);

          if (option_ids && Array.isArray(option_ids)) {
            const [groups] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ?', [breakfast_id]);
            if (groups.length > 0) {
              const [options] = await db.query(
                'SELECT id, group_id, additional_price FROM breakfast_options WHERE breakfast_id = ? AND id IN (?)',
                [breakfast_id, option_ids]
              );
              if (options.length !== option_ids.length) {
                logger.warn('Invalid breakfast options', { breakfast_id, option_ids, sessionID, timestamp });
                return res.status(400).json({ error: `Invalid option IDs for breakfast ${breakfast_id}` });
              }
              const selectedGroups = new Set(options.map(opt => opt.group_id));
              if (selectedGroups.size !== groups.length) {
                logger.warn('Missing options for groups', { breakfast_id, selectedGroups: [...selectedGroups], groupCount: groups.length, sessionID, timestamp });
                return res.status(400).json({ error: `Must select one option from each of the ${groups.length} option groups for breakfast ${breakfast_id}` });
              }
              const optionPrice = options.reduce((sum, opt) => sum + parseFloat(opt.additional_price || 0), 0);
              expectedPrice += optionPrice;
            } else if (option_ids.length > 0) {
              logger.warn('Options provided but no groups exist', { breakfast_id, option_ids, sessionID, timestamp });
              return res.status(400).json({ error: `No option groups defined for breakfast ${breakfast_id}, but options provided` });
            }
          } else if (option_ids && !Array.isArray(option_ids)) {
            logger.warn('Invalid option_ids format', { breakfast_id, option_ids, sessionID, timestamp });
            return res.status(400).json({ error: `Option IDs for breakfast ${breakfast_id} must be an array` });
          } else {
            const [groups] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ?', [breakfast_id]);
            if (groups.length > 0) {
              logger.warn('No options provided but groups exist', { breakfast_id, groupCount: groups.length, sessionID, timestamp });
              return res.status(400).json({ error: `Must select one option from each of the ${groups.length} option groups for breakfast ${breakfast_id}` });
            }
          }

          if (Math.abs(parseFloat(unit_price) - expectedPrice) > 0.01) {
            logger.warn('Price mismatch', { breakfast_id, provided: unit_price, expected: expectedPrice, sessionID, timestamp });
            return res.status(400).json({ error: `Invalid unit_price for breakfast ${breakfast_id}. Expected ${expectedPrice}, got ${unit_price}` });
          }

          if (!breakfastMap.has(breakfast_id)) {
            breakfastMap.set(breakfast_id, { breakfast_id, quantity: 0, unit_price: expectedPrice, option_ids: [] });
          }
          const breakfastEntry = breakfastMap.get(breakfast_id);
          breakfastEntry.quantity += quantity;
          if (option_ids && Array.isArray(option_ids)) {
            breakfastEntry.option_ids.push(...option_ids.filter(id => !breakfastEntry.option_ids.includes(id)));
          }
          calculatedTotal += expectedPrice * quantity;
        }
      }

      let table = null;
      if (table_id) {
        const [tableRows] = await db.query('SELECT id, status FROM tables WHERE id = ?', [table_id]);
        if (tableRows.length === 0) {
          logger.warn('Invalid table', { table_id, sessionID, timestamp });
          return res.status(400).json({ error: 'Table does not exist' });
        }
        table = tableRows;
        if (table[0].status === 'reserved') {
          logger.warn('Table reserved', { table_id, sessionID, timestamp });
          return res.status(400).json({ error: 'Table is reserved' });
        }
        if (table[0].status !== 'occupied') {
          await db.query('UPDATE tables SET status = ? WHERE id = ?', ['occupied', table_id]);
        }
      }

      let discount = 0;
      if (promotion_id) {
        const [promo] = await db.query(
          'SELECT discount_percentage, item_id FROM promotions WHERE id = ? AND active = TRUE AND NOW() BETWEEN start_date AND end_date',
          [promotion_id]
        );
        if (promo.length > 0) {
          discount = promo[0].discount_percentage / 100;
          let promoCalculatedPrice = 0;

          if (items && Array.isArray(items)) {
            for (const item of items) {
              const [menuItem] = await db.query('SELECT regular_price, sale_price FROM menu_items WHERE id = ?', [item.item_id]);
              let itemPrice = (menuItem[0].sale_price !== null ? parseFloat(menuItem[0].sale_price) : parseFloat(menuItem[0].regular_price)) * item.quantity;
              if (item.supplement_id) {
                const [supplement] = await db.query(
                  'SELECT additional_price FROM menu_item_supplements WHERE menu_item_id = ? AND supplement_id = ?',
                  [item.item_id, item.supplement_id]
                );
                if (supplement.length > 0) {
                  itemPrice += parseFloat(supplement[0].additional_price) * item.quantity;
                }
              }
              promoCalculatedPrice += (!promo[0].item_id || item.item_id === promo[0].item_id) ? itemPrice * (1 - discount) : itemPrice;
            }
          }

          if (breakfastItems && Array.isArray(breakfastItems)) {
            for (const item of breakfastItems) {
              const [breakfast] = await db.query('SELECT price FROM breakfasts WHERE id = ?', [item.breakfast_id]);
              let itemPrice = parseFloat(breakfast[0].price) * item.quantity;
              if (item.option_ids && Array.isArray(item.option_ids)) {
                const [options] = await db.query(
                  'SELECT additional_price FROM breakfast_options WHERE breakfast_id = ? AND id IN (?)',
                  [item.breakfast_id, item.option_ids]
                );
                const optionPrice = options.reduce((sum, opt) => sum + parseFloat(opt.additional_price || 0), 0) * item.quantity;
                itemPrice += optionPrice;
              }
              promoCalculatedPrice += itemPrice;
            }
          }

          calculatedTotal = promoCalculatedPrice;
        }
      }

      const providedPrice = parseFloat(total_price) || 0;
      if (Math.abs(providedPrice - calculatedTotal) > 0.01) {
        logger.warn('Total price mismatch', { providedPrice, calculatedPrice: calculatedTotal, sessionID, timestamp });
        return res.status(400).json({ error: `Total price mismatch. Expected ${calculatedTotal.toFixed(2)}, got ${providedPrice.toFixed(2)}` });
      }

      const connection = await db.getConnection();
      await connection.beginTransaction();

      try {
        const [orderResult] = await connection.query(
          'INSERT INTO orders (total_price, order_type, delivery_address, promotion_id, table_id, session_id) VALUES (?, ?, ?, ?, ?, ?)',
          [calculatedTotal, order_type, delivery_address || null, promotion_id || null, table_id || null, sessionID]
        );
        const orderId = orderResult.insertId;

        if (items && Array.isArray(items)) {
          for (const item of items) {
            await connection.query(
              'INSERT INTO order_items (order_id, item_id, quantity, unit_price, supplement_id) VALUES (?, ?, ?, ?, ?)',
              [orderId, item.item_id, item.quantity, item.unit_price, item.supplement_id || null]
            );
          }
        }

        if (breakfastItems && Array.isArray(breakfastItems)) {
          for (const [breakfast_id, { quantity, unit_price, option_ids }] of breakfastMap) {
            const [orderItemResult] = await connection.query(
              'INSERT INTO order_items (order_id, breakfast_id, quantity, unit_price) VALUES (?, ?, ?, ?)',
              [orderId, breakfast_id, quantity, unit_price]
            );
            const orderItemId = orderItemResult.insertId;
            if (option_ids && Array.isArray(option_ids)) {
              for (const optionId of option_ids) {
                await connection.query(
                  'INSERT INTO breakfast_order_options (order_item_id, breakfast_option_id) VALUES (?, ?)',
                  [orderItemId, optionId]
                );
              }
            }
          }
        }

        const [orderDetails] = await connection.query(`
          SELECT o.*, t.table_number,
                 GROUP_CONCAT(oi.item_id) AS item_ids,
                 GROUP_CONCAT(CASE WHEN oi.item_id IS NOT NULL THEN oi.quantity END) AS menu_quantities,
                 GROUP_CONCAT(mi.name) AS item_names, GROUP_CONCAT(mi.image_url) AS image_urls,
                 GROUP_CONCAT(oi.unit_price) AS unit_prices, GROUP_CONCAT(oi.supplement_id) AS supplement_ids,
                 GROUP_CONCAT(mis.name) AS supplement_names, GROUP_CONCAT(mis.additional_price) AS supplement_prices,
                 GROUP_CONCAT(DISTINCT oi.breakfast_id) AS breakfast_ids,
                 GROUP_CONCAT(CASE WHEN oi.breakfast_id IS NOT NULL THEN oi.quantity END) AS breakfast_quantities,
                 GROUP_CONCAT(DISTINCT b.name) AS breakfast_names,
                 GROUP_CONCAT(DISTINCT b.image_url) AS breakfast_images,
                 GROUP_CONCAT(boo.breakfast_option_id) AS breakfast_option_ids,
                 GROUP_CONCAT(bo.option_name) AS breakfast_option_names,
                 GROUP_CONCAT(bo.additional_price) AS breakfast_option_prices
          FROM orders o
          LEFT JOIN order_items oi ON o.id = oi.order_id
          LEFT JOIN menu_items mi ON oi.item_id = mi.id
          LEFT JOIN menu_item_supplements mis ON oi.supplement_id = mis.supplement_id AND oi.item_id = mis.menu_item_id
          LEFT JOIN breakfasts b ON oi.breakfast_id = b.id
          LEFT JOIN breakfast_order_options boo ON oi.id = boo.order_item_id
          LEFT JOIN breakfast_options bo ON boo.breakfast_option_id = bo.id
          LEFT JOIN tables t ON o.table_id = t.id
          WHERE o.id = ?
          GROUP BY o.id
        `, [orderId]);

        orderDetails[0].approved = Number(orderDetails[0].approved);

        const table_number = orderDetails[0].table_number || 'N/A';
        const notificationMessage = order_type === 'local'
          ? `New order #${orderId} for Table ${table_number}`
          : `New delivery order #${orderId} for ${delivery_address}`;
        const [notificationResult] = await connection.query(
          'INSERT INTO notifications (type, reference_id, message) VALUES (?, ?, ?)',
          ['order', orderId, notificationMessage]
        );
        const notificationId = notificationResult.insertId;

        const [rows] = await connection.query('SELECT * FROM notifications WHERE id = ?', [notificationId]);
        const notification = rows[0];

        await connection.commit();

        io.emit('newOrder', orderDetails[0]);
        if (table_id && table && table[0].status !== 'occupied') {
          io.emit('tableStatusUpdate', { id: table_id, status: 'occupied' });
        }

        io.to('staff-notifications').emit('newNotification', {
          id: notification.id,
          type: notification.type,
          reference_id: notification.reference_id,
          message: notification.message,
          is_read: Number(notification.is_read),
          created_at: notification.created_at.toISOString(),
        });

        logger.info('Order created successfully', {
          orderId,
          items: items?.length || 0,
          breakfastItems: breakfastItems?.length || 0,
          supplements: items?.map(i => ({ item_id: i.item_id, supplement_id: i.supplement_id })) || [],
          request_id,
          table_id,
          total_price: calculatedTotal,
          notificationId,
          sessionID,
          timestamp,
        });
        res.status(201).json({ message: 'Order created', orderId });
      } catch (err) {
        await connection.rollback();
        logger.error('Error creating order in transaction', { error: err.message, table_id, sessionID, timestamp });
        res.status(500).json({ error: 'Failed to create order' });
      } finally {
        connection.release();
      }
    } catch (err) {
      logger.error('Error creating order', { error: err.message, table_id, sessionID, timestamp });
      res.status(500).json({ error: 'Failed to create order' });
    }
  });

  router.get('/orders', async (req, res) => {
    const sessionID = req.headers['x-session-id'] || req.sessionID;
    const timestamp = new Date().toISOString();
    const { time_range, approved } = req.query;

    try {
      if (!req.session.user || !await checkAdminOrServer(req.session.user.id)) {
        logger.warn('Unauthorized attempt to fetch orders', { sessionUser: req.session.user, sessionID, timestamp });
        return res.status(403).json({ error: 'Admin or server access required' });
      }

      let query = `
        SELECT o.*, t.table_number,
               GROUP_CONCAT(oi.item_id) AS item_ids,
               GROUP_CONCAT(CASE WHEN oi.item_id IS NOT NULL THEN oi.quantity END) AS menu_quantities,
               GROUP_CONCAT(mi.name) AS item_names, GROUP_CONCAT(mi.image_url) AS image_urls,
               GROUP_CONCAT(oi.unit_price) AS unit_prices, GROUP_CONCAT(oi.supplement_id) AS supplement_ids,
               GROUP_CONCAT(mis.name) AS supplement_names, GROUP_CONCAT(mis.additional_price) AS supplement_prices,
               GROUP_CONCAT(DISTINCT oi.breakfast_id) AS breakfast_ids,
               GROUP_CONCAT(CASE WHEN oi.breakfast_id IS NOT NULL THEN oi.quantity END) AS breakfast_quantities,
               GROUP_CONCAT(DISTINCT b.name) AS breakfast_names,
               GROUP_CONCAT(DISTINCT b.image_url) AS breakfast_images,
               GROUP_CONCAT(boo.breakfast_option_id) AS breakfast_option_ids,
               GROUP_CONCAT(bo.option_name) AS breakfast_option_names,
               GROUP_CONCAT(bo.additional_price) AS breakfast_option_prices
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        LEFT JOIN menu_items mi ON oi.item_id = mi.id
        LEFT JOIN menu_item_supplements mis ON oi.supplement_id = mis.supplement_id AND oi.item_id = mis.menu_item_id
        LEFT JOIN breakfasts b ON oi.breakfast_id = b.id
        LEFT JOIN breakfast_order_options boo ON oi.id = boo.order_item_id
        LEFT JOIN breakfast_options bo ON boo.breakfast_option_id = bo.id
        LEFT JOIN tables t ON o.table_id = t.id
      `;
      let queryParams = [];
      let whereClauses = [];

      if (time_range === 'hour') {
        whereClauses.push('o.created_at >= NOW() - INTERVAL 1 HOUR');
      } else if (time_range === 'day') {
        whereClauses.push('o.created_at >= CURDATE()');
      } else if (time_range === 'yesterday') {
        whereClauses.push('o.created_at >= CURDATE() - INTERVAL 1 DAY AND o.created_at < CURDATE()');
      } else if (time_range === 'week') {
        whereClauses.push('o.created_at >= CURDATE() - INTERVAL 7 DAY');
      } else if (time_range === 'month') {
        whereClauses.push('o.created_at >= CURDATE() - INTERVAL 30 DAY');
      }

      if (approved === '1') {
        whereClauses.push('o.approved = 1');
      } else if (approved === '0') {
        whereClauses.push('o.approved = 0');
      }

      if (whereClauses.length > 0) {
        query += ' WHERE ' + whereClauses.join(' AND ');
      }

      query += ' GROUP BY o.id ORDER BY o.created_at DESC';

      const [rows] = await db.query(query, queryParams);

      const formattedRows = rows.map(row => ({
        ...row,
        approved: Number(row.approved),
      }));

      logger.info('Orders fetched successfully', { count: formattedRows.length, time_range, approved, sessionID, timestamp });
      res.json({ data: formattedRows });
    } catch (err) {
      logger.error('Error fetching orders', { error: err.message, time_range, approved, sessionID, timestamp });
      res.status(500).json({ error: 'Failed to fetch orders' });
    }
  });

  router.get('/orders/:id', async (req, res) => {
    const { id } = req.params;
    const sessionID = req.headers['x-session-id'] || req.sessionID;
    const timestamp = new Date().toISOString();

    try {
      const orderId = parseInt(id);
      if (isNaN(orderId) || orderId <= 0) {
        logger.warn('Invalid order ID', { orderId: id, sessionID, timestamp });
        return res.status(400).json({ error: 'Valid order ID required' });
      }

      const [rows] = await db.query(`
        SELECT o.*, t.table_number,
               GROUP_CONCAT(oi.item_id) AS item_ids,
               GROUP_CONCAT(CASE WHEN oi.item_id IS NOT NULL THEN oi.quantity END) AS menu_quantities,
               GROUP_CONCAT(mi.name) AS item_names, GROUP_CONCAT(mi.image_url) AS image_urls,
               GROUP_CONCAT(oi.unit_price) AS unit_prices, GROUP_CONCAT(oi.supplement_id) AS supplement_ids,
               GROUP_CONCAT(mis.name) AS supplement_names, GROUP_CONCAT(mis.additional_price) AS supplement_prices,
               GROUP_CONCAT(DISTINCT oi.breakfast_id) AS breakfast_ids,
               GROUP_CONCAT(CASE WHEN oi.breakfast_id IS NOT NULL THEN oi.quantity END) AS breakfast_quantities,
               GROUP_CONCAT(DISTINCT b.name) AS breakfast_names,
               GROUP_CONCAT(DISTINCT b.image_url) AS breakfast_images,
               GROUP_CONCAT(boo.breakfast_option_id) AS breakfast_option_ids,
               GROUP_CONCAT(bo.option_name) AS breakfast_option_names,
               GROUP_CONCAT(bo.additional_price) AS breakfast_option_prices
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        LEFT JOIN menu_items mi ON oi.item_id = mi.id
        LEFT JOIN menu_item_supplements mis ON oi.supplement_id = mis.supplement_id AND oi.item_id = mis.menu_item_id
        LEFT JOIN breakfasts b ON oi.breakfast_id = b.id
        LEFT JOIN breakfast_order_options boo ON oi.id = boo.order_item_id
        LEFT JOIN breakfast_options bo ON boo.breakfast_option_id = bo.id
        LEFT JOIN tables t ON o.table_id = t.id
        WHERE o.id = ?
        GROUP BY o.id
      `, [orderId]);

      if (rows.length === 0) {
        logger.warn('Order not found', { orderId, sessionID, timestamp });
        return res.status(404).json({ error: 'Order not found' });
      }

      rows[0].approved = Number(rows[0].approved);

      logger.info('Order fetched successfully', { orderId, sessionID, timestamp });
      res.json(rows[0]);
    } catch (err) {
      logger.error('Error fetching order', { error: err.message, orderId: id, sessionID, timestamp });
      res.status(500).json({ error: 'Failed to fetch order' });
    }
  });

  router.put('/orders/:id', async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const sessionID = req.headers['x-session-id'] || req.sessionID;
    const timestamp = new Date().toISOString();

    try {
      if (!req.session.user || !await checkAdminOrServer(req.session.user.id)) {
        logger.warn('Unauthorized attempt to update order', { sessionUser: req.session.user.id, sessionID, timestamp });
        return res.status(403).json({ error: 'Admin or server access required' });
      }

      const orderId = parseInt(id);
      if (isNaN(orderId) || orderId <= 0) {
        logger.warn('Invalid order ID', { id, sessionID, timestamp });
        return res.status(400).json({ error: 'Valid order ID required' });
      }

      logger.warn('Status updates not supported', { orderId, status, sessionID, timestamp });
      return res.status(400).json({ error: 'Order status updates are not supported' });
    } catch (err) {
      logger.error('Error processing order update', { error: err.message, orderId: id, sessionID, timestamp });
      res.status(500).json({ error: 'Failed to process order update' });
    }
  });

  router.post('/orders/:id/approve', async (req, res) => {
    const { id } = req.params;
    const timestamp = new Date().toISOString();
    const sessionID = req.headers['x-session-id'] || req.sessionID;

    try {
      if (!req.session.user || !await checkAdminOrServer(req.session.user.id)) {
        logger.warn('Unauthorized attempt to approve order', { sessionUser: req.session.user.id, sessionID, timestamp });
        return res.status(403).json({ error: 'Admin or server access required' });
      }
      const orderId = parseInt(id);
      if (isNaN(orderId) || orderId <= 0) {
        logger.warn('Invalid order ID for approval', { id, sessionID, timestamp });
        return res.status(400).json({ error: 'Valid order ID required' });
      }
      const [orderRows] = await db.query('SELECT session_id, approved FROM orders WHERE id = ?', [orderId]);
      if (orderRows.length === 0) {
        logger.warn('Order not found for approval', { orderId, sessionID, timestamp });
        return res.status(404).json({ error: 'Order not found' });
      }
      if (orderRows[0].approved) {
        logger.warn('Order already approved', { orderId, sessionID, timestamp });
        return res.status(400).json({ error: 'Order already approved' });
      }

      await db.query('UPDATE orders SET approved = 1 WHERE id = ?', [orderId]);

      const [orderDetails] = await db.query(`
        SELECT o.*, t.table_number,
               GROUP_CONCAT(oi.item_id) AS item_ids,
               GROUP_CONCAT(CASE WHEN oi.item_id IS NOT NULL THEN oi.quantity END) AS menu_quantities,
               GROUP_CONCAT(mi.name) AS item_names, GROUP_CONCAT(mi.image_url) AS image_urls,
               GROUP_CONCAT(oi.unit_price) AS unit_prices, GROUP_CONCAT(oi.supplement_id) AS supplement_ids,
               GROUP_CONCAT(mis.name) AS supplement_names, GROUP_CONCAT(mis.additional_price) AS supplement_prices,
               GROUP_CONCAT(DISTINCT oi.breakfast_id) AS breakfast_ids,
               GROUP_CONCAT(CASE WHEN oi.breakfast_id IS NOT NULL THEN oi.quantity END) AS breakfast_quantities,
               GROUP_CONCAT(DISTINCT b.name) AS breakfast_names,
               GROUP_CONCAT(DISTINCT b.image_url) AS breakfast_images,
               GROUP_CONCAT(boo.breakfast_option_id) AS breakfast_option_ids,
               GROUP_CONCAT(bo.option_name) AS breakfast_option_names,
               GROUP_CONCAT(bo.additional_price) AS breakfast_option_prices
        FROM orders o
        LEFT JOIN order_items oi ON o.id = oi.order_id
        LEFT JOIN menu_items mi ON oi.item_id = mi.id
        LEFT JOIN menu_item_supplements mis ON oi.supplement_id = mis.supplement_id AND oi.item_id = mis.menu_item_id
        LEFT JOIN breakfasts b ON oi.breakfast_id = b.id
        LEFT JOIN breakfast_order_options boo ON oi.id = boo.order_item_id
        LEFT JOIN breakfast_options bo ON boo.breakfast_option_id = bo.id
        LEFT JOIN tables t ON o.table_id = t.id
        WHERE o.id = ?
        GROUP BY o.id
      `, [orderId]);

      orderDetails[0].approved = Number(orderDetails[0].approved);

      const sessionId = orderRows[0].session_id;
      io.to(sessionId).emit('order-approved', { orderId: orderId.toString(), orderDetails: orderDetails[0] });
      io.emit('orderApproved', { orderId: orderId.toString(), orderDetails: orderDetails[0] });

      logger.info('Order approved successfully', { orderId, sessionId, sessionID, timestamp });
      res.status(200).json({ message: 'Order approved' });
    } catch (err) {
      logger.error('Error approving order', { error: err.message, orderId: id, sessionID, timestamp });
      res.status(500).json({ error: 'Failed to approve order' });
    }
  });

  router.get('/session', (req, res) => {
    const sessionID = req.headers['x-session-id'] || req.sessionID;
    res.json({ sessionId: sessionID });
  });

  return router;
};