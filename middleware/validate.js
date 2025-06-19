const { body, validationResult, param, query } = require('express-validator');
const logger = require('../logger');
const db = require('../config/db');

const validate = (req, res, next) => {
  const validations = [];

  logger.debug('Validation middleware called', {
    method: req.method,
    path: req.path,
    params: req.params,
    body: req.body,
  });

  // Menu item validations
  if (req.method === 'POST' || req.method === 'PUT') {
    if (req.path.includes('/menu-items') && !req.path.includes('/availability') && !req.path.includes('/supplements')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('regular_price')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : undefined)
          .isFloat({ min: 0.01 })
          .withMessage('Regular price must be a positive number'),
        body('sale_price')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : undefined)
          .isFloat({ min: 0 })
          .withMessage('Sale price must be a non-negative number'),
        body('category_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Invalid category ID'),
        body('availability')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value === 'true' || value === true)
          .isBoolean()
          .withMessage('Availability must be a boolean'),
        body('dietary_tags')
          .optional()
          .customSanitizer(value => {
            if (!value) return [];
            try {
              const parsed = Array.isArray(value) ? value : JSON.parse(value);
              return Array.isArray(parsed) ? parsed : value.split(',').map(tag => tag.trim()).filter(tag => tag);
            } catch {
              return value.split(',').map(tag => tag.trim()).filter(tag => tag);
            }
          }),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string')
      );
      if (req.method === 'PUT' && req.path.match(/^\/menu-items\/\d+$/)) {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid item ID is required')
        );
      }
    } else if (req.path.includes('/orders') && req.method === 'POST') {
      validations.push(
        body('items').optional().isArray().withMessage('Items must be an array'),
        body('items.*.item_id')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid item ID is required'),
        body('items.*.quantity')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Quantity must be at least 1'),
        body('items.*.unit_price')
          .optional()
          .isFloat({ min: 0.01 })
          .withMessage('Unit price must be a positive number'),
        body('items.*.supplement_id')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid supplement ID is required'),
        body('breakfastItems').optional().isArray().withMessage('Breakfast items must be an array'),
        body('breakfastItems.*.breakfast_id')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required'),
        body('breakfastItems.*.quantity')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Quantity must be at least 1'),
        body('breakfastItems.*.unit_price')
          .optional()
          .isFloat({ min: 0.01 })
          .withMessage('Unit price must be a positive number'),
        body('breakfastItems.*.option_ids')
          .optional()
          .isArray()
          .withMessage('Option IDs must be an array'),
        body('breakfastItems.*.option_ids.*')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid option ID is required'),
        body('breakfastItems.*.option_ids')
          .optional()
          .custom(async (optionIds, { req }) => {
            if (!optionIds || !Array.isArray(optionIds)) return true;
            const breakfastId = req.body.breakfastItems.find(item => item.option_ids === optionIds)?.breakfast_id;
            if (!breakfastId) return false;
            const [groups] = await db.query('SELECT id FROM breakfast_option_groups WHERE breakfast_id = ?', [breakfastId]);
            if (groups.length === 0 && optionIds.length === 0) return true; // No groups, no options needed
            if (groups.length === 0 && optionIds.length > 0) {
              throw new Error(`No option groups defined for breakfast ${breakfastId}, but options provided`);
            }
            const [options] = await db.query(
              'SELECT group_id FROM breakfast_options WHERE id IN (?) AND breakfast_id = ?',
              [optionIds, breakfastId]
            );
            const selectedGroups = new Set(options.map(opt => opt.group_id));
            if (selectedGroups.size !== groups.length) {
              throw new Error(`Must select exactly one option from each of the ${groups.length} option groups for breakfast ${breakfastId}`);
            }
            return true;
          })
          .withMessage('Must select exactly one option from each option group'),
        body('total_price')
          .isFloat({ min: 0.01 })
          .withMessage('Total price must be a positive number'),
        body('order_type')
          .isIn(['delivery', 'local'])
          .withMessage('Order type must be delivery or local'),
        body('delivery_address')
          .if(body('order_type').equals('delivery'))
          .notEmpty()
          .isString()
          .withMessage('Delivery address is required for delivery orders'),
        body('promotion_id')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid promotion ID is required'),
        body('table_id')
          .if(body('order_type').equals('local'))
          .notEmpty()
          .isInt({ min: 1 })
          .withMessage('Table ID is required for local orders'),
        body('request_id')
          .notEmpty()
          .isString()
          .matches(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)
          .withMessage('Valid UUID v4 request ID is required')
      );
    } else if (req.path.match(/^\/orders\/\d+\/approve$/) && req.method === 'POST') {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid order ID is required')
      );
    } else if (req.path.includes('/categories') && !req.path.includes('/supplements')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid category ID is required')
        );
      }
    } else if (req.path.includes('/promotions')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string'),
        body('discount_percentage')
          .isFloat({ min: 0, max: 100 })
          .withMessage('Discount percentage must be between 0 and 100'),
        body('item_id')
          .optional()
          .isInt({ min: 1 })
          .withMessage('Valid item ID is required'),
        body('start_date').isISO8601().withMessage('Valid start date is required'),
        body('end_date').isISO8601().withMessage('Valid end date is required'),
        body('active').isBoolean().withMessage('Active must be a boolean')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid promotion ID is required')
        );
      }
    } else if (req.path.includes('/staff') || req.path.match(/^\/users(\/\d+)?$/)) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('email').isEmail().withMessage('Valid email is required'),
        body('role')
          .isIn(['server', 'admin'])
          .withMessage('Role must be server or admin')
      );
      if (req.path.includes('/staff')) {
        validations.push(
          body('password')
            .isString()
            .notEmpty()
            .isLength({ min: 6 })
            .withMessage('Password must be at least 6 characters')
        );
      }
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid user ID is required')
        );
      }
    } else if (req.path.includes('/tables')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('table_number')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Table number is required'),
        body('capacity')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Capacity must be a positive integer'),
        body('status')
          .optional()
          .isIn(['available', 'occupied'])
          .withMessage('Status must be available or occupied')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid table ID is required')
        );
      }
    } else if (req.path.includes('/reservations')) {
      validations.push(
        body('table_id')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid table ID is required'),
        body('reservation_time').isISO8601().withMessage('Valid reservation time is required'),
        body('phone_number')
          .matches(/^\+\d{10,15}$/)
          .withMessage('Phone number must be in international format (e.g., +1234567890)')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid reservation ID is required'),
          body('status')
            .isIn(['pending', 'confirmed', 'cancelled'])
            .withMessage('Valid status is required')
        );
      }
    } else if (req.path.includes('/supplements') && !req.path.includes('/menu-items')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('price')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : undefined)
          .isFloat({ min: 0.01 })
          .withMessage('Price must be a positive number')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid supplement ID is required')
        );
      }
    } else if (req.path.includes('/menu-items') && req.path.includes('/supplements')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('supplement_id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid supplement ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('additional_price')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : undefined)
          .isFloat({ min: 0 })
          .withMessage('Additional price must be a non-negative number'),
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid menu item ID is required')
      );
      if (req.method === 'PUT' && req.path.match(/^\/menu-items\/\d+\/supplements\/\d+$/)) {
        validations.push(
          param('menuItemId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid menu item ID is required'),
          param('supplementId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid supplement ID is required'),
          body('user_id')
            .optional()
            .isString()
            .trim()
            .customSanitizer(value => value ? parseInt(value) : undefined)
            .isInt({ min: 1 })
            .withMessage('Valid user ID is required'),
          body('name')
            .isString()
            .notEmpty()
            .trim()
            .withMessage('Name is required'),
          body('additional_price')
            .isString()
            .trim()
            .customSanitizer(value => value ? parseFloat(value) : undefined)
            .isFloat({ min: 0 })
            .withMessage('Additional price must be a non-negative number')
        );
      }
      if (req.method === 'DELETE') {
        validations.push(
          param('menuItemId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid menu item ID is required'),
          param('supplementId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid supplement ID is required')
        );
      }
    } else if (req.path.includes('/breakfasts') && req.path.includes('/option-groups')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('title')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Title is required'),
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
      if (req.method === 'PUT' && req.path.match(/^\/breakfasts\/\d+\/option-groups\/\d+$/)) {
        validations.push(
          param('breakfastId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required'),
          param('groupId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid group ID is required')
        );
      }
      if (req.method === 'DELETE') {
        validations.push(
          param('breakfastId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required'),
          param('groupId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid group ID is required')
        );
      }
    } else if (req.path.includes('/breakfasts') && req.path.includes('/options')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('group_id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid group ID is required'),
        body('option_type')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Option type is required'),
        body('option_name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Option name is required'),
        body('additional_price')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : 0)
          .isFloat({ min: 0 })
          .withMessage('Additional price must be a non-negative number'),
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
      if (req.method === 'PUT' && req.path.match(/^\/breakfasts\/\d+\/options\/\d+$/)) {
        validations.push(
          param('breakfastId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Invalid category ID'),
          body('group_id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid group ID is required')
        );
      }
      if (req.method === 'DELETE') {
        validations.push(
          param('breakfastId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required'),
          param('optionId')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid option ID is required')
        );
      }
    } else if (req.path.includes('/breakfasts') && !req.path.includes('/options') && !req.path.includes('/option-groups')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('name')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Name is required'),
        body('price')
          .isString()
          .trim()
          .customSanitizer(value => value ? parseFloat(value) : undefined)
          .isFloat({ min: 0.01 })
          .withMessage('Price must be a positive number'),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string'),
        body('availability')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value === 'true' || value === true)
          .isBoolean()
          .withMessage('Availability must be a boolean'),
        body('category_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Invalid category ID')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid breakfast ID is required')
        );
      }
    } else if (req.path.includes('/notifications')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('type')
          .isIn(['order', 'reservation'])
          .withMessage('Type must be order or reservation'),
        body('message')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Message is required'),
        body('ref_id')
          .isInt({ min: 1 })
          .withMessage('Valid reference ID is required')
      );
    } else if (req.path.includes('/banners')) {
      validations.push(
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('title')
          .isString()
          .notEmpty()
          .trim()
          .withMessage('Title is required'),
        body('description')
          .optional()
          .isString()
          .trim()
          .withMessage('Description must be a string'),
        body('active')
          .isBoolean()
          .withMessage('Active must be a boolean')
      );
      if (req.method === 'PUT') {
        validations.push(
          param('id')
            .isString()
            .trim()
            .customSanitizer(value => parseInt(value))
            .isInt({ min: 1 })
            .withMessage('Valid banner ID is required')
        );
      }
    }
  }

  // GET and DELETE validations
  if (req.method === 'GET') {
    if (req.path.match(/^\/orders(?!.*(approve|session))/)) {
      validations.push(
        query('time_range')
          .optional()
          .isIn(['hour', 'day', 'yesterday', 'week', 'month'])
          .withMessage('Invalid time range'),
        query('approved')
          .optional()
          .isIn(['0', '1'])
          .withMessage('Approved must be 0 or 1')
      );
    }
    if (req.path.match(/^\/orders\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid order ID is required')
      );
    }
    if (req.path.match(/^\/menu-items\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid item ID is required')
      );
    }
    if (req.path.match(/^\/categories\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid category ID is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/options$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
    if (req.path.match(/^\/breakfasts\/\d+\/option-groups$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required')
      );
    }
  }

  if (req.method === 'DELETE') {
    if (req.path.match(/^\/menu-items\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid item ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/categories\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid category ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/promotions\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid promotion ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/staff\/\d+$/) || req.path.match(/^\/users\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/tables\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid table ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/supplements\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid supplement ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    } else if (req.path.match(/^\/breakfasts\/\d+$/)) {
      validations.push(
        param('id')
          .isString()
          .trim()
          .customSanitizer(value => parseInt(value))
          .isInt({ min: 1 })
          .withMessage('Valid breakfast ID is required'),
        body('user_id')
          .optional()
          .isString()
          .trim()
          .customSanitizer(value => value ? parseInt(value) : undefined)
          .isInt({ min: 1 })
          .withMessage('Valid user ID is required')
      );
    }
  }

  Promise.all(validations.map(validation => validation.run(req))).then(() => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Validation errors', {
        errors: errors.array(),
        method: req.method,
        path: req.path,
        body: req.body,
        params: req.params,
        query: req.query,
      });
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  });
};

module.exports = validate;