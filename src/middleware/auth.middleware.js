import logger from '#config/logger.js';
import { jwtToken } from '#utils/jwt.js';
import { users } from '#models/user.model.js';
import { db } from '#config/database.js';
import { eq } from 'drizzle-orm';

export const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'No access token provided',
      });
    }

    const decoded = jwtToken.verify(token);

    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email,decoded.email))
      .limit(1);

    if (!existingUser) {
      throw new Error('Failed to authenticate token');
    }

    logger.info(`User authenticated: ${decoded.email} (${decoded.role})`);
    req.user = existingUser;
    next();
  } catch (e) {
    logger.error('Authentication error:', e);

    if (e.message === 'Failed to authenticate token') {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid or expired token',
      });
    }

    return res.status(500).json({
      error: 'Internal server error',
      message: 'Error during authentication',
    });
  }
};

export const requireRole = allowedRoles => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'User not authenticated',
        });
      }

      if (!allowedRoles.includes(req.user.role)) {
        logger.warn(
          `Access denied for user ${req.user.email} with role ${req.user.role}. Required: ${allowedRoles.join(', ')}`
        );
        return res.status(403).json({
          error: 'Access denied',
          message: 'Insufficient permissions',
        });
      }

      next();
    } catch (e) {
      logger.error('Role verification error:', e);
      return res.status(500).json({
        error: 'Internal server error',
        message: 'Error during role verification',
      });
    }
  };
};