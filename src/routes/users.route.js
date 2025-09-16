import express from 'express';
import { authenticateToken, requireRole } from '#middleware/auth.middleware.js';
import {
  deleteUserById,
  fetchAllUsers,
  fetchUserById,
  getProfile,
  updateProfile,
  deleteUserProfile,
  updateUserById,
} from '#controllers/users.controller.js';


const router = express.Router();

// ========================== USER Routes ===================================================

router.get('/profile',authenticateToken,getProfile);

router.put('/profile',authenticateToken,updateProfile);

router.delete('/profile', authenticateToken, deleteUserProfile);

// ========================== ADMIN Routes ===================================================

// GET /users - Get users (admin only)
// router.post('/', async (req, res) => {});

// GET /users - Get users (admin only)
router.get('/',authenticateToken,requireRole(['admin']),fetchAllUsers);

// GET /users/:id - Get users (admin only)
router.get('/:id',authenticateToken,requireRole(['admin']),fetchUserById);

// PUT /users/:id - Update user by ID (admin only)
router.put('/:id', authenticateToken,requireRole(['admin']),updateUserById);

// DELETE /users/:id - Delete user by ID (admin only)
router.delete(
  '/:id',
  authenticateToken,
  requireRole(['admin']),
  deleteUserById,
);

export default router;