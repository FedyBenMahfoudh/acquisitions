import { signInSchema, signUpSchema } from '#validations/auth.validations.js';
import logger from '#config/logger.js';
import { formatValidationErrors } from '#utils/format.js';
import { authenticateUser, createUser } from '#services/auth.service.js';
import { jwtToken } from '#utils/jwt.js';
import { cookies } from '#utils/cookie.js';


export const signUp = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationErrors(validationResult.error),
      });
    }
    const { name, email, password,role } = validationResult.data;

    // Auth service
    const user = await createUser({ name, email, password, role });

    const token = await jwtToken.sign({id: user.id,email: user.email,role: user.role});

    cookies.set(res,'token', token);

    logger.info(`User registered successfully : ${email}`);
    res.status(201).json({
      message: 'User registered successfully registered',
      user : {
        id : user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });
  }catch(err) {
    logger.error('Error occurred while signing up.',err);
    if(err.message === 'User with this email already exists') {
      return res.status(409).json({error: 'Email already exists'});
    }
    next(err);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationErrors(validationResult.error),
      });
    }
    const { email, password } = validationResult.data;

    // Auth service
    const user = await authenticateUser({ email, password });

    const token = await jwtToken.sign({id: user.id,email: user.email,role: user.role});

    cookies.set(res,'token', token);

    logger.info(`User Signed in successfully : ${email}`);
    res.status(201).json({
      message: 'User Signed in successfully',
      user : {
        id : user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });
  }catch(err) {
    logger.error('Sign in error', err);

    if (err.message === 'User not found' || err.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    next(err);

  }
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User signed out successfully');
    res.status(200).json({
      message: 'User signed out successfully',
    });
  } catch (e) {
    logger.error('Sign out error', e);
    next(e);
  }
};