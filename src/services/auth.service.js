import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try{
    return await bcrypt.hash(password, 10);
  }catch(err){
    logger.error(`Error hashing the password : ${err}`);
    throw new Error('Error hashing the password');
  }
};

export const comparePassword = async (password,hashedPassword) => {
  try{
    return await bcrypt.compare(password, hashedPassword);
  }catch(err){
    logger.error(`Error comparing password : ${err}`);
    throw new Error('Error comparing the password');
  }
};

export const createUser = async ({name,email,password,role = 'user'}) => {
  try{
    const existingUser = db.select().from(users).where(eq(users.email,email)).limit(1);
    if (existingUser.length > 0) {
      throw new Error('User already exists');
    }

    const hashedPassword = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({name, email, password: hashedPassword, role})
      .returning({ id : users.id, name : users.name, email: users.email, role: users.role, created_at: users.created_at });

    logger.info(`Successfully created user ${newUser.email}`);
    return newUser;
  }catch(err){
    logger.error(`Error Creating the user : ${err}`);
    throw err;

  }
};

export const authenticateUser = async ({ email, password }) => {
  try{
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email,email))
      .limit(1);

    if (!existingUser) {
      throw new Error('User not found');
    }

    const isPasswordValid = await comparePassword(password, existingUser.password);

    if (!isPasswordValid) {
      throw new Error('Invalid password');
    }

    logger.info(`User ${existingUser.email} authenticated successfully`);

    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      created_at: existingUser.created_at,
    };

  }catch(err){
    logger.error(`Error authenticating the user : ${err}`);
    throw err;
  }

};