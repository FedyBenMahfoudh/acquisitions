import jwt from 'jsonwebtoken';
import logger from '#config/logger.js';

const JWT_SECRET = process.env.JWT_SECRET || 'secret-key';
const JWT_EXPIRE_IN = '1d';

export const  jwtToken = {
  sign : (payload) => {
    try{
      return jwt.sign(payload, JWT_SECRET,{expiresIn: JWT_EXPIRE_IN});
    }catch(err){
      logger.error('Error in authenticating token');
      throw new Error('Error in authenticating token');
    }
  },
  verify : (token ) => {
    try{
      return jwt.verify(token, JWT_SECRET);
    }catch(err){
      logger.error('Error in verifying token');
      throw new Error('Error in verifying token');
    }
  }
};

