import express from 'express';
import logger from '#config/logger.js';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoute from '#routes/auth.route.js';
import securityMiddleware from '#middleware/security.middleware.js';
import usersRoute from '#routes/users.route.js';


const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  morgan('combined', {
    stream: { write: message => logger.info(message.trim()) },
  })
);
app.use(securityMiddleware);

app.get('/health', (req, res) => {
  res
    .status(200)
    .json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
});


app.get('/', (req, res) => {
  logger.info('Hello Acquisitions Api!');
  res.status(200).send('Hello from Acquisitions API');
});

app.get('/api', (req, res) => {
  res.status(200).json({ message: 'Acquisitions API is running!' });
});

app.use('/api/auth',authRoute);
app.use('/api/users', usersRoute);

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});


export default app;
