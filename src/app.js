import express from 'express';
const app = express();

const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.status(200).send('Hello from Acquisitions API');
});

export default app;
