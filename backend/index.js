const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'florasense',
  waitForConnections: true,
  connectionLimit: 10,
});

const JWT_SECRET = process.env.JWT_SECRET || 'florasense_dev_secret_change_in_prod';

const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ message: 'Invalid or expired token.' });
  }
};

app.post('/auth/register', async (req, res) => {
  const { fName, lName, username, password, email } = req.body;

  if (!fName || !lName || !username || !password || !email) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT userID FROM user WHERE username = ? OR email = ?',
      [username, email]
    );
    if (existing.length > 0) {
      return res.status(409).json({ message: 'Username or email already taken.' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const [result] = await pool.query(
      'INSERT INTO user (fName, lName, username, password, email) VALUES (?, ?, ?, ?, ?)',
      [fName, lName, username, hashedPassword, email]
    );

    res.status(201).json({
      message: 'Account created successfully.',
      userID: result.insertId,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT userID, fName, lName, username, email, password FROM user WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    const token = jwt.sign(
      { userID: user.userID, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { password: _pw, ...safeUser } = user;

    res.json({ token, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

app.get('/auth/me', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT userID, fName, lName, username, email FROM user WHERE userID = ?',
      [req.user.userID]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'User not found.' });
    res.json({ user: rows[0] });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', app: 'FloraSense API' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🌿 FloraSense API running on port ${PORT}`);
});

app.get('/plants/:userID', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM plants WHERE userID = ?',
      [req.params.userID]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Could not fetch plants.' });
  }
});

app.post('/plants', authenticate, async (req, res) => {
  const { name, type, description, location, userID, sensorID } = req.body;

  console.log('Body received:', req.body);

  if (!name || !type) return res.status(400).json({ message: 'Name and type are required.' });
  try {
    const [result] = await pool.query(
      'INSERT INTO plants (name, type, description, location, userID, sensorID) VALUES (?, ?, ?, ?, ?, ?)',
      [name, type, description, location, userID, sensorID ?? null]
    );
    res.status(201).json({ message: 'Plant added.', plantID: result.insertId });
  } catch (err) {
    console.error('Add plant error:', err.message);
    res.status(500).json({ message: 'Could not add plant.' });
  }
});

app.put('/plants/:plantID', authenticate, async (req, res) => {
  const { name, type, description, location, sensorID } = req.body;
  try {
    await pool.query(
      'UPDATE plants SET name = ?, type = ?, description = ?, location = ?, sensorID = ? WHERE plantID = ?',
      [name, type, description, location, sensorID ?? null, req.params.plantID]
    );
    res.json({ message: 'Plant updated.' });
  } catch (err) {
    console.error('Update plant error:', err.message);
    res.status(500).json({ message: 'Could not update plant.' });
  }
});

app.delete('/plants/:plantID', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM plants WHERE plantID = ?', [req.params.plantID]);
    res.json({ message: 'Plant deleted.' });
  } catch (err) {
    console.error('Delete plant error:', err.message);
    res.status(500).json({ message: 'Could not delete plant.' });
  }
});