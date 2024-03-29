const express = require('express')
const mongodb = require('mongodb')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const swaggerJsdoc = require('swagger-jsdoc')
const swaggerUi = require('swagger-ui-express')
const fs = require('fs');
const app = express()

app.use(express.json())

const port = process.env.PORT || 3005;
const secretKey = 'officeapt';

/*// MongoDB connection URL with username & password
const mongoURL =
  'mongodb+srv://aza:mongoaza@officevms.tilw1nt.mongodb.net/?retryWrites=true&w=majority';*/

// MongoDB connection URL with certificate
const mongoURL =
  'mongodb+srv://officevms.tilw1nt.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites=true&w=majority';

// Add the path to your certificate file
const tlsOptions = {
  sslCA: [fs.readFileSync('C:/Users/HP/Desktop/office2024/X509-cert-2696330171953200812.pem')],
};

// MongoDB database and collections names
const dbName = 'officevms';
const staffCollection = 'staff';
const securityCollection = 'security';
const appointmentCollection = 'appointments';

// Middleware for parsing JSON data
app.use(express.json());

/*// MongoDB connection
mongodb.MongoClient.connect(mongoURL, { useUnifiedTopology: true })
  .then((client) => {
    const db = client.db(dbName);
    staffDB = db.collection(staffCollection);
    securityDB = db.collection(securityCollection);
    appointmentDB = db.collection(appointmentCollection);
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });*/

// MongoDB connection (CERT)
mongodb.MongoClient.connect(mongoURL, {
  useUnifiedTopology: true,
  tls: true,
  tlsCAFile: 'C:/Users/HP/Desktop/office2024/X509-cert-2696330171953200812.pem',
})
  .then((client) => {
    const db = client.db(dbName);
    staffDB = db.collection(staffCollection);
    securityDB = db.collection(securityCollection);
    appointmentDB = db.collection(appointmentCollection);
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
});

// Middleware for authentication and authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Invalid or unauthorized token');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid or expired token');
    }
    req.user = user;
    next();
  });
};

const options = {
  definition: {
      openapi: '3.0.0',
      info: {
          title: 'AZFA Sdn. Bhd. Office Appointment',
          version: '1.0.0',
          description: "Group 13 Developer: \n -Norazizah Binti Zainal Abidin (B022110149) \n -Norfadhila Binti Mohd Azian (B022110143)"
      },
  },
  apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));


app.get('/', (req, res) => {
 res.send('Hello World!')
})

app.listen(port, () => {
 console.log(`Example app listening on port ${port}`)
})

/**
* @swagger
* components:
*   securitySchemes:
*     bearerAuth:
*       type: http
*       scheme: bearer
*       bearerFormat: JWT
*/

/**
* @swagger
* tags:
*   name: Security
*   description: APIs accessible only by security personnel
*/

/**
* @swagger
* tags:
*   name: Staff
*   description: APIs accessible only by staff members
*/

/**
* @swagger
* tags:
*   name: Testing API
*   description: APIs for testing only (will not be saved into the main database)
*/

/**
* @swagger
* /register-staff:
*   post:
*     summary: Register staff
*     tags: [Security]
*     security:
*       - bearerAuth: []
*     requestBody:
*       content:
*         application/json:
*           schema: 
*             type: object
*             properties:
*               username:
*                 type: string
*               password:
*                 type: string
*     responses:
*       200:
*         description: Staff registered successfully
*       403:
*         description: Invalid or unauthorized token
*       409:
*         description: Username already exists
*       500:
*         description: Error registering staff
*/

// Register staff
app.post('/register-staff', authenticateToken, async (req, res) => {
  const { role } = req.user;

  if (role !== 'security') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  const { username, password } = req.body;

  const existingStaff = await staffDB.findOne({ username });

  if (existingStaff) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const staff = {
    username,
    password: hashedPassword,
  };

  staffDB
    .insertOne(staff)
    .then(() => {
      res.status(200).send('Staff registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering staff');
    });
});

/**
* @swagger
* /register-security:
*   post:
*     summary: Register security
*     tags: [Security]
*     requestBody:
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*               password:
*                 type: string
*     responses:
*       200:
*         description: Security registered successfully
*       409:
*         description: Username already exists
*       500:
*         description: Error registering security
*/

// Register security
app.post('/register-security', async (req, res) => {
  const { username, password } = req.body;

  const existingSecurity = await securityDB.findOne({ username });

  if (existingSecurity) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const security = {
    username,
    password: hashedPassword,
  };

  securityDB
    .insertOne(security)
    .then(() => {
      res.status(200).send('Security registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering security');
    });
});

/**
* @swagger
* /login-staff:
*   post:
*     summary: Staff login
*     tags: [Staff]
*     requestBody:
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*               password:
*                 type: string
*     responses:
*       200:
*         description: Staff logged in successfully
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 token:
*                   type: string
*       401:
*         description: Invalid credentials
*       500:
*         description: Error storing token
*/


// Staff login
app.post('/login-staff', async (req, res) => {
  const { username, password } = req.body;

  const staff = await staffDB.findOne({ username });

  if (!staff) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, staff.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username, role: 'staff' }, secretKey);
  staffDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

/**
* @swagger
* /login-security:
*   post:
*     summary: Security login
*     tags: [Security]
*     requestBody:
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*               password:
*                 type: string
*     responses:
*       200:
*         description: Security logged in successfully
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 token:
*                   type: string
*       401:
*         description: Invalid credentials
*       500:
*         description: Error storing token
*/

// Security login
app.post('/login-security', async (req, res) => {
  const { username, password } = req.body;

  const security = await securityDB.findOne({ username });

  if (!security) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, security.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = security.token || jwt.sign({ username, role: 'security' }, secretKey);
  securityDB
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

/**
 * @swagger
 * /appointments:
 *   post:
 *     summary: Create appointment
 *     tags: [Public]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               company:
 *                 type: string
 *               purpose:
 *                 type: string
 *               phoneNo:
 *                 type: string
 *               date:
 *                 type: string
 *               time:
 *                 type: string
 *               staff:
 *                 type: object
 *                 properties:
 *                   username:
 *                     type: string
 *     responses:
 *       200:
 *         description: Appointment created successfully
 *       500:
 *         description: Error creating appointment
 */


// Create appointment
  app.post('/appointments', async (req, res) => {
    const {
      name,
      company,
      purpose,
      phoneNo,
      date,
      time,
      verification,
      staff: { username },
    } = req.body;

    const appointment = {
      name,
      company,
      purpose,
      phoneNo,
      date,
      time,
      verification,
      staff: { username },
    };

    appointmentDB
      .insertOne(appointment)
      .then(() => {
        res.status(200).send('Appointment created successfully');
      })
      .catch((error) => {
        res.status(500).send('Error creating appointment');
      });
  });

/**
* @swagger
* /staff-appointments/{username}:
*   get:
*     summary: Get staff's appointments
*     tags: [Staff]
*     security:
*       - bearerAuth: []
*     parameters:
*       - name: username
*         in: path
*         description: Staff member's username
*         required: true
*         schema:
*           type: string
*     responses:
*       200:
*         description: List of staff's appointments
*       403:
*         description: Invalid or unauthorized token
*       500:
*         description: Error retrieving appointments
*/

// Get staff's appointments
app.get('/staff-appointments/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  if (username !== authenticatedUsername) {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .find({ 'staff.username': username })
    .toArray()
    .then((appointments) => {
      res.json(appointments);
    })
    .catch((error) => {
      res.status(500).send('Error retrieving appointments');
    });
});

/**
* @swagger
* /appointments/{name}:
*   put:
*     summary: Update appointment verification by visitor name
*     tags: [Staff]
*     security:
*       - bearerAuth: []
*     parameters:
*       - name: name
*         in: path
*         description: Visitor's name
*         required: true
*         schema:
*           type: string
*     requestBody:
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               verification:
*                 type: boolean
*     responses:
*       200:
*         description: Appointment verification updated successfully
*       403:
*         description: Invalid or unauthorized token
*       404:
*         description: Appointment not found
*       500:
*         description: Error updating appointment verification
*/

// Update appointment verification by visitor name
app.put('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { verification } = req.body;
  const { role, username: authenticatedUsername } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  // Find the appointment by name and staff username
  const appointment = await appointmentDB.findOne({ name, 'staff.username': authenticatedUsername });

  if (!appointment) {
    return res.status(404).send('Appointment not found');
  }


  // Update the verification only if the staff member matches the creator
  appointmentDB
    .updateOne({ name, 'staff.username': authenticatedUsername }, { $set: { verification } })
    .then(() => {
      res.status(200).send('Appointment verification updated successfully');
    })
    .catch((error) => {
      res.status(500).send('Error updating appointment verification');
    });
});

/**
* @swagger
* /appointments/{name}:
*   delete:
*     summary: Delete appointment
*     tags: [Staff]
*     security:
*       - bearerAuth: []
*     parameters:
*       - name: name
*         in: path
*         description: Visitor's name
*         required: true
*         schema:
*           type: string
*     responses:
*       200:
*         description: Appointment deleted successfully
*       403:
*         description: Invalid or unauthorized token
*       500:
*         description: Error deleting appointment
*/

// Delete appointment
app.delete('/appointments/:name', authenticateToken, async (req, res) => {
  const { name } = req.params;
  const { role } = req.user;

  if (role !== 'staff') {
    return res.status(403).send('Invalid or unauthorized token');
  }

  appointmentDB
    .deleteOne({ name })
    .then(() => {
      res.status(200).send('Appointment deleted successfully');
    })
    .catch((error) => {
      res.status(500).send('Error deleting appointment');
    });
});

/**
* @swagger
* /appointments:
*   get:
*     summary: view appointments using the name used when the appointment was made (visitor)
*     tags: [Public]
*     parameters:
*       - name: name
*         in: query
*         description: Filter appointments by name
*         required: false
*         schema:
*           type: string
*     responses:
*       200:
*         description: List of appointments
*       500:
*         description: Error retrieving appointments
*/

app.get('/appointments', async (req, res) => {
const { name } = req.query;

const filter = name ? { name: { $regex: name, $options: 'i' } } : {};

appointmentDB
  .find(filter)
  .toArray()
  .then((appointments) => {
    res.json(appointments);
  })
  .catch((error) => {
    res.status(500).send('Error retrieving appointments');
  });
});

/*********** TESTING API *******************/

// MongoDB connection URL for testing
const testMongoURL =
  'mongodb+srv://aza:mongoaza@officevms.tilw1nt.mongodb.net/test?retryWrites=true&w=majority';

const testDBName = 'test';
const testStaffCollection = 'staff';
const testSecurityCollection = 'security';
const testAppointmentCollection = 'appointments';

let testStaffDB, testSecurityDB, testAppointmentDB;

mongodb.MongoClient.connect(testMongoURL, { useUnifiedTopology: true })
  .then((client) => {
    const testDB = client.db(testDBName);
    testStaffDB = testDB.collection(testStaffCollection);
    testSecurityDB = testDB.collection(testSecurityCollection);
    testAppointmentDB = testDB.collection(testAppointmentCollection);
  })
  .catch((err) => {
    console.error('Error connecting to test MongoDB:', err);
  });

/**
 * @swagger
 * /test/register-staff:
 *   post:
 *     summary: Register staff (testing)
 *     tags: [Testing API]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Staff registered successfully
 *       409:
 *         description: Username already exists
 *       500:
 *         description: Error registering staff
 */


// Register staff (testing)
app.post('/test/register-staff', async (req, res) => {
  const { username, password } = req.body;

  const existingStaff = await testStaffDB.findOne({ username });

  if (existingStaff) {
    return res.status(409).send('Username already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const staff = {
    username,
    password: hashedPassword,
  };

  testStaffDB
    .insertOne(staff)
    .then(() => {
      res.status(200).send('Staff registered successfully');
    })
    .catch((error) => {
      res.status(500).send('Error registering staff');
    });
});

/**
 * @swagger
 * /test/login-staff:
 *   post:
 *     summary: Staff login (testing)
 *     tags: [Testing API]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Staff logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Error storing token
 */
app.post('/test/login-staff', async (req, res) => {
  const { username, password } = req.body;

  const staff = await testStaffDB.findOne({ username });

  if (!staff) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, staff.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username, role: 'staff' }, secretKey);
  testStaffDB // Use the testing database collection
    .updateOne({ username }, { $set: { token } })
    .then(() => {
      res.status(200).json({ token });
    })
    .catch(() => {
      res.status(500).send('Error storing token');
    });
});

