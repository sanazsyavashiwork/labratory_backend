const cors = require('cors');
require("dotenv").config();
const express = require('express');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const moment = require('moment');


const { neon } = require("@neondatabase/serverless");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }))

app.use(cors({
  origin: 'http://localhost:3000',
}));
const sql = neon(process.env.DATABASE_URL);
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 600
}));

//return lists of books
app.get('/login/', async (request, response) => {
  const result = await sql`SELECT * from library`;
  response.send(result)
})


app.post('/login', async (req, res) => {
  const { username, password } = req.body;


  const user = await sql`SELECT * from users WHERE users.username=${username} `
  if (user.length > 0) {
    if (username === user[0].username && password === user[0].password) {
      const payload = { id: user[0].id, username: user[0].username };
      const token = jwt.sign(payload, 'mySecretKey', { expiresIn: '8h' });
      res.json({ token, role: user[0].role });
    } else {
      res.status(401).json({ message: 'Invalid Username Or Password' });
    }
  } else {
    res.status(401).json({ message: 'Invalid Username Or Password' });
  }
})

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, 'mySecretKey', (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

app.post('/changePassword', authenticateJWT, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    const user = await sql`SELECT * FROM users WHERE id=${userId}`;

    if (user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    if (oldPassword !== user[0].password) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    await sql`UPDATE users SET password=${newPassword} WHERE id=${userId}`;

    res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get('/users', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  try {
    const user = await sql`SELECT * FROM users WHERE id=${userId}`;
    if (user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user[0].role != 'admin') {
      return res.status(403).json({ message: "You don't have enough permission " });
    } else {
      const users = await sql`SELECT * from users WHERE users.role='user'`;
      if (!users) {
        res.status(404).send("Users not found!")
        return;
      }
      const filteredUsers = users.map((user) => {
        const { password, username, role, ...rest } = user;
        return rest;
      });
      res.send(filteredUsers)
    }
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
})

app.post('/users', authenticateJWT, async (req, res) => {
  const { newUserName, firstname, lastname, age, emailaddress, phonenumber, newPassword, sex } = req.body;
  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role !== 'admin') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }

  if (!newUserName || !firstname || !lastname || !age || !emailaddress || !phonenumber || !newPassword || !sex) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    await sql`
      INSERT INTO users (username, firstname, lastname, age, emailaddress, phonenumber, password, sex,role)
      VALUES (${newUserName}, ${firstname}, ${lastname}, ${age}, ${emailaddress}, ${phonenumber}, ${newPassword}, ${sex},'user')
    `;

    res.status(201).json({ message: "User created successfully" });
  }
  catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.put('/user/:id/', authenticateJWT, async (req, res) => {
  const { firstname, lastname, age, emailaddress, phonenumber, sex } = req.body;
  const id = +req.params.id

  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  const selectedUser = await sql`SELECT * FROM users WHERE id=${id}`
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (!selectedUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role !== 'admin') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }

  if (!firstname || !lastname || !age || !emailaddress || !phonenumber || !sex) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {

    await sql`
    UPDATE users
SET 
    firstname = ${firstname},
    lastname = ${lastname},
    age = ${age},
    emailaddress = ${emailaddress},
    phonenumber = ${phonenumber},
    sex = ${sex}
WHERE users.id = ${id};
    `

    res.status(201).json({ message: "User created successfully" });
  }
  catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete('/user/:id/', authenticateJWT, async (req, res) => {
  const id = +req.params.id

  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  const selectedUser = await sql`SELECT * FROM users WHERE id=${id}`
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (!selectedUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role !== 'admin') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }


  try {

    await sql`
    DELETE  from users
WHERE users.id = ${id};
    `

    res.status(204).json({ message: "User deleted successfully" });
  }
  catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
//-------------------------------------------------------------------------------------------
app.get('/guests/:search?/', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const search = req?.params?.search
  try {

    const user = await sql`SELECT * FROM users WHERE id=${userId}`;
    if (user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user[0].role == 'user') {
      return res.status(403).json({ message: "You don't have enough permission " });
    } else {
      let users;
      if (!search) {
        users = await sql`SELECT * from users WHERE users.role='guest'`;
      } else {
        const searchTerms = search.trim().split(/\s+/);

        if (searchTerms.length === 1) {
          users = await sql`
            SELECT * from users 
            WHERE users.role='guest' 
            AND users.firstname  ILIKE ${'%' + search + '%'}
          `;
          if (users.length === 0) {
            users = await sql`
            SELECT * from users 
            WHERE users.role='guest' 
            AND users.lastname  ILIKE ${'%' + search + '%'}
          `;
          }
        } else if (searchTerms.length === 2) {
          const [firstName, lastName] = searchTerms;

          users = await sql`
            SELECT * from users 
            WHERE users.role='guest' 
            AND users.firstname  ILIKE ${'%' + firstName + '%'}
            AND users.lastname  ILIKE ${'%' + lastName + '%'}
          `;
        }
      }
      if (!users) {
        res.status(404).send("Users not found!")
        return;
      }
      const filteredUsers = users.map((user) => {
        const { password, role, ...rest } = user;
        return rest;
      });
      res.send(filteredUsers)
    }
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: "Internal server error" });
  }
})

app.post('/guests', authenticateJWT, async (req, res) => {
  const { newUserName, firstname, lastname, age, emailaddress, phonenumber, newPassword, sex } = req.body;
  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role === 'guest') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }

  if (!newUserName || !firstname || !lastname || !age || !emailaddress || !phonenumber || !newPassword || !sex) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    await sql`
      INSERT INTO users (username, firstname, lastname, age, emailaddress, phonenumber, password, sex,role)
      VALUES (${newUserName}, ${firstname}, ${lastname}, ${age}, ${emailaddress}, ${phonenumber}, ${newPassword}, ${sex},'guest')
    `;

    res.status(201).json({ message: "User created successfully" });
  }
  catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.put('/guest/:id/', authenticateJWT, async (req, res) => {
  const { firstname, lastname, age, emailaddress, phonenumber, sex } = req.body;
  const id = +req.params.id

  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  const selectedUser = await sql`SELECT * FROM users WHERE id=${id}`
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (!selectedUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role === 'guest') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }

  if (!firstname || !lastname || !age || !emailaddress || !phonenumber || !sex) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {

    await sql`
    UPDATE users
SET 
    firstname = ${firstname},
    lastname = ${lastname},
    age = ${age},
    emailaddress = ${emailaddress},
    phonenumber = ${phonenumber},
    sex = ${sex}
WHERE users.id = ${id};
    `

    res.status(201).json({ message: "User created successfully" });
  }
  catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete('/guest/:id/', authenticateJWT, async (req, res) => {
  const id = +req.params.id

  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  const selectedUser = await sql`SELECT * FROM users WHERE id=${id}`
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (!selectedUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role === 'guest') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }


  try {

    await sql`
    DELETE  from users
WHERE users.id = ${id};
    `

    res.status(204).json({ message: "User deleted successfully" });
  }
  catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//---------------------------------------------------------------------------
app.get('/tests-scheduled/:search?/', authenticateJWT, async (req, res) => {
  const search = req?.params?.search

  const currentUserId = req.user.id;

  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
    else {
      let testHeadersWithUsernames;
      if (!search) {
        testHeadersWithUsernames = await sql`
        SELECT 
          scheduledtest.*,
          u1.username AS user_username,
          u2.username AS guest_username
        FROM scheduledtest
        LEFT JOIN users u1 ON scheduledtest.userid = u1.id
        LEFT JOIN users u2 ON scheduledtest.guestid = u2.id
      `;
      } else {
        testHeadersWithUsernames = await sql`
           SELECT 
          scheduledtest.*,
          u1.username AS user_username,
          u2.username AS guest_username
        FROM scheduledtest
        LEFT JOIN users u1 ON scheduledtest.userid = u1.id
        LEFT JOIN users u2 ON scheduledtest.guestid = u2.id
        WHERE u1.username ILIKE ${'%' + search + '%'} or u2.username ILIKE ${'%' + search + '%'}
          `;
      }

      if (testHeadersWithUsernames.length === 0) {
        return res.status(404).json({ message: "No test headers found" });
      }

      const formattedTestHeaders = testHeadersWithUsernames.map(testHeader => {
        return {
          ...testHeader,
          reservationdate: moment(testHeader.reservationdate).format('YYYY-MM-DD'),
          testdate: moment(testHeader.testdate).format('YYYY-MM-DD')
        };
      });

      res.json(formattedTestHeaders);
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//------------------------------------------------------------------------------------
app.post('/test-scheduled/', authenticateJWT, async (req, res) => {
  const { guest_username, testdate, testtype } = req.body;
  const currentUserId = req.user.id;
  const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
  if (!currentUser.length) {
    return res.status(404).json({ message: "User not found" });
  }
  if (currentUser[0].role === 'guest') {
    return res.status(403).json({ message: "You don't have enough permission" });
  }

  if (!guest_username || !testdate || !testtype) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const guestUser = await sql`SELECT users.id FROM users WHERE username=${guest_username}`;
  const ReservationDate = new Date().toISOString();
  if (!guestUser.length) {
    return res.status(404).json({ message: "Guest user not found" });
  }
  const guestId = guestUser[0].id;
  try {
    await sql`
      INSERT INTO scheduledtest (userid, guestid, reservationdate, TestDate, testtype)
      VALUES (${currentUserId}, ${guestId}, ${ReservationDate}, ${testdate}, ${testtype})
    `;

    res.status(201).json({ message: "scheduled Tests created successfully" });
  }
  catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//-----------------------------------------------------------------------

app.put('/test-scheduled/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const { guest_username, testdate, testtype } = req.body;
    const currentUserId = req.user.id;


    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }

    const existingTest = await sql`SELECT * FROM scheduledtest WHERE testid=${id}`;
    if (!existingTest.length) {
      return res.status(404).json({ message: "Test not found" });
    }

    if (!guest_username || !testdate || !testtype) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const guestUser = await sql`SELECT users.id FROM users WHERE username=${guest_username}`;
    if (!guestUser.length) {
      return res.status(404).json({ message: "Guest user not found" });
    }
    const guestId = guestUser[0].id;

    await sql`
      UPDATE scheduledtest 
      SET 
        guestid = ${guestId},
        TestDate = ${testdate},
        testtype = ${testtype}
      WHERE testid = ${id}
    `;

    res.json({ message: "Test schedule updated successfully" });
  } catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//-------------------------------------------------------------------------------------
app.delete('/test-scheduled/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const currentUserId = req.user.id;

    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }

    const existingTest = await sql`SELECT * FROM scheduledtest WHERE testid=${id}`;
    if (!existingTest.length) {
      return res.status(404).json({ message: "Test not found" });
    }




    await sql`
     DELETE  from scheduledtest
WHERE testid = ${id};
    `;

    res.status(204).json({ message: "User deleted successfully" });
  } catch (error) {
    if (error.code === '23505') {
      const duplicateField = error.detail.match(/\((.*?)\)/)[1];
      return res.status(400).json({
        message: `Duplicate entry detected for field: ${duplicateField}`
      });
    }
    console.error("Server error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//---------------------------------------------------------------------------

app.get('/guest', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  try {

    const user = await sql`SELECT * FROM users WHERE id=${userId}`;
    if (user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user[0].role == 'user') {
      return res.status(403).json({ message: "You don't have enough permission " });
    } else {
      const users = await sql`SELECT users.username from users WHERE users.role='guest'`;
      if (!users) {
        res.status(404).send("Users not found!")
        return;
      }
      const filteredUsers = users.map((user) => {
        const { password, role, ...rest } = user;
        return rest;
      });
      res.send(filteredUsers)
    }
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: "Internal server error" });
  }
})
//------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------
app.get('/tests-header/:search?/', authenticateJWT, async (req, res) => {
  const search = req?.params?.search

  const currentUserId = req.user.id;

  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
    else {
      let testHeadersWithUsernames;
      if (!search) {
        testHeadersWithUsernames = await sql`
           SELECT 
              th.testid,
              th.userid,
              th.guestid,
              th.testdate,
              th.testtype,
              th.status,
              th.createdat,
              th.description,
              u1.username AS user_username,
              u2.username AS guest_username,
              CASE 
                  WHEN th.testtype = 'CBC' THEN 
                      json_build_object(
                          'resultid', cbc.resultid,
                          'wbc', cbc.wbc,
                          'rbc', cbc.rbc,
                          'hemoglobin', cbc.hemoglobin,
                          'hematocrit', cbc.hematocrit,
                          'platelets', cbc.platelets
                      )
                  WHEN th.testtype = 'BCT' THEN 
                      json_build_object(
                          'resultid', bct.resultid,
                          'fasting_glucose', bct.fasting_glucose,
                          'random_glucose', bct.random_glucose,
                          'hba1c', bct.hba1c
                      )
                  WHEN th.testtype = 'LP' THEN 
                      json_build_object(
                          'resultid', lp.resultid,
                          'total_cholesterol', lp.total_cholesterol,
                          'hdl', lp.hdl,
                          'ldl', lp.ldl,
                          'triglycerides', lp.triglycerides
                      )
                  WHEN th.testtype = 'LFT' THEN 
                      json_build_object(
                          'resultid', lft.resultid,
                          'alt', lft.alt,
                          'ast', lft.ast,
                          'alp', lft.alp,
                          'total_bilirubin', lft.total_bilirubin,
                          'albumin', lft.albumin
                      )
              END AS test_results
          FROM testheader th
          LEFT JOIN users u1 ON th.userid = u1.id
          LEFT JOIN users u2 ON th.guestid = u2.id
          LEFT JOIN cbc_results cbc ON th.testid = cbc.testid AND th.testtype = 'CBC'
          LEFT JOIN bct_results bct ON th.testid = bct.testid AND th.testtype = 'BCT'
          LEFT JOIN lp_results lp ON th.testid = lp.testid AND th.testtype = 'LP'
          LEFT JOIN lft_results lft ON th.testid = lft.testid AND th.testtype = 'LFT'
      `;
      } else {
        testHeadersWithUsernames = await sql`
           SELECT 
              th.testid,
              th.userid,
              th.guestid,
              th.testdate,
              th.testtype,
              th.status,
              th.createdat,
              th.description,
              u1.username AS user_username,
              u2.username AS guest_username,
              CASE 
                  WHEN th.testtype = 'CBC' THEN 
                      json_build_object(
                          'resultid', cbc.resultid,
                          'wbc', cbc.wbc,
                          'rbc', cbc.rbc,
                          'hemoglobin', cbc.hemoglobin,
                          'hematocrit', cbc.hematocrit,
                          'platelets', cbc.platelets
                      )
                  WHEN th.testtype = 'BCT' THEN 
                      json_build_object(
                          'resultid', bct.resultid,
                          'fasting_glucose', bct.fasting_glucose,
                          'random_glucose', bct.random_glucose,
                          'hba1c', bct.hba1c
                      )
                  WHEN th.testtype = 'LP' THEN 
                      json_build_object(
                          'resultid', lp.resultid,
                          'total_cholesterol', lp.total_cholesterol,
                          'hdl', lp.hdl,
                          'ldl', lp.ldl,
                          'triglycerides', lp.triglycerides
                      )
                  WHEN th.testtype = 'LFT' THEN 
                      json_build_object(
                          'resultid', lft.resultid,
                          'alt', lft.alt,
                          'ast', lft.ast,
                          'alp', lft.alp,
                          'total_bilirubin', lft.total_bilirubin,
                          'albumin', lft.albumin
                      )
              END AS test_results
          FROM testheader th
          LEFT JOIN users u1 ON th.userid = u1.id
          LEFT JOIN users u2 ON th.guestid = u2.id
          LEFT JOIN cbc_results cbc ON th.testid = cbc.testid AND th.testtype = 'CBC'
          LEFT JOIN bct_results bct ON th.testid = bct.testid AND th.testtype = 'BCT'
          LEFT JOIN lp_results lp ON th.testid = lp.testid AND th.testtype = 'LP'
          LEFT JOIN lft_results lft ON th.testid = lft.testid AND th.testtype = 'LFT'
        WHERE u1.username ILIKE ${'%' + search + '%'} or u2.username ILIKE ${'%' + search + '%'}
          `;
      }

      if (testHeadersWithUsernames.length === 0) {
        return res.status(404).json({ message: "No test headers found" });
      }


      const formattedTestHeaders = testHeadersWithUsernames.map(testHeader => {
        return {
          ...testHeader,
          testdate: moment(testHeader.testdate).format('YYYY-MM-DD')
        };
      });

      res.json(formattedTestHeaders);
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//------------------------------------------------------------------------------------
app.post('/test-header', authenticateJWT, async (req, res) => {
  const currentUserId = req.user.id;
  const { userid, guestid, testdate, testtype, testResults } = req.body;
 
  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
 
    // اول رکورد را در testheader با وضعیت Pending ایجاد می‌کنیم
    const newTestHeader = await sql`
      INSERT INTO testheader 
      (userid, guestid, testdate, testtype, status)
      VALUES
      (${userid}, ${guestid}, ${testdate}, ${testtype}, 'Pending')
      RETURNING testid
    `;
 
    const testid = newTestHeader[0].testid;
 
    // درج نتایج تست بر اساس نوع آن
    if (testResults) {
      let updateStatusQuery;
      
      switch (testtype) {
        case 'CBC':
          await sql`
            INSERT INTO cbc_results (testid, wbc, rbc, hemoglobin, hematocrit, platelets)
            VALUES (${testid}, ${testResults.wbc}, ${testResults.rbc}, 
                    ${testResults.hemoglobin}, ${testResults.hematocrit}, ${testResults.platelets})
          `;
          
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN wbc < 3.5 OR wbc > 11.0 OR hemoglobin < 10 OR platelets < 100000 THEN 'Critical'
                  WHEN wbc NOT BETWEEN 4.5 AND 11.0 
                    OR rbc NOT BETWEEN 4.2 AND 5.4 
                    OR hemoglobin NOT BETWEEN 13.0 AND 17.0 
                    OR hematocrit NOT BETWEEN 38.0 AND 48.0 
                    OR platelets NOT BETWEEN 150000 AND 450000 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM cbc_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
 
        case 'BCT':
          await sql`
            INSERT INTO bct_results (testid, fasting_glucose, random_glucose, hba1c)
            VALUES (${testid}, ${testResults.fasting_glucose}, 
                    ${testResults.random_glucose}, ${testResults.hba1c})
          `;
          
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN fasting_glucose > 126 OR random_glucose > 200 OR hba1c > 6.5 THEN 'Critical'
                  WHEN fasting_glucose >= 100 OR random_glucose >= 140 OR hba1c >= 5.7 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM bct_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
 
        case 'LP':
          await sql`
            INSERT INTO lp_results (testid, total_cholesterol, hdl, ldl, triglycerides)
            VALUES (${testid}, ${testResults.total_cholesterol}, ${testResults.hdl}, 
                    ${testResults.ldl}, ${testResults.triglycerides})
          `;
          
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN total_cholesterol > 300 OR triglycerides > 500 THEN 'Critical'
                  WHEN total_cholesterol > 200 
                    OR hdl < 40 
                    OR ldl > 130 
                    OR triglycerides > 150 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM lp_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
 
        case 'LFT':
          await sql`
            INSERT INTO lft_results (testid, alt, ast, alp, total_bilirubin, albumin)
            VALUES (${testid}, ${testResults.alt}, ${testResults.ast}, ${testResults.alp}, 
                    ${testResults.total_bilirubin}, ${testResults.albumin})
          `;
          
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN alt > 200 OR ast > 200 OR total_bilirubin > 3 THEN 'Critical'
                  WHEN alt NOT BETWEEN 7 AND 56 
                    OR ast NOT BETWEEN 10 AND 40
                    OR alp NOT BETWEEN 44 AND 147
                    OR total_bilirubin NOT BETWEEN 0.3 AND 1.2
                    OR albumin NOT BETWEEN 3.4 AND 5.4 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM lft_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
      }
 
      await updateStatusQuery;
    }
 
    res.status(201).json({ message: "Test result created successfully", testid });
  } catch (error) {
    console.error('Error details:', error);
    res.status(500).json({ message: "Internal server error" });
  }
 });

 //---------------------------------------------------------------------------------------------------
// PUT - Update existing test result
app.put('/test-header/:testid', authenticateJWT, async (req, res) => {
  const currentUserId = req.user.id;
  const testid = req.params.testid;
  const { testtype, testResults } = req.body;

  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }

    // اول آپدیت نتایج تست
    if (testResults) {
      switch (testtype) {
        case 'CBC':
          await sql`
            UPDATE cbc_results 
            SET wbc=${testResults.wbc}, rbc=${testResults.rbc}, 
                hemoglobin=${testResults.hemoglobin}, 
                hematocrit=${testResults.hematocrit}, 
                platelets=${testResults.platelets}
            WHERE testid=${testid}
          `;
          break;
        case 'BCT':
          await sql`
            UPDATE bct_results 
            SET fasting_glucose=${testResults.fasting_glucose}, 
                random_glucose=${testResults.random_glucose}, 
                hba1c=${testResults.hba1c}
            WHERE testid=${testid}
          `;
          break;
        case 'LP':
          await sql`
            UPDATE lp_results 
            SET total_cholesterol=${testResults.total_cholesterol}, 
                hdl=${testResults.hdl}, ldl=${testResults.ldl}, 
                triglycerides=${testResults.triglycerides}
            WHERE testid=${testid}
          `;
          break;
        case 'LFT':
          await sql`
            UPDATE lft_results 
            SET alt=${testResults.alt}, ast=${testResults.ast}, 
                alp=${testResults.alp}, 
                total_bilirubin=${testResults.total_bilirubin}, 
                albumin=${testResults.albumin}
            WHERE testid=${testid}
          `;
          break;
      }

      let updateStatusQuery;
      switch (testtype) {
        case 'BCT':
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN fasting_glucose > 126 OR random_glucose > 200 OR hba1c > 6.5 THEN 'Critical'
                  WHEN fasting_glucose >= 100 OR random_glucose >= 140 OR hba1c >= 5.7 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM bct_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
        case 'CBC':
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN wbc < 3.5 OR wbc > 11.0 OR hemoglobin < 10 OR platelets < 100000 THEN 'Critical'
                  WHEN wbc NOT BETWEEN 4.5 AND 11.0 
                    OR rbc NOT BETWEEN 4.2 AND 5.4 
                    OR hemoglobin NOT BETWEEN 13.0 AND 17.0 
                    OR hematocrit NOT BETWEEN 38.0 AND 48.0 
                    OR platelets NOT BETWEEN 150000 AND 450000 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM cbc_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
        case 'LP':
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN total_cholesterol > 300 OR triglycerides > 500 THEN 'Critical'
                  WHEN total_cholesterol > 200 
                    OR hdl < 40 
                    OR ldl > 130 
                    OR triglycerides > 150 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM lp_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
        case 'LFT':
          updateStatusQuery = sql`
            UPDATE testheader 
            SET status = (
              SELECT 
                CASE 
                  WHEN alt > 200 OR ast > 200 OR total_bilirubin > 3 THEN 'Critical'
                  WHEN alt NOT BETWEEN 7 AND 56 
                    OR ast NOT BETWEEN 10 AND 40
                    OR alp NOT BETWEEN 44 AND 147
                    OR total_bilirubin NOT BETWEEN 0.3 AND 1.2
                    OR albumin NOT BETWEEN 3.4 AND 5.4 THEN 'Abnormal'
                  ELSE 'Normal'
                END 
              FROM lft_results 
              WHERE testid=${testid}
            )
            WHERE testid=${testid}
          `;
          break;
      }

      await updateStatusQuery;
    }

    res.json({ message: "Test result updated successfully" });
  } catch (error) {
    console.error('Detailed error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//-------------------------------------------------------------------------------------
// DELETE - Delete test result
app.delete('/test-header/:testid', authenticateJWT, async (req, res) => {
  const currentUserId = req.user.id;
  const testid = req.params.testid;

  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }

    const testHeader = await sql`SELECT testtype FROM testheader WHERE testid=${testid}`;
    if (testHeader.length > 0) {
      switch (testHeader[0].testtype) {
        case 'CBC':
          await sql`DELETE FROM cbc_results WHERE testid=${testid}`;
          break;
        case 'BCT':
          await sql`DELETE FROM bct_results WHERE testid=${testid}`;
          break;
        case 'LP':
          await sql`DELETE FROM lp_results WHERE testid=${testid}`;
          break;
        case 'LFT':
          await sql`DELETE FROM lft_results WHERE testid=${testid}`;
          break;
      }
    }

    await sql`DELETE FROM testheader WHERE testid=${testid}`;

    res.json({ message: "Test result deleted successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//----------------------------------------------------------------------------------------------

app.get('/tests-header-guest/', authenticateJWT, async (req, res) => {

  const currentUserId = req.user.id;

  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role !== 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
    else {
      let testHeadersWithUsernames = await sql`
           SELECT 
              th.testid,
              th.userid,
              th.guestid,
              th.testdate,
              th.testtype,
              th.status,
              th.createdat,
              th.description,
              u1.username AS user_username,
              CASE 
                  WHEN th.testtype = 'CBC' THEN 
                      json_build_object(
                          'resultid', cbc.resultid,
                          'wbc', cbc.wbc,
                          'rbc', cbc.rbc,
                          'hemoglobin', cbc.hemoglobin,
                          'hematocrit', cbc.hematocrit,
                          'platelets', cbc.platelets
                      )
                  WHEN th.testtype = 'BCT' THEN 
                      json_build_object(
                          'resultid', bct.resultid,
                          'fasting_glucose', bct.fasting_glucose,
                          'random_glucose', bct.random_glucose,
                          'hba1c', bct.hba1c
                      )
                  WHEN th.testtype = 'LP' THEN 
                      json_build_object(
                          'resultid', lp.resultid,
                          'total_cholesterol', lp.total_cholesterol,
                          'hdl', lp.hdl,
                          'ldl', lp.ldl,
                          'triglycerides', lp.triglycerides
                      )
                  WHEN th.testtype = 'LFT' THEN 
                      json_build_object(
                          'resultid', lft.resultid,
                          'alt', lft.alt,
                          'ast', lft.ast,
                          'alp', lft.alp,
                          'total_bilirubin', lft.total_bilirubin,
                          'albumin', lft.albumin
                      )
              END AS test_results
          FROM testheader th
          LEFT JOIN users u1 ON th.userid = u1.id
          LEFT JOIN users u2 ON th.guestid = u2.id
          LEFT JOIN cbc_results cbc ON th.testid = cbc.testid AND th.testtype = 'CBC'
          LEFT JOIN bct_results bct ON th.testid = bct.testid AND th.testtype = 'BCT'
          LEFT JOIN lp_results lp ON th.testid = lp.testid AND th.testtype = 'LP'
          LEFT JOIN lft_results lft ON th.testid = lft.testid AND th.testtype = 'LFT'
          where th.guestid = ${currentUserId}
      `;
      if (testHeadersWithUsernames.length === 0) {
        return res.status(404).json({ message: "No test headers found" });
      }


      const formattedTestHeaders = testHeadersWithUsernames.map(testHeader => {
        return {
          ...testHeader,
          testdate: moment(testHeader.testdate).format('YYYY-MM-DD')
        };
      });

      res.json(formattedTestHeaders);
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
//----------------------------------------------------------------------------------------
app.get('/tests-header-guest/:testid', authenticateJWT, async (req, res) => {

  const currentUserId = req.user.id;

  const testid = req.params.testid;


  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role !== 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
    else {
      let testHeadersWithUsernames = await sql`
           SELECT 
              th.testid,
              th.userid,
              th.guestid,
              th.testdate,
              th.testtype,
              th.status,
              th.createdat,
              th.description,
              u1.username AS user_username,
              CASE 
                  WHEN th.testtype = 'CBC' THEN 
                      json_build_object(
                          'resultid', cbc.resultid,
                          'wbc', cbc.wbc,
                          'rbc', cbc.rbc,
                          'hemoglobin', cbc.hemoglobin,
                          'hematocrit', cbc.hematocrit,
                          'platelets', cbc.platelets
                      )
                  WHEN th.testtype = 'BCT' THEN 
                      json_build_object(
                          'resultid', bct.resultid,
                          'fasting_glucose', bct.fasting_glucose,
                          'random_glucose', bct.random_glucose,
                          'hba1c', bct.hba1c
                      )
                  WHEN th.testtype = 'LP' THEN 
                      json_build_object(
                          'resultid', lp.resultid,
                          'total_cholesterol', lp.total_cholesterol,
                          'hdl', lp.hdl,
                          'ldl', lp.ldl,
                          'triglycerides', lp.triglycerides
                      )
                  WHEN th.testtype = 'LFT' THEN 
                      json_build_object(
                          'resultid', lft.resultid,
                          'alt', lft.alt,
                          'ast', lft.ast,
                          'alp', lft.alp,
                          'total_bilirubin', lft.total_bilirubin,
                          'albumin', lft.albumin
                      )
              END AS test_results
          FROM testheader th
          LEFT JOIN users u1 ON th.userid = u1.id
          LEFT JOIN users u2 ON th.guestid = u2.id
          LEFT JOIN cbc_results cbc ON th.testid = cbc.testid AND th.testtype = 'CBC'
          LEFT JOIN bct_results bct ON th.testid = bct.testid AND th.testtype = 'BCT'
          LEFT JOIN lp_results lp ON th.testid = lp.testid AND th.testtype = 'LP'
          LEFT JOIN lft_results lft ON th.testid = lft.testid AND th.testtype = 'LFT'
          where th.guestid = ${currentUserId} and th.testid=${testid}
      `;
      if (testHeadersWithUsernames.length === 0) {
        return res.status(404).json({ message: "No test headers found" });
      }


      const formattedTestHeaders = testHeadersWithUsernames.map(testHeader => {
        return {
          ...testHeader,
          testdate: moment(testHeader.testdate).format('YYYY-MM-DD')
        };
      });

      res.json(formattedTestHeaders);
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//----------------------------------------------------------------------------------------------
app.get('/test-header/:testid', authenticateJWT, async (req, res) => {

  const currentUserId = req.user.id;

  const testid = req.params.testid;


  try {
    const currentUser = await sql`SELECT * FROM users WHERE id=${currentUserId}`;
    if (!currentUser.length) {
      return res.status(404).json({ message: "User not found" });
    }
    if (currentUser[0].role === 'guest') {
      return res.status(403).json({ message: "You don't have enough permission" });
    }
    else {
      let testHeadersWithUsernames = await sql`
           SELECT 
              th.testid,
              th.userid,
              th.guestid,
              th.testdate,
              th.testtype,
              th.status,
              th.createdat,
              th.description,
              u1.username AS user_username,
              u2.*,
              CASE 
                  WHEN th.testtype = 'CBC' THEN 
                      json_build_object(
                          'resultid', cbc.resultid,
                          'wbc', cbc.wbc,
                          'rbc', cbc.rbc,
                          'hemoglobin', cbc.hemoglobin,
                          'hematocrit', cbc.hematocrit,
                          'platelets', cbc.platelets
                      )
                  WHEN th.testtype = 'BCT' THEN 
                      json_build_object(
                          'resultid', bct.resultid,
                          'fasting_glucose', bct.fasting_glucose,
                          'random_glucose', bct.random_glucose,
                          'hba1c', bct.hba1c
                      )
                  WHEN th.testtype = 'LP' THEN 
                      json_build_object(
                          'resultid', lp.resultid,
                          'total_cholesterol', lp.total_cholesterol,
                          'hdl', lp.hdl,
                          'ldl', lp.ldl,
                          'triglycerides', lp.triglycerides
                      )
                  WHEN th.testtype = 'LFT' THEN 
                      json_build_object(
                          'resultid', lft.resultid,
                          'alt', lft.alt,
                          'ast', lft.ast,
                          'alp', lft.alp,
                          'total_bilirubin', lft.total_bilirubin,
                          'albumin', lft.albumin
                      )
              END AS test_results
          FROM testheader th
          LEFT JOIN users u1 ON th.userid = u1.id
          LEFT JOIN users u2 ON th.guestid = u2.id
          LEFT JOIN cbc_results cbc ON th.testid = cbc.testid AND th.testtype = 'CBC'
          LEFT JOIN bct_results bct ON th.testid = bct.testid AND th.testtype = 'BCT'
          LEFT JOIN lp_results lp ON th.testid = lp.testid AND th.testtype = 'LP'
          LEFT JOIN lft_results lft ON th.testid = lft.testid AND th.testtype = 'LFT'
          where th.testid=${testid}
      `;
      if (testHeadersWithUsernames.length === 0) {
        return res.status(404).json({ message: "No test headers found" });
      }


      const formattedTestHeaders = testHeadersWithUsernames.map(testHeader => {
        return {
          ...testHeader,
          testdate: moment(testHeader.testdate).format('YYYY-MM-DD')
        };
      });

      res.json(formattedTestHeaders);
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
  }
});



app.listen(process.env.PORT, () => console.log(`My app is listening at http://localhost:${process.env.PORT}`))








