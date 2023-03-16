const express = require('express');
const path = require('path');
const bodyParser = require('body-parser')
const mongoose = require('mongoose');
const User = require('./model/user')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'sjkdwejkfjklwebf!$%$&^^&jwevahsvjhvcjhee'



// MONGOOSE CONNECTION
mongoose.connect('mongodb://localhost:27017/login-auth');
var db=mongoose.connection;
db.on('error', console.log.bind(console, "connection error"));
db.once('open', function(callback){
	console.log("connection succeeded");
})

const app = express(); 
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())



 // CHANGING PASSWORDS
 
 app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})



 // LOGIN ROUTE
 
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})

  




// REGISTER ROUTE
app.post('/api/register', async (req, res) => {
    console.log(req.body)
    // res.json({status: 'ok'})


const {username, password: plainTextPassword} =req.body
const password = await bcrypt.hash(plainTextPassword, 10)

try {
    const response = await User.create({
        username,
        password
    })
    console.log('User created successfully:', response)

} catch (error) {
  if (error) throw error;
  if (error.code === 11000) {
    // dupilicate key
    return res.json({ status: 'error', error: 'Username already in use' })
  }
  throw error
}

console.log(await bcrypt.hash(password, 10))

 })

// WHERE AM LISTENING FROM

app.listen(3000);
console.log("listening on PORT 3000");


