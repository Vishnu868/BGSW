const express = require('express')
const _ = require('lodash')
const app = express()
// users: { email, password, cardNumber }
app.post('/api/login', (req, res) => res.json(_.pick(req.body, ['email', 'password'])))
app.post('/api/payment', (req, res) => res.json({ ok: true, card: req.body.cardNumber }))
app.listen(3000)
