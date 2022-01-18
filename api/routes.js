const express = require("express");
const router = express.Router();
const passport = require('passport');
const { notFound,home } = require("./controllers/home");
const { register, login } = require("./controllers/userController");


router.get('/', home)
router.post('/register',register)
router.post('/login',login)


router.get('*', notFound)


module.exports = router;