var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')


router.post('/register',async function (req, res, next) {
  let newUser = await userController.CreateAnUser(
    req.body.username,
    req.body.password,
    req.body.email,
    '69a4f929f8d941f2dd234b88'
  )
  
  res.send(newUser)
});
//localhost:3000
router.get('/home', function (req, res, next) {
  res.render('index', { title: 'Express' });
});


module.exports = router;


//mongodb
