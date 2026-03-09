var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')
let nodemailer = require('nodemailer')
let userModel = require('../schemas/users');

router.post('/register', async function (req, res, next) {
  let newUser = await userController.CreateAnUser(
    req.body.username,
    req.body.password,
    req.body.email,
    '69a4f929f8d941f2dd234b88'
  )
  res.send(newUser)
});
router.post('/login', async function (req, res, next) {
  let { username, password } = req.body;
  let getUser = await userController.FindByUsername(username);
  if (!getUser) {
    res.status(404).send({
      message: "username khong ton tai hoac thong tin dang nhap sai"
    })
    return;
  }
  let result = bcrypt.compareSync(password, getUser.password);
  if (result) {
    let token = jwt.sign({
      id: getUser._id,
      exp: Date.now() + 3600 * 1000
    }, "HUTECH")
    res.send(token)
  } else {
    res.status(404).send({
      message: "username khong ton tai hoac thong tin dang nhap sai"
    })
  }
});
//localhost:3000
router.get('/me', checkLogin, async function (req, res, next) {
    let user = await userController.FindByID(req.userId);
    res.send(user)
});

router.post('/forgot-password', async function (req, res, next) {
  try {
    let { email } = req.body;
    
    // 1. Tìm user theo email
    let user = await userModel.findOne({ email: email, isDeleted: false });
    if (!user) {
      return res.status(404).send({ message: "Email không tồn tại trong hệ thống!" });
    }

    // 2. Tạo token xác thực (hết hạn trong 15 phút)
    let resetToken = jwt.sign({ id: user._id }, "HUTECH_RESET", { expiresIn: '15m' });

    // 3. Cấu hình Mailtrap của bạn
    var transport = nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 2525,
      auth: {
        user: "c140806d2f3f3f",
        pass: "c1e3e5f797c34e"
      }
    });

    let mailOptions = {
      from: '"Hệ thống Admin" <admin@hutech.edu.vn>',
      to: email,
      subject: "Mã xác nhận khôi phục mật khẩu",
      html: `<p>Xin chào <b>${user.username}</b>,</p>
             <p>Bạn đã yêu cầu đặt lại mật khẩu. Vui lòng sử dụng mã Token dưới đây để tiến hành đổi mật khẩu (Mã có hiệu lực trong 15 phút):</p>
             <h3 style="color: blue; word-break: break-all;">${resetToken}</h3>
             <p>Vui lòng gửi POST request kèm <b>token</b> và <b>newPassword</b> đến API /auth/reset-password để hoàn tất.</p>`
    };

    // 4. Gửi mail
    await transport.sendMail(mailOptions);
    res.send({ message: "Gửi mail thành công! Vui lòng kiểm tra Mailtrap để lấy mã xác nhận." });

  } catch (error) {
    res.status(500).send({ message: "Lỗi hệ thống: " + error.message });
  }
});

router.post('/reset-password', async function (req, res, next) {
  try {
    let { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).send({ message: "Vui lòng cung cấp đủ token và newPassword!" });
    }

    // 1. Xác thực token xem có đúng không, có bị hết hạn chưa
    let decoded;
    try {
        decoded = jwt.verify(token, "HUTECH_RESET");
    } catch (err) {
        return res.status(403).send({ message: "Token không hợp lệ hoặc đã hết hạn!" });
    }

    // 2. Tìm user từ ID giải mã được
    let user = await userModel.findById(decoded.id);
    if (!user) {
      return res.status(404).send({ message: "Không tìm thấy người dùng!" });
    }

    // 3. Cập nhật và lưu vào Database
    user.password = newPassword; // Lưu mật khẩu mới (sẽ được hash trong pre-save hook của Mongoose)
    await user.save();

    res.send({ message: "Đổi mật khẩu thành công! Bạn có thể dùng mật khẩu mới để đăng nhập." });

  } catch (error) {
    res.status(500).send({ message: "Lỗi hệ thống: " + error.message });
  }
});

module.exports = router;


//mongodb
