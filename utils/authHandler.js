let jwt = require('jsonwebtoken')
let userModel = require("../schemas/users");
module.exports = {
    checkLogin: function (req, res, next) {
        try {
            let authorizationToken = req.headers.authorization;
            if (!authorizationToken.startsWith("Bearer")) {
                res.status(403).send({
                    message: "ban chua dang nhap"
                })
                return;
            }
            let token = authorizationToken.split(' ')[1];
            let result = jwt.verify(token, 'HUTECH');
            if (result.exp > Date.now()) {
                req.userId = result.id;
                next();
            } else {
                res.status(403).send({
                    message: "ban chua dang nhap"
                })
            }
        } catch (error) {
            res.status(403).send({
                message: "ban chua dang nhap"
            })
            return;
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            try {
                let userId = req.userId;
                let getUser = await userModel.findById(userId).populate('role');
                                if (!getUser || !getUser.role) {
                    return res.status(403).send({ message: "Tai khoan chua duoc cap quyen (role trống)" });
                }
                let roleName = getUser.role.name; 
                if (requiredRole.includes(roleName)) {
                    next();
                } else {
                    return res.status(403).send({ message: "ban khong co quyen" });
                }
            } catch (error) {
                return res.status(500).send({ message: "Lỗi server khi check quyền: " + error.message });
            }
        }
    }
}