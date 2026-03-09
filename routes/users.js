var express = require("express");
var router = express.Router();
let bcrypt = require('bcrypt')
let { userPostValidation, validateResult } =
  require('../utils/validationHandler')

let userController = require("../controllers/users");


router.get("/", async function (req, res, next) {
  let users = await userModel
    .find({ isDeleted: false }).
    populate({ path: 'role', select: 'name' })
  res.send(users);
});

router.get("/:id", async function (req, res, next) {
  try {
    let result = await userModel
      .find({ _id: req.params.id, isDeleted: false })
    if (result.length > 0) {
      res.send(result);
    }
    else {
      res.status(404).send({ message: "id not found" });
    }
  } catch (error) {
    res.status(404).send({ message: "id not found" });
  }
});

router.post("/", userPostValidation, validateResult,
  async function (req, res, next) {
    try {
      let newItem = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email, 
        req.body.role,
        "", "",
        false
      )
      // populate cho đẹp
      let saved = await userController.FindByID(newItem._id);
      res.send(saved);
    } catch (err) {
      res.status(400).send({ message: err.message });
    }
  });

router.put("/:id", async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findOne({ _id: id, isDeleted: false })
    if (!updatedItem) return res.status(404).send({ message: "id not found" });
    let keys = Object.keys(req.body);
    for (const key of keys) {
      updatedItem[key] = req.body[key];
    }
    await updatedItem.save();
    let populated = await userModel
      .findById(updatedItem._id)
    res.send(populated);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});
router.delete("/:id", async function (req, res, next) {
  try {
    let id = req.params.id;
    let updatedItem = await userModel.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    if (!updatedItem) {
      return res.status(404).send({ message: "id not found" });
    }
    res.send(updatedItem);
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

module.exports = router;