var express = require("express");
let userModel = require("../schemas/users");
module.exports = {
    CreateAnUser: async function (username, password,
        email,role,fullName, avatarUrl, status
    ) {
        let newItem = new userModel({
            username: username,
            password: password,
            email: email,
            role: role,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status
            
        });
        await newItem.save();
        return newItem;
    },
    FindByID: async function (id) {
        return await userModel
            .findById(newItem._id);
    }
}