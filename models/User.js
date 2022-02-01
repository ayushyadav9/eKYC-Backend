const mongoose = require("mongoose");
const { Schema } = mongoose;

const UserSchema = new Schema({
  email:{
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  kycId: {
    type: String,
    required: true,
    unique: true,
  },
  socket:{
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});
const User = mongoose.model('user',UserSchema)
module.exports = User;