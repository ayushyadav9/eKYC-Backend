const mongoose = require("mongoose");
const { Schema } = mongoose;

const BankSchema = new Schema({
  email:{
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  ethAddress: {
    type: String,
    required: true,
    unique: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  approvedClients:[{
      name: {type: String},
      kycId:{type: String}
  }]
});
const Bank = mongoose.model('bank',BankSchema)
module.exports = Bank;