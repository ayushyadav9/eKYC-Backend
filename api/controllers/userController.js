const User = require("../../models/User");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { gmail } = require("googleapis/build/src/apis/gmail");
const transporter = require("../../config/nodemailer");
const generateRandomString = require("../../utils/random");
const Bank = require("../../models/Bank");


module.exports.register = async (req,res)=>{
    try {
        if(req.body.sender=='client'){
            let user = await User.findOne({ email: req.body.email });
            if (user) {
                return res.status(400).json({
                    message: 'User already exists',
                    success: false,
                });
            }
            let kycId = "KYC-"+generateRandomString();
            let userWithKYC = await User.findOne({kycId:kycId})
            while(userWithKYC){
                kycId = "KYC-"+generateRandomString();
                userWithKYC = await User.findOne({kycId:kycId})
            }
            let pass = generateRandomString(8)
            let hash = await bcrypt.hash(pass, 10);
            user =  User({
                email: req.body.email,
                kycId: kycId,
                password: hash,
            });
            const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);
            await user.save();
            const result = await transporter.sendMail({
                from: "eKYC Portal <ayushtest935@gmail.com>",
                to: req.body.email,
                replyTo:"ayushtest935@gmail.com",
                subject: "KYC credentials",
                html:  `<h4><span style="font-size:16px">Email</span>:&nbsp; ${user.email}</h4>
                        <h4><span style="font-size:16px">Password</span>:&nbsp; ${pass}</h4>
                        <h4><span style="font-size:16px">KYC-ID</span>:&nbsp; ${user.kycId}</h4>`,
            });
            res.status(200).json({
                message: 'Registered Successfully',
                data: {
                    user,
                    token: token,
                },
                success: true,
            });
        }
        else if(req.body.sender=='bank'){
            let bank = await Bank.findOne({ email: req.body.email });
            let bankEth = await Bank.findOne({ ethAddress: req.body.ethAddress });
            if (bank || bankEth) {
                return res.status(400).json({
                    message: 'Bank already exists',
                    success: false,
                });
            }
            let pass = generateRandomString(8)
            let hash = await bcrypt.hash(pass, 10);
            bank =  Bank({
                email: req.body.email,
                ethAddress: req.body.ethAddress,
                password: hash,
            });
            const token = jwt.sign({ email: bank.email }, process.env.JWT_SECRET);
            await bank.save();
            const result = await transporter.sendMail({
                from: "eKYC Portal <ayushtest935@gmail.com>",
                to: req.body.email,
                replyTo:"ayushtest935@gmail.com",
                subject: "Bank credentials",
                html: `<p><span style="font-size:16px">Email</span>:&nbsp; ${bank.email}</p>
                        <p><span style="font-size:16px">Password</span>:&nbsp; ${pass}</p>`,
            });
            res.status(200).json({
                message: 'Registered Successfully',
                data: {
                    bank,
                    token: token,
                },
                success: true,
            });
        }
        else{
            res.status(400).json({
                message: 'Sender not specified!',
                success: false,
            }); 
        }

    } catch (err) {
        res.status(500).json({
            error: err.message,
            message: 'Something went wrong',
            success: false,
        });
    }
}

module.exports.login = async(req,res)=>{
    try {
        if(req.body.sender=='client'){
            let user = await User.findOne({ email: req.body.email })
            if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
                return res.status(400).json({
                    message: 'Invalid email or password',
                    success: false,
                });
            }
            const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);
            res.status(200).json({
                message: 'User logged in successfully',
                data: {
                    user:{
                        email:user.email,
                        kycId:user.kycId,
                    }, 
                    token
                },
                success: true,
            });
        }
        else if(req.body.sender=='bank'){
            let bank = await Bank.findOne({ email: req.body.email })
            if (!bank || !(await bcrypt.compare(req.body.password, bank.password))) {
                return res.status(400).json({
                    message: 'Invalid email or password',
                    success: false,
                });
            }
            const token = jwt.sign({ email: bank.email }, process.env.JWT_SECRET);
            res.status(200).json({
                message: 'Bank logged in successfully',
                data: {
                    bank:{
                        email: bank.email,
                        ethAddress: bank.ethAddress
                    }, 
                    token
                },
                success: true,
            });
        }
        else{
            res.status(400).json({
                message: 'Sender not specified!',
                success: false,
            });
        }
    } catch (error) {
        res.status(500).json({
            error: error.message,
            message: 'Something went wrong',
            success: false,
        });
    }
}
