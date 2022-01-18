const User = require("../../models/User");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { gmail } = require("googleapis/build/src/apis/gmail");
const transporter = require("../../config/nodemailer");
const generateRandomString = require("../../utils/random");


module.exports.register = async (req,res)=>{
    try {
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

        let hash = await bcrypt.hash(req.body.password, 10);
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
            html: `<h3>kycId: ${user.kycId}</h3><h3>Password: ${req.body.password}</h3>`,
          });

        res.status(200).json({
            message: 'Registered Successfully',
            data: {
                user,
                token: token,
            },
            success: true,
        });

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

    } catch (error) {
        res.status(500).json({
            error: error.message,
            message: 'Something went wrong',
            success: false,
        });
    }
}
