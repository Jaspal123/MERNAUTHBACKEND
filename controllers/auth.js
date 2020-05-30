const User = require('../models/User');
const jwt = require('jsonwebtoken')
const sgMail = require('@sendgrid/mail')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

exports.signup = (req,res) => {
    const {name,email,password} = req.body
    
    User.findOne({email}).exec((err,user) => {
        if(user){
            return res.status(400).json({
                err:'Email taken'
            })
        }

        // generate token
        const token = jwt.sign({ name,email,password},process.env.JWT_ACCOUNT_ACTIVATION, {expiresIn: '10m'})

        // Data to be sent to user email

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject:`Account activation link`,
            html:`
                <p>Please use the following link to activate you account</p>
                <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
                <hr/>
                <p>This email may contain a senstive data</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        }

        sgMail.send(emailData).then(sent => {
            return res.json({
                message: `Email has been sent to the ${email}. Follow the insturctions to activate your account.`
            })
        }).catch(err => {
            // console.log('Email Sent error',err)
            return res.json({
                message: err.message
            })
        })

    })
}

exports.accountActivation = (req,res) => {
    const {token} = req.body

    if(token){
        jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION,(err,decoded)=>{
            if(err){
                console.log('JWT VERIFING ACCOUNt ACTIVATION ERROr', err)
                return res.status(401).json({
                    error: 'Expired Link. Sign up Again!'
                })
            }
            const {name,email,password} = jwt.decode(token)

            const user = new User({name,email,password})

            user.save((err,user) => {
                if(err){
                    console.log('SAVE USER IN DB ACTIVATION ERROR', err)
                    return res.status(401).json({
                        error:'Error saving user in DB. Try Sign up Again'
                    })
                }
                return res.json({
                    message: 'Sign up success. Please Sign in!'
                })
            })
        })
    }else{
        return res.json({
            message: 'Something went wrong.Please try again'
        })
    }
}

exports.signin = (req,res) => {
    const {email, password} = req.body

    // Check if user exist
    User.findOne({email}).exec((err, user) =>{
        if(err || !user){
            return res.status(400).json({
                error: 'User with that email does not exit. Please Sign up.'
            })
        }
        // Match password
        if(!user.authenticate(password))
        {
            return res.status(400).json({
                error: 'Email and password do not match.'
            })
        }

        // generate a token and send to client

        const token = jwt.sign({_id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})
        const {_id, name,email,role} = user
        
        return res.json({
            token,
            user:{ _id,name,email,role}
        })
    })
}