const User = require('../models/User');
const jwt = require('jsonwebtoken')
const expressJwt = require('express-jwt')
const _ = require('lodash')
const {OAuth2Client} = require('google-auth-library')
const sgMail = require('@sendgrid/mail')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

exports.signup = (req,res) => {
    const {name,email,password} = req.body
    
    User.findOne({email}).exec((err,user) => {
        if(user){
            return res.status(400).json({
                error:'Email taken'
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

exports.requireSignin = expressJwt({
    secret: process.env.JWT_SECRET
})

exports.adminMiddleware = (req,res,next) => {
    User.findById(req.user._id).exec((err,user)=>{
        if(err || !user){
            return res.status(400).json({
                error: 'User not found.'
            })
        }

        if(user.role !== 'admin'){
            return res.status(400).json({
                error: 'Admin resource. Access denied'
            })
        }

        req.profile = user;
        next();
    })
}

exports.forgotPassword = (req,res) => {
    const {email} = req.body

    User.findOne({email}, (err,user) => {
        if(err || !user){
            return res.status(400).json({
                error: 'User with that email does not exist'
            })
        }

         // generate token
         const token = jwt.sign({_id: user._id},process.env.JWT_RESET_PASSWORD, {expiresIn: '10m'})

         // Data to be sent to user email
 
         const emailData = {
             from: process.env.EMAIL_FROM,
             to: email,
             subject:`Password Reset link`,
             html:`
                 <p>Please use the following link to reset your password</p>
                 <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
                 <hr/>
                 <p>This email may contain a senstive data</p>
                 <p>${process.env.CLIENT_URL}</p>
             `
         }
 
         return user .updateOne({resetPasswordLink: token}, (err,success) => {
             if(err){
                 console.log('RESET PASSWORD LINK ERROR', error)
                 return res.status(400).json({
                     error: 'Database connection error on user forgot request'
                 })
             }else{
                sgMail.send(emailData).then(sent => {
                    return res.json({
                        message: `Email has been sent to the ${email}. Follow the insturctions to reset your password.`
                    })
                }).catch(err => {
                    // console.log('Email Sent error',err)
                    return res.json({
                        message: err.message
                    })
                })
             }
         })
    })
}

exports.resetPassword = (req,res) => {
    const {resetPasswordLink, newPassword} = req.body

    if(resetPasswordLink){
        jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(err, download){
            if(err){
                return res.status(400).json({
                    error: 'Expired link.Try again.'
                })
            }

            User.findOne({resetPasswordLink}, (err,user) => {
                if(err || !user){
                    return res.status(400).json({
                        error: 'Something went wrong. Try later.'
                    }) 
                }

                const updateFields = {
                    password: newPassword,
                    resetPasswordLink: ''
                }

                user = _.extend(user, updateFields)

                user.save((err,result) => {
                    if(err){
                        return res.status(400).json({
                            error: 'Error saving updated passed'
                        })
                    }
                    res.json({
                        message: `Great! Now you can login with your new password`
                    })
                })
            })
        })
    }
}
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

exports.googleLogin = (req,res) => {
    const {idToken} = req.body

    client.verifyIdToken({idToken, audience:process.env.GOOGLE_CLIENT_ID})
    .then(response => {
        // console.log('GOOGLE LOGIN RESPONSE : ',response)
        const {email_verified, name,email} = response.payload;

        if(email_verified){
            // find user in DB
            User.findOne({email}).exec((err, user) => {
                if(user){
                    const token = jwt.sign({_id:user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})
                    const {_id, email,name,role} = user
                    return res.json({
                        token,user:{_id,email,name,role}
                    })
                }else{
                    let password = email + process.env.JWT_SECRET
                    user = new User({name,email,password})
                    user.save((err,data) => {
                        if(err){
                            console.log('ERROR GOOGLE LOGIN ON USER SAVE : ', err)
                            return res.status(400).json({
                                error: 'User signup with google failed.'
                            })
                        }
                        const token = jwt.sign({_id:data._id}, process.env.JWT_SECRET, {expiresIn: '7d'})
                        const {_id, email,name,role} = data
                        return res.json({
                        token,user:{_id,email,name,role}
                    })
                    })
                }
            })
        }else{
            return res.status(400).json({
                error:'Google login failed. Try Again'
            })
        }

    })

}

