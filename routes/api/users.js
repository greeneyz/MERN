const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secretKey = require('../../config/keys');

//Load User Model
const User = require('../../models/User');

// @route       GET api/users/test
// @desc        Test Users route
// @access      Public
router.get('/test', (req, res) => res.json({msg: "Users Working!"}) );

// @route       GET api/users/register
// @desc        register a user
// @access      Public
router.post('/register', (req, res)=> {
User.findOne({email: req.body.email})
    .then(user=>{
        if(user) {
            res.status(400).json({email: 'Email already exist!'})
        } else {
            
            const avatar = gravatar.url(req.body.email, {
                s: '200', //Size
                r: 'pg', //Rating
                d: 'mm' //Default
            });

            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                avatar: avatar,
                password: req.body.password
            })

            bcrypt.genSalt(10, (err, salt)=>{
                bcrypt.hash(req.body.password, salt, (err, hash)=>{
                    if(err) throw err;
                    newUser.password = hash;
                    newUser.save()
                        .then(user=>res.json(user))
                        .catch(err=>console.log(err))
                })
            })
        }
    })
})

// @route       GET api/users/login
// @desc        Login user / Returning JWT token
// @access      Public
router.post('/login', (req, res)=>{
    const email = req.body.email;
    const password = req.body.password;

    // Find the user
    User.findOne({email})
        .then(user => {
            //check user
            if(!user){
                return res.status(404).json({email: 'User not found'});
            }

            //check password
            bcrypt.compare(password, user.password)
                .then(isMatch => {
                    if(isMatch){
                        // Logic for generating the token
                        
                        // Make payload object to pass in jwt signin method
                        const payload = { id: user.id, name: user.name, avatar: user.avatar }    

                        //Sign JWT
                        jwt.sign(
                            payload, 
                            secretKey.secretKey,
                            { expiresIn: 3600 },
                            (err, token) => {
                                res.json({ success: true, token: 'Bearer ' + token })
                            }
                        );
                    }
                    else {
                        return res.status(400).json({password: 'password incorrect'})
                    }
                })
        })
})

module.exports = router;