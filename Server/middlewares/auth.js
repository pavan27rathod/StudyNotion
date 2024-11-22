const jwt=require("jsonwebtoken");
require("dotenv").config();
const User=require("../models/User");

//auth
exports.auth = async (req, res)=>{
    try{
        //extract token
        const token = req.cookies.token 
                || req.body.token 
                || req.header("Authorisation").replace("Bearer","");

        //If token is missing
        if(!token){
            return res.status(401).json({
                success:false,
                message: "Token is missing"
            })
        }

        //verify token
        try{
            const decode = await jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user=decode;
        }
        catch(error){
            //If verification issue occurs
            return res.status(401).json({
                success:false,
                message:"Token is invalid"
            })

        }
        next();
    }
    catch(error){
        return res.status(401).json({
            success:false,
            message:"Something is wrong while validating the token "
        })
    }
}

//isStudent
exports.isStudent = async(req, res)=>{
    try{
        if(req.user.accountType !== "Student"){
            return res.status(401).json({
                success:false,
                message:"This is protected route for Students only"
            })
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:"User role can not be verified"
        })
    }
}

//isInstructor
exports.isInstructor = async(req, res)=>{
    try{
        if(req.user.accountType !== "Instructor"){
            return res.status(401).json({
                success:false,
                message:"This is protected route for Instructor only"
            })
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:"User role can not be verified"
        })
    }
}

//isAdmin
exports.isAdmin = async(req, res)=>{
    try{
        if(req.user.accountType !== "Admin"){
            return res.status(401).json({
                success:false,
                message:"This is protected route for Admin only"
            })
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:"User role can not be verified"
        })
    }
}