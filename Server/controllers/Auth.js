const User=require("../models/User");
const OTP=require("../models/OTP");
const otpGenerator=require("otp-generator");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
require("dotenv").config();

//sendOTP
exports.sendOTP=async(req, res)=>{

    try{
            //Fetch Email
        const {email} = req.body;

        //Check if User alreay exists
        const checkUserPresent= await User.findOne({email});

        //if User alreay exists, send response
        if(checkUserPresent){
            return res.status(401).json({
                success: false,
                message: 'User is already registered',
            })
        }

        //Generate OTP 
        var otp=otpGenerator.generate(6,{
            upperCaseAlphabets:false,
            lowerCaseAlphabets:false,
            specialChars:false
        })
        console("OTP Generated: ", otp);

        //Check if the generated otp is unique
        let result=await OTP.findOne({otp:otp});
        
        //If we don't get any unique OTP, generate till we get unique one
        while(result){
            otp=otpGenerator(6,{
                upperCaseAlphabets:false,
                lowerCaseAlphabets:false,
                specialChars:false
            })
            result=await OTP.findOne({otp:otp});
        }

        //After generating Unique OTP, make entry in DB
        const otpPayload={email,otp}; //Entry will get stored in OTP.js
        const otpBody=await OTP.create(otpPayload);
        console.log(otpBody);

        //Return Response
        res.status(200).json({
            success:true,
            message:'OTP Sent Successfully',
            otp
        })
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:error.message
        })
    }
    
}

//signUp
exports.signUp=async(req, res)=>{
    try{
            //fetch data
        const{
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        }=req.body;

        //valid data
        if(!firstName || !lastName || !email || !password || !confirmPassword || ! otp ){
            return res.status(403).json({
                success:false,
                message:"All fields are required"
            })
        }

        //Match password & confirm password
        if(password !== confirmPassword){
            return res.status(400).json({
                success:false,
                message: "Password & Confirm Password did not match, please try again"
            });
        }
            

        //check user already exists or not
        const existingUser=await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"User is already registered"
            });
        }

        //find most recent otp stored for the user
        const recentOtp=await OTP.find({email}).sort({createdAt:-1}).limit(1);
        console.log(recentOtp);

        //validate otp entered by user & otp stored in DB
        if(recentOtp.length==0){
            //OTP not found
            return res.status(400).json({
                success:false,
                message:"OTP Not Found"
            })
        }

        else if(otp !==recentOtp.otp){
            //Invalid OTP
            res.status(400).json({
                success:false,
                message:"Invalid OTP"
            })
        }

        //hash password
        const hashedPassword=await bcrypt.hash(password,10);

        //create entry in DB
        const profileDetails = await User.create({
            gender:null,
            dateOfBirth:null,
            about:null,
            contactNumber:null
        });

        const user=await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password:hashedPassword,
            accountType,
            additionDetails: profileDetails._id,
            image:`https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`
        })
        //return response
        res.status(200).json({
            success:true,
            message:"User registered successfully",
            user
        })

    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"User cannot be registered. Please try again"
        })
    }

}

//Login
exports.login=async(req, res)=>{
   try{
        //Fetch Email & Password
        const {email, password}=req.body;
        //Validate Email & Password
        if(!email || !password ){
            return res.status(403).json({
                success:false,
                message:"All fields are required, please try again"
            })
        }

        //Check if user exists or not
        const user=await User.findOne({email}).populate("additionalDetails");
        if(!user){
            return res.status(401).json({
                success:false,
                message:"User is not registered, please sign up first"
            });
        }
        //Generate JWT after password matching
        if(await bcrypt.compare(password,user.password)){
            const payload={
                email:user.email,
                id:user._id,
                role:user.role
            }
            const token=jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h",
            })
            user.token=token;
            user.password=undefined;
        }

        //Create cookie & send response
        const options={
            expires:new Date(Date.now()) + 3*24*60*60*1000,
            httpOnly:true
        }
        res.cookie("token", token, options).status(200).json({
            success:true,
            token,
            user,
            message: "Logged in successfully"

        })
        else{
            
        }
   }
   catch(error){

   }
}

//changePassword