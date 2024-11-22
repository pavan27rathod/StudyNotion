const User= require("../models/User");
const mailSender=require("../utils/mailSender");
const crypto=require(crypto);

//resetPassword token
exports.resetPasswordToken = async (req, res) => {
    try {
        //get email from req body
        const email = req.body.email;
        //check user for this email , email validation
        const user = await User.findOne({email: email});
        if(!user) {
            return res.json({success:false,
            message:'Your Email is not registered with us'});
        }
        //generate token 
        const token  = crypto.randomUUID();
        //update user by adding token and expiration time
        const updatedDetails = await User.findOneAndUpdate(
                                        {email:email},
                                        {
                                            token:token,
                                            resetPasswordExpires: Date.now() + 5*60*1000,
                                        },
                                        {new:true});
        //create url
        const url = `http://localhost:3000/update-password/${token}`
        //send mail containing the url
        await mailSender(email, 
                        "Password Reset Link",
                        `Password Reset Link: ${url}`);
        //return response
        return res.json({
            success:true,
            message:'Email sent successfully, please check email and change pwd',
        });
    }
    catch(error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:'Something went wrong while sending reset pwd mail'
        })
    }   
}

exports.resetPassword = async (req, res) => {
    try {
        // Data fetch from request body
        const {password, confirmPassword, token} = req.body;
        
        // Validate if password and confirmPassword match
        if(password !== confirmPassword) {
            return res.json({
                success:false,
                message:'Password not matching',
            });
        }
        
        // Fetch user details from DB using token
        const userDetails = await User.findOne({token: token});
        
        // Check if user exists, if not token is invalid
        if(!userDetails) {
            return res.json({
                success:false,
                message:'Token is invalid',
            });
        }
        
        // Check if token is expired
        if(userDetails.resetPasswordExpires < Date.now()) {
            return res.json({
                success:false,
                message:'Token is expired, please regenerate your token',
            });
        }
        
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Update password in DB
        await User.findOneAndUpdate(
            {token: token}, 
            {password: hashedPassword}, 
            {new: true} // Ensures updated user data is returned after the update
        );
        
        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Password reset successful',
        });
    } catch(error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: 'Something went wrong while sending reset pwd mail'
        });
    }
}
