const Profile = require("../models/Profile");
const User = require("../models/User");

exports.updateProfile = async(req, res) =>{
    try{
        //Fetch Data
        const {dateOfBirth="", about="", contactNumber, gender} = req.body;

        //Fetch user ID 
        const id=req.user.id;

        //Validation
        if(!contactNumber || !gender || !id){
            return res.status(400).json({
                success:false,
                message:"All fields are required"
            });
        }

        //Find Profile
        const userDetails = await User.findById(id);
        const profileId = userDetails.additionDetails;
        const profileDetails = await Profile.findById(profileId);
        
        //Update Profile
        profileDetails.dateOfBirth=dateOfBirth;
        profileDetails.about=about;
        profileDetails.gender=gender;
        await profileDetails.save(); //saves data in DB

        //Return Response
        return res.status(200).json({
            success:true,
            message:"Profile Updated Successfully",
            profileDetails
        })


    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:"Unable to update profile",
            error:error.message
        })
    }
}

exports.deleteAccount = async(req, res) =>{
    try{
        //Get id
        const id=req.user.id;

        //Validation
        const userDetails = await User.findById(id);
        if(!userDetails){
            return res.status(404).json({
                success:false,
                message:"User Not Found"
            })
        }

        //Delete profile first then delete user
        await Profile.findByIdAndDelete({_id:userDetails.additionDetails});

        //Delete User
        await User.findByIdAndDelete({_id:id});
        //Return response
    }
    catch(error){

    }
}