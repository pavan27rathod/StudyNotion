const Section = require("../models/Section");
const Course = require("../models/Course");

exports.createSection = async (req, res) =>{
    try{
        //fetch data
        const {sectionName, courseId} = req.id;

        //data validation
        if(!sectionName || !!courseId){
            res.status(200).json({
                success: false,
                message: "Missing Properties"
            })
        }
        //create section
        const newSection = await Section. create({sectionName});

        //update course with section ObjectID
        const updatedCourseDetails = await Course.findByIdAndUpdate(
                                                courseId,
                                                {
                                                    $push:{
                                                        courseContent:newSection._id
                                                    }
                                                },
                                                {new:true}
                                            ).populate({
                                                path: "courseContent",
                                                populate: {
                                                    path: "subSection",
                                                },
                                            })
                                            .exec();
        //return response

        return res.status(200).json({
            success:true,
            message:"Section Created Successfully",
            data:updatedCourseDetails
        })
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Unable to creare section, please try again",
            error:error.message
        })
    }
}

//Update Section
exports.updateSection = async(req, res) =>{
    try{
        //Data input
        const {sectionName,sectionId} = req.body
        //Data Validation
        if(!sectionId || !sectionName){
            return res.status(400).json(
                {
                    success: false,
                    message:"Missing Properties"
                }
            )
        }

        //Update the data
        const section = await Section.findByIdAndUpdate(sectionId, {sectionName}, {new:true});

        //Return response
        return res.status(200).json({
            success:true,
            message:"Section Updated Successfully"
        })
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            success:false,
            message: "Unable to Update the Section"
        })
    }
}

//Delete Section

exports.deleteSection = async (req, res) =>{
    try{
        //Get ID - Assume that we are sending ID in params
        const {sectionId} = req.params;

        //Delete
        await Section.findByIdAndDelete(sectionId);

        //Return response
        return res.status(200).json({
            success:true,
            message:"Section Deleted Successfully..."            
        })
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            success:false,
            message:"Unable to delete section, please try again",
            error:error.message
        })
    }
}