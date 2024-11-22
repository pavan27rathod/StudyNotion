const SubSection = require("../models/SubSection");
const Section = require("../models/Section");
const { uploadImageToCloudinary } = require("../utils/imageUploader");

//Create subsection

exports.createSubSection = async (req, res) => {
    try{
        //fetch data
        const {sectionId, title, timeDuration, description} = req.body;
        //extract file/video
        const video = req.files.videoFile;

        //validation
        if(!sectionId || !title || !timeDuration || !description){
            return res.status(400).json({
                success:false,
                message:"All fields are required"
            });
        }

        //Upload video to cloudinary
        const uploadDetails = await uploadImageToCloudinary(video, process.env.FOLDER_NAME);

        //Create a subsection
        const subSectionDetails = await SubSection.create({
            title:title,
            timeDuration:timeDuration,
            description: description,
            videoUrl:uploadDetails.secure_url
        })

        //Update section with this subsection ObjectId
        const updatedSection = await Section.findByIdAndUpdate({_id:sectionId},
                                        {$push:{
                                            subSection:subSectionDetails._id
                                        }},
                                        {new:true}).populate("subSection");
        //return response
        return res.status(200).json({
            success:true,
            message:"Subsection created successfully",
            updatedSection
        })
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Unable to create subsection",
            error:error
        })
    }
}

exports.updateSubSection = async (req, res) => {
    try {
        const { sectionId, subSectionId, title, description } = req.body;
        const subSection = await SubSection.findById(subSectionId);
  
        if (!subSection) {
            return res.status(404).json({
                success: false,
                message: "SubSection not found",
            });
        }
  
        if (title) {
            subSection.title = title;
        }
  
        if (description) {
            subSection.description = description;
        }

        // Check if the video file is provided
        if (req.files && req.files.videoFile) {
            const videoFile = req.files.videoFile; // Ensure consistent naming
            const uploadDetails = await uploadImageToCloudinary(videoFile, process.env.FOLDER_NAME);
            subSection.videoUrl = uploadDetails.secure_url;
            // Assuming uploadDetails contains time duration
            subSection.timeDuration = uploadDetails.duration ? `${uploadDetails.duration}` : subSection.timeDuration;
        }
  
        await subSection.save();
  
        // Find updated section and return it
        const updatedSection = await Section.findById(sectionId).populate("subSection");
  
        return res.json({
            success: true,
            message: "SubSection updated successfully",
            data: updatedSection,
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "An error occurred while updating the SubSection",
        });
    }
};

  
  exports.deleteSubSection = async (req, res) => {
    try {
      const { subSectionId, sectionId } = req.body
      await Section.findByIdAndUpdate(
        { _id: sectionId },
        {
          $pull: {
            subSection: subSectionId,
          },
        }
      )
      const subSection = await SubSection.findByIdAndDelete({ _id: subSectionId })
  
      if (!subSection) {
        return res
          .status(404)
          .json({ success: false, message: "SubSection not found" })
      }
  
      // find updated section and return it
      const updatedSection = await Section.findById(sectionId).populate(
        "subSection"
      )
  
      return res.json({
        success: true,
        message: "SubSection deleted successfully",
        data: updatedSection,
      })
    } catch (error) {
      console.error(error)
      return res.status(500).json({
        success: false,
        message: "An error occurred while deleting the SubSection",
      })
    }
  }