const config = require("../configuration/config");
const bcrypt = require("bcryptjs");
const UserModel = require("../models/userModel"); // Assuming you have a User model
const Joi = require("joi");

class UserService {
    async userRegistrartion(userData) {
        try {
            // Validate user input
            const { error } = this.validateUserInput(userData);
            if (error) {
                throw new Error(error.details[0].message);
            }

            // Check if the user already exists
            const existingUser = await UserModel.findOne({ email: userData.email });
            if (existingUser) {
                throw new Error("User with this email already exists");
            }

            // Check if the phone number is already in use
            const existingPhoneNumber = await UserModel.findOne({ phoneNumber: userData.phoneNumber });    
            if (existingPhoneNumber) {
                throw new Error("Phone number already in use");
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(userData.password, 10);

            // Create a new user
            const newUser = new UserModel({
                email: userData.email,
                password: hashedPassword,
                phoneNumber: userData.phoneNumber,
                name: userData.name
            });

            // Save the user to the database
            await newUser.save();

            return {
                Message: "User registered successfully"
            };
        } catch (error) {
            console.error("Error in user registration:", error);
            throw error;
        }
    }

    validateUserInput(userData) {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required(),
            name: Joi.string().min(2).required(),
            phoneNumber: Joi.string().min(11).required(),
        });

        return schema.validate(userData);
    }   
}
  
module.exports = UserService;
