const UserService = require("../services/UserService");
const userService = new UserService();

class UserController{
    static async userRegistration (req,res) {
        try{
            const response = await userService.userRegistrartion(req.body);
            return res.status(201).json({response: response.Message});
        }
        catch(error){
            res.status(400).json({error:error.message})
        }
    }
}


module.exports = UserController;