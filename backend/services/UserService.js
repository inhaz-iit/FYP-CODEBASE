const config = require("../configuration/config");

class UserService {
    constructor() {}

    async userRegistrartion(walletParams,res) {
        try{    
            return {
                "Message":"User Registered Successfully",
            };
        } catch (error) {
            console.error("Error:", error);
            throw error;
        }
    }

}
  
module.exports = UserService;
