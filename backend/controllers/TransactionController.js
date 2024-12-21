const TransactionService = require("../services/TransactionService");
const transactionService = new TransactionService();

class TransactionController{
    static async sendTokens (req,res) {
        try{
            const transaction = await transactionService.sendTokens(req.body, res);
            return res.status(200).json({"transaction":transaction});
        }
        catch(error){
            res.status(400).json({error:error.message})
        }
    }
}


module.exports = TransactionController;