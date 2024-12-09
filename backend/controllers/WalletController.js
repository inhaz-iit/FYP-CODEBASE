const WalletService = require("../services/WalletService");
const walletService = new WalletService();

class WalletController{
    static async createWallet (req,res) {
        try{
            const newWallet = await walletService.createWallet(req.body, res);
            return res.status(200).json({newWallet});
        }
        catch(error){
            res.status(400).json({error:error.message})
        }
    }

    static async connectSepolia (req,res) {
        try{
            const newWallet = await walletService.connectSepolia(req.body, res);
            return res.status(200).json({newWallet});
        }
        catch(error){
            res.status(400).json({error:error.message})
        }
    }
}


module.exports = WalletController;