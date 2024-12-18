const path = require("path");
// Loading the values from .env file
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Define required environment variables
const requiredVariables = [
    'PORT',
    'MONGO_USERNAME', 
    'MONGO_PASSWORD',
    'MONGO_STRING',
    'SEPOLIA_RPC',
    'PRIVATE_KEY',
    'AMOY_RPC',
    'TOKEN_ADDRESS',
    'WRAPPED_TOKEN_ADDRESS',
    'LOCK_CONTRACT_ADDRESS',
    'SENDER_PRIVATE_KEY',
    'ETHERSCAN_API_KEY'
];

// Check if all required environment variables are defined and throws an error if there are missing values in the env file
const missingVariables = requiredVariables.filter(variable => !(process.env[variable]));
if (missingVariables.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVariables.join(', ')}`);
}

// Stores all the environment variable in the config object
const config = {
    PORT: process.env.PORT,
    MONGO_USERNAME: process.env.MONGO_USERNAME,
    MONGO_PASSWORD: process.env.MONGO_PASSWORD,
    MONGO_STRING: process.env.MONGO_STRING,
    SEPOLIA_RPC: process.env.SEPOLIA_RPC,
    PRIVATE_KEY: process.env.PRIVATE_KEY,
    AMOY_RPC: process.env.AMOY_RPC,
    TOKEN_ADDRESS: process.env.TOKEN_ADDRESS,
    WRAPPED_TOKEN_ADDRESS: process.env.WRAPPED_TOKEN_ADDRESS,
    LOCK_CONTRACT_ADDRESS: process.env.LOCK_CONTRACT_ADDRESS,
    SENDER_PRIVATE_KEY: process.env.SENDER_PRIVATE_KEY,
    ETHERSCAN_API_KEY: process.env.ETHERSCAN_API_KEY
}

// generate mongoURI for database
function generateMongoURI() {
    if(config.MONGO_USERNAME && config.MONGO_PASSWORD && config.MONGO_STRING){
        return `mongodb+srv://${config.MONGO_USERNAME}:${config.MONGO_PASSWORD}@${config.MONGO_STRING}`;
    } else {
        throw new Error('Error when generating MongoURI');
    }
};

// generated uri is added to the config
config.MONGO_URI = generateMongoURI();

// config file is exported
module.exports = config;
