//----------------------------------
// 1) Install Node.js
// 2) Install dependencies:
//    npm install jwk-to-pem --save
//    npm install node-rsa
//----------------------------------
const jwkToPem = require("jwk-to-pem");
const fs = require("fs");
const argv     = require('node:process');

async function main (){
  try {
    const args = process.argv;
    if (args[2]) {
      const data = fs.readFileSync(args[2], "utf8");
      const jsonData = JSON.parse(data);
      console.log(jsonData);
      const pem = jwkToPem(jsonData);
      console.log(pem);
    }
    else{
      console.error("Please specify a RSA JWK public filename in the command line")
    }
  } catch (error) {
      console.error(error);
  }  
}

main();