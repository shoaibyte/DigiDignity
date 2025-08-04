/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * RefugeeChain Identity Chaincode - Entry Point
 *
 * FILE LOCATION: chaincode/refugeeidentity/index.js
 *
 * This is the main entry point for the Hyperledger Fabric chaincode.
 * It exports the RefugeeIdentityChaincode contract for deployment.
 */

'use strict';

const RefugeeIdentityChaincode = require('./lib/refugeeidentity-chaincode');

// Export the chaincode contract
module.exports.RefugeeIdentityChaincode = RefugeeIdentityChaincode;

// Export contracts array for Fabric runtime
module.exports.contracts = [RefugeeIdentityChaincode];

// Optional: Export version information
module.exports.info = {
    title: 'RefugeeChain Identity Management System',
    version: '1.0.0',
    description: 'AI-Integrated Blockchain Identity System for Refugees and Stateless Populations',
    author: 'RefugeeChain Development Team',
    license: 'Apache-2.0'
};