#!/bin/bash

# =============================================================================
# 🚀 COMPLETE GUIDE: How to Run RefugeeChain Identity Project
# =============================================================================

echo "📚 RefugeeChain Identity - Complete Running Guide"
echo "=================================================="

# =============================================================================
# STEP 1: VERIFY PREREQUISITES
# =============================================================================

echo "🔍 Step 1: Verifying Prerequisites..."

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18.x"
    exit 1
fi

# Check if Fabric binaries are available
if ! command -v peer &> /dev/null; then
    echo "❌ Hyperledger Fabric binaries not found in PATH"
    echo "💡 Run the setup script first or add fabric-samples/bin to PATH"
    exit 1
fi

echo "✅ All prerequisites verified!"

# =============================================================================
# STEP 2: PROJECT SETUP
# =============================================================================

echo "🏗️ Step 2: Setting up Project Structure..."

# Create main project directory
mkdir -p ~/refugeechain-identity
cd ~/refugeechain-identity

# Create directory structure
mkdir -p chaincode/refugeeidentity/lib
mkdir -p chaincode/refugeeidentity/test
mkdir -p application
mkdir -p network/crypto-config
mkdir -p network/config
mkdir -p config
mkdir -p scripts
mkdir -p wallet

echo "✅ Project structure created!"

# =============================================================================
# STEP 3: CREATE CHAINCODE FILES
# =============================================================================

echo "📝 Step 3: Creating Chaincode Files..."

# Create package.json for chaincode
cat > chaincode/refugeeidentity/package.json << 'EOF'
{
  "name": "refugeeidentity-chaincode",
  "version": "1.0.0",
  "description": "RefugeeChain Identity Management Chaincode",
  "main": "index.js",
  "engines": {
    "node": ">=18.0.0"
  },
  "scripts": {
    "start": "fabric-chaincode-node start",
    "test": "mocha test --recursive --timeout 10000",
    "lint": "eslint lib/ --fix",
    "format": "prettier --write lib/ test/"
  },
  "dependencies": {
    "fabric-contract-api": "^2.5.4",
    "fabric-shim": "^2.5.4"
  },
  "devDependencies": {
    "mocha": "^10.2.0",
    "chai": "^4.3.8",
    "sinon": "^15.2.0",
    "eslint": "^8.50.0",
    "prettier": "^3.0.3"
  },
  "author": "RefugeeChain Development Team",
  "license": "Apache-2.0"
}
EOF

# Create index.js (entry point)
cat > chaincode/refugeeidentity/index.js << 'EOF'
/*
 * SPDX-License-Identifier: Apache-2.0
 * RefugeeChain Identity Chaincode - Entry Point
 */

'use strict';

const RefugeeIdentityChaincode = require('./lib/refugeeidentity-chaincode');

module.exports.RefugeeIdentityChaincode = RefugeeIdentityChaincode;
module.exports.contracts = [RefugeeIdentityChaincode];

module.exports.info = {
    title: 'RefugeeChain Identity Management System',
    version: '1.0.0',
    description: 'AI-Integrated Blockchain Identity System for Refugees and Stateless Populations',
    author: 'RefugeeChain Development Team',
    license: 'Apache-2.0'
};
EOF

echo "✅ Chaincode files created!"

# =============================================================================
# STEP 4: INSTALL DEPENDENCIES
# =============================================================================

echo "📦 Step 4: Installing Dependencies..."

cd chaincode/refugeeidentity
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install chaincode dependencies"
    exit 1
fi

echo "✅ Dependencies installed!"

# =============================================================================
# STEP 5: CREATE NETWORK CONFIGURATION
# =============================================================================

echo "🌐 Step 5: Creating Network Configuration..."

cd ../../network

# Create simplified test network configuration
cat > docker-compose-test.yaml << 'EOF'
version: '3.7'

volumes:
  orderer.example.com:
  peer0.org1.example.com:
  peer0.org2.example.com:

networks:
  test:
    name: fabric_test

services:

  orderer.example.com:
    image: hyperledger/fabric-orderer:2.5.4
    labels:
      service: hyperledger-fabric
    environment:
      - FABRIC_LOGGING_SPEC=INFO
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT=7050
      - ORDERER_GENERAL_LOCALMSPID=OrdererMSP
      - ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp
      - ORDERER_GENERAL_TLS_ENABLED=true
      - ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_BOOTSTRAPMETHOD=none
      - ORDERER_CHANNELPARTICIPATION_ENABLED=true
      - ORDERER_ADMIN_TLS_ENABLED=true
      - ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:7053
      - ORDERER_OPERATIONS_LISTENADDRESS=orderer.example.com:9443
      - ORDERER_METRICS_PROVIDER=prometheus
    working_dir: /root
    command: orderer
    volumes:
        - ../organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp:/var/hyperledger/orderer/msp
        - ../organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls:/var/hyperledger/orderer/tls
        - orderer.example.com:/var/hyperledger/production/orderer
    ports:
      - 7050:7050
      - 7053:7053
      - 9443:9443
    networks:
      - test

  peer0.org1.example.com:
    image: hyperledger/fabric-peer:2.5.4
    labels:
      service: hyperledger-fabric
    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - FABRIC_LOGGING_SPEC=INFO
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_PROFILE_ENABLED=false
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID=peer0.org1.example.com
      - CORE_PEER_ADDRESS=peer0.org1.example.com:7051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:7051
      - CORE_PEER_CHAINCODEADDRESS=peer0.org1.example.com:7052
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org1.example.com:7051
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org1.example.com:7051
      - CORE_PEER_LOCALMSPID=Org1MSP
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS=peer0.org1.example.com:9444
      - CORE_METRICS_PROVIDER=prometheus
      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={"peername":"peer0org1"}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
    volumes:
        - ../organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com:/etc/hyperledger/fabric
        - peer0.org1.example.com:/var/hyperledger/production
    working_dir: /root
    command: peer node start
    ports:
      - 7051:7051
      - 9444:9444
    networks:
      - test

  peer0.org2.example.com:
    image: hyperledger/fabric-peer:2.5.4
    labels:
      service: hyperledger-fabric
    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - FABRIC_LOGGING_SPEC=INFO
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_PROFILE_ENABLED=false
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID=peer0.org2.example.com
      - CORE_PEER_ADDRESS=peer0.org2.example.com:9051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:9051
      - CORE_PEER_CHAINCODEADDRESS=peer0.org2.example.com:9052
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:9052
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.org2.example.com:9051
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer0.org2.example.com:9051
      - CORE_PEER_LOCALMSPID=Org2MSP
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS=peer0.org2.example.com:9445
      - CORE_METRICS_PROVIDER=prometheus
      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={"peername":"peer0org2"}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
    volumes:
        - ../organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com:/etc/hyperledger/fabric
        - peer0.org2.example.com:/var/hyperledger/production
    working_dir: /root
    command: peer node start
    ports:
      - 9051:9051
      - 9445:9445
    networks:
      - test
EOF

echo "✅ Network configuration created!"

# =============================================================================
# STEP 6: CREATE DEPLOYMENT SCRIPTS
# =============================================================================

echo "🚀 Step 6: Creating Deployment Scripts..."

cd ../scripts

# Create network startup script
cat > start-network.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting RefugeeChain Identity Network..."

# Set environment variables
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/

cd ../network

# Use the test-network from fabric-samples as base
if [ -d "~/fabric-samples/test-network" ]; then
    echo "📋 Using fabric-samples test-network..."
    cd ~/fabric-samples/test-network

    # Start the network
    ./network.sh up createChannel -ca -c mychannel -s couchdb

    if [ $? -eq 0 ]; then
        echo "✅ Network started successfully!"
        echo "📊 Network Status:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    else
        echo "❌ Failed to start network"
        exit 1
    fi
else
    echo "❌ fabric-samples not found. Please run the setup script first."
    exit 1
fi
EOF

# Create chaincode deployment script
cat > deploy-chaincode.sh << 'EOF'
#!/bin/bash

echo "📦 Deploying RefugeeChain Identity Chaincode..."

# Set environment variables
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Go to fabric-samples test-network
cd ~/fabric-samples/test-network

# Package the chaincode
echo "📦 Packaging chaincode..."
peer lifecycle chaincode package refugeeidentity.tar.gz \
    --path ~/refugeechain-identity/chaincode/refugeeidentity \
    --lang node \
    --label refugeeidentity_1.0

if [ $? -ne 0 ]; then
    echo "❌ Failed to package chaincode"
    exit 1
fi

# Install chaincode on peer0.org1
echo "🔧 Installing chaincode on Org1 peer..."
peer lifecycle chaincode install refugeeidentity.tar.gz

# Get package ID
export CC_PACKAGE_ID=$(peer lifecycle chaincode queryinstalled --output json | jq -r '.installed_chaincodes[0].package_id')

# Install chaincode on peer0.org2
echo "🔧 Installing chaincode on Org2 peer..."
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer lifecycle chaincode install refugeeidentity.tar.gz

# Approve chaincode for Org2
echo "✅ Approving chaincode for Org2..."
peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --channelID mychannel \
    --name refugeeidentity \
    --version 1.0 \
    --package-id $CC_PACKAGE_ID \
    --sequence 1

# Approve chaincode for Org1
echo "✅ Approving chaincode for Org1..."
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:7051

peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --channelID mychannel \
    --name refugeeidentity \
    --version 1.0 \
    --package-id $CC_PACKAGE_ID \
    --sequence 1

# Check commit readiness
echo "🔍 Checking commit readiness..."
peer lifecycle chaincode checkcommitreadiness \
    --channelID mychannel \
    --name refugeeidentity \
    --version 1.0 \
    --sequence 1 \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --output json

# Commit chaincode
echo "🚀 Committing chaincode..."
peer lifecycle chaincode commit \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    --channelID mychannel \
    --name refugeeidentity \
    --peerAddresses localhost:7051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    --version 1.0 \
    --sequence 1

# Query committed chaincodes
echo "📋 Querying committed chaincodes..."
peer lifecycle chaincode querycommitted --channelID mychannel --name refugeeidentity

# Initialize the ledger
echo "🔧 Initializing ledger..."
peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    -C mychannel \
    -n refugeeidentity \
    --peerAddresses localhost:7051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"initLedger","Args":[]}'

echo "✅ Chaincode deployed and initialized successfully!"
EOF

# Create test script
cat > test-chaincode.sh << 'EOF'
#!/bin/bash

echo "🧪 Testing RefugeeChain Identity Chaincode..."

# Set environment variables
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

cd ~/fabric-samples/test-network

echo "📝 Test 1: Register a new identity..."
peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls \
    --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" \
    -C mychannel \
    -n refugeeidentity \
    --peerAddresses localhost:7051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 \
    --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" \
    -c '{"function":"registerIdentity","Args":["REFUGEE_001","a1b2c3d4e5f6789012345678901234567890abcdef","encrypted_metadata_sample","UNHCR001"]}'

echo "🔍 Test 2: Query the registered identity..."
peer chaincode query \
    -C mychannel \
    -n refugeeidentity \
    -c '{"function":"queryIdentity","Args":["REFUGEE_001"]}'

echo "✅ Chaincode tests completed!"
EOF

# Make scripts executable
chmod +x start-network.sh
chmod +x deploy-chaincode.sh
chmod +x test-chaincode.sh

echo "✅ Deployment scripts created!"

# =============================================================================
# STEP 7: CREATE APPLICATION EXAMPLES
# =============================================================================

echo "💻 Step 7: Creating Application Examples..."

cd ../application

# Create simple application example
cat > register-identity.js << 'EOF'
/*
 * RefugeeChain Identity - Register Identity Example Application
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

async function main() {
    try {
        // Build connection profile from fabric-samples
        const ccpPath = path.resolve(__dirname, '..', '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', 'org1.example.com', 'connection-org1.json');
        const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

        // Create wallet
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check if user exists in wallet
        const identity = await wallet.get('appUser');
        if (!identity) {
            console.log('An identity for the user "appUser" does not exist in the wallet');
            console.log('Run the enrollAdmin.js application before retrying');
            return;
        }

        // Create gateway connection
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'appUser', discovery: { enabled: true, asLocalhost: true } });

        // Get network and contract
        const network = await gateway.getNetwork('mychannel');
        const contract = network.getContract('refugeeidentity');

        // Register a new identity
        console.log('\n--> Submit Transaction: Register Identity');
        const result = await contract.submitTransaction(
            'registerIdentity',
            'REFUGEE_001',
            'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
            'encrypted_metadata_here',
            'UNHCR001'
        );
        console.log('*** Result:', result.toString());

        // Query the identity
        console.log('\n--> Evaluate Transaction: Query Identity');
        const queryResult = await contract.evaluateTransaction('queryIdentity', 'REFUGEE_001');
        console.log('*** Result:', queryResult.toString());

        // Disconnect
        await gateway.disconnect();

    } catch (error) {
        console.error(`******** FAILED to run the application: ${error}`);
        process.exit(1);
    }
}

main();
EOF

# Create package.json for application
cat > package.json << 'EOF'
{
  "name": "refugeechain-application",
  "version": "1.0.0",
  "description": "RefugeeChain Identity Application SDK",
  "main": "register-identity.js",
  "scripts": {
    "register": "node register-identity.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "fabric-network": "^2.5.4",
    "fabric-ca-client": "^2.5.4"
  },
  "author": "RefugeeChain Development Team",
  "license": "Apache-2.0"
}
EOF

echo "✅ Application examples created!"

# =============================================================================
# FINAL SUMMARY
# =============================================================================

echo ""
echo "🎉 RefugeeChain Identity Project Setup Complete!"
echo "=================================================="
echo ""
echo "📁 Project structure created at: ~/refugeechain-identity/"
echo ""
echo "🚀 To run the project, execute these commands:"
echo ""
echo "1️⃣  Start the Hyperledger Fabric network:"
echo "   cd ~/refugeechain-identity/scripts"
echo "   ./start-network.sh"
echo ""
echo "2️⃣  Deploy the RefugeeChain Identity chaincode:"
echo "   ./deploy-chaincode.sh"
echo ""
echo "3️⃣  Test the chaincode functionality:"
echo "   ./test-chaincode.sh"
echo ""
echo "4️⃣  Run application examples:"
echo "   cd ../application"
echo "   npm install"
echo "   npm run register"
echo ""
echo "📚 Additional commands:"
echo "   • View network status: docker ps"
echo "   • Stop network: cd ~/fabric-samples/test-network && ./network.sh down"
echo "   • View logs: docker logs <container_name>"
echo ""
echo "🔧 Troubleshooting:"
echo "   • If scripts fail, ensure Docker is running"
echo "   • Check that fabric-samples is installed in home directory"
echo "   • Verify Node.js version is 18.x"
echo ""
echo "Happy coding! 🚀"