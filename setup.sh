#!/bin/bash

# =============================================================================
# RefugeeChain Identity - Hyperledger Fabric Development Environment Setup
# =============================================================================

echo "🚀 Setting up RefugeeChain Identity Development Environment..."

# =============================================================================
# STEP 1: System Prerequisites
# =============================================================================

echo "📋 Step 1: Installing System Prerequisites..."

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Git
sudo apt install git -y

# Install curl
sudo apt install curl -y

# Install build essentials
sudo apt install build-essential -y

# Install Python (required for some Node.js packages)
sudo apt install python3 python3-pip -y

echo "✅ System prerequisites installed!"

# =============================================================================
# STEP 2: Install Docker and Docker Compose
# =============================================================================

echo "🐳 Step 2: Installing Docker and Docker Compose..."

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.21.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo "✅ Docker installed! Please logout and login again for group changes to take effect."

# =============================================================================
# STEP 3: Install Node.js and npm
# =============================================================================

echo "📦 Step 3: Installing Node.js and npm..."

# Install Node Version Manager (nvm)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Reload bash profile
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

# Install Node.js LTS (version 18.x recommended for Fabric)
nvm install 18
nvm use 18
nvm alias default 18

# Verify installation
node --version
npm --version

echo "✅ Node.js $(node --version) and npm $(npm --version) installed!"

# =============================================================================
# STEP 4: Install Go (required for Fabric binaries)
# =============================================================================

echo "🔧 Step 4: Installing Go..."

# Download and install Go
GO_VERSION="1.21.3"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm go${GO_VERSION}.linux-amd64.tar.gz

# Add Go to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Reload bash profile
source ~/.bashrc

echo "✅ Go $(go version) installed!"

# =============================================================================
# STEP 5: Install Hyperledger Fabric Binaries
# =============================================================================

echo "🔗 Step 5: Installing Hyperledger Fabric..."

# Create fabric directory
mkdir -p ~/fabric-samples
cd ~/fabric-samples

# Download Fabric samples, binaries, and Docker images
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.4 1.5.7

# Add Fabric binaries to PATH
echo 'export PATH=$PATH:$HOME/fabric-samples/bin' >> ~/.bashrc
source ~/.bashrc

echo "✅ Hyperledger Fabric binaries installed!"

# =============================================================================
# STEP 6: Setup RefugeeChain Identity Project
# =============================================================================

echo "🏗️ Step 6: Setting up RefugeeChain Identity Project..."

# Create project directory
mkdir -p ~/refugeechain-identity
cd ~/refugeechain-identity

# Initialize Node.js project
npm init -y

# Install Fabric SDK and dependencies
npm install fabric-contract-api fabric-network fabric-ca-client --save
npm install fabric-shim --save

# Install development dependencies
npm install mocha chai sinon fabric-mock-stub --save-dev
npm install eslint prettier --save-dev

# Create project structure
mkdir -p chaincode/refugeeidentity/lib
mkdir -p application
mkdir -p network
mkdir -p test
mkdir -p config

echo "✅ Project structure created!"

# =============================================================================
# STEP 7: Create Package.json for Chaincode
# =============================================================================

echo "📄 Step 7: Creating chaincode package.json..."

cat > chaincode/refugeeidentity/package.json << EOF
{
  "name": "refugeeidentity-chaincode",
  "version": "1.0.0",
  "description": "RefugeeChain Identity Management Chaincode",
  "main": "index.js",
  "engines": {
    "node": ">=14"
  },
  "scripts": {
    "start": "fabric-chaincode-node start",
    "test": "mocha test --recursive",
    "lint": "eslint .",
    "format": "prettier --write ."
  },
  "dependencies": {
    "fabric-contract-api": "^2.5.4",
    "fabric-shim": "^2.5.4"
  },
  "devDependencies": {
    "mocha": "^10.2.0",
    "chai": "^4.3.8",
    "sinon": "^15.2.0",
    "fabric-mock-stub": "^2.0.0",
    "eslint": "^8.50.0",
    "prettier": "^3.0.3"
  },
  "author": "RefugeeChain Development Team",
  "license": "Apache-2.0"
}
EOF

# =============================================================================
# STEP 8: Create Chaincode Index File
# =============================================================================

echo "📝 Step 8: Creating chaincode index.js..."

cat > chaincode/refugeeidentity/index.js << 'EOF'
/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const RefugeeIdentityChaincode = require('./lib/refugeeidentity-chaincode');

module.exports.RefugeeIdentityChaincode = RefugeeIdentityChaincode;
module.exports.contracts = [RefugeeIdentityChaincode];
EOF

# =============================================================================
# STEP 9: Create Development Configuration
# =============================================================================

echo "⚙️ Step 9: Creating development configuration..."

# Create ESLint configuration
cat > chaincode/refugeeidentity/.eslintrc.json << EOF
{
    "env": {
        "node": true,
        "es2021": true,
        "mocha": true
    },
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion": 12,
        "sourceType": "module"
    },
    "rules": {
        "indent": ["error", 4],
        "quotes": ["error", "single"],
        "semi": ["error", "always"]
    }
}
EOF

# Create Prettier configuration
cat > chaincode/refugeeidentity/.prettierrc << EOF
{
    "semi": true,
    "trailingComma": "es5",
    "singleQuote": true,
    "printWidth": 100,
    "tabWidth": 4
}
EOF

# Create VS Code workspace settings
mkdir -p .vscode
cat > .vscode/settings.json << EOF
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll.eslint": true
    },
    "eslint.workingDirectories": ["chaincode/refugeeidentity"],
    "files.associations": {
        "*.yaml": "yaml",
        "*.yml": "yaml"
    }
}
EOF

# =============================================================================
# STEP 10: Create Network Configuration
# =============================================================================

echo "🌐 Step 10: Creating network configuration..."

# Create docker-compose for development network
cat > network/docker-compose-dev.yaml << 'EOF'
version: '3.7'

volumes:
  orderer.refugeechain.org:
  peer0.unhcr.refugeechain.org:
  peer0.irc.refugeechain.org:
  peer0.unicef.refugeechain.org:

networks:
  refugeechain:
    name: fabric_refugeechain

services:
  orderer.refugeechain.org:
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
      - ORDERER_OPERATIONS_LISTENADDRESS=orderer.refugeechain.org:9443
      - ORDERER_METRICS_PROVIDER=prometheus
    working_dir: /root
    command: orderer
    volumes:
        - ../organizations/ordererOrganizations/refugeechain.org/orderers/orderer.refugeechain.org/msp:/var/hyperledger/orderer/msp
        - ../organizations/ordererOrganizations/refugeechain.org/orderers/orderer.refugeechain.org/tls:/var/hyperledger/orderer/tls
        - orderer.refugeechain.org:/var/hyperledger/production/orderer
    ports:
      - 7050:7050
      - 7053:7053
      - 9443:9443
    networks:
      - refugeechain

  peer0.unhcr.refugeechain.org:
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
      - CORE_PEER_ID=peer0.unhcr.refugeechain.org
      - CORE_PEER_ADDRESS=peer0.unhcr.refugeechain.org:7051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:7051
      - CORE_PEER_CHAINCODEADDRESS=peer0.unhcr.refugeechain.org:7052
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer0.unhcr.refugeechain.org:7051
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer0.unhcr.refugeechain.org:7051
      - CORE_PEER_LOCALMSPID=UNHCRMSP
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS=peer0.unhcr.refugeechain.org:9444
      - CORE_METRICS_PROVIDER=prometheus
      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={"peername":"peer0unhcr"}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
    volumes:
        - ../organizations/peerOrganizations/unhcr.refugeechain.org/peers/peer0.unhcr.refugeechain.org:/etc/hyperledger/fabric
        - peer0.unhcr.refugeechain.org:/var/hyperledger/production
    working_dir: /root
    command: peer node start
    ports:
      - 7051:7051
      - 9444:9444
    networks:
      - refugeechain
EOF

# =============================================================================
# STEP 11: Create Application SDK Examples
# =============================================================================

echo "💻 Step 11: Creating application examples..."

cat > application/register-identity.js << 'EOF'
/*
 * RefugeeChain Identity - Register Identity Example
 */

'use strict';

const { Gateway, Wallets } = require('fabric-network');
const FabricCAServices = require('fabric-ca-client');
const path = require('path');
const fs = require('fs');

async function registerIdentity() {
    try {
        // Load connection profile
        const ccpPath = path.resolve(__dirname, '..', 'config', 'connection-profile.json');
        const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

        // Create a new CA client
        const caInfo = ccp.certificateAuthorities['ca.unhcr.refugeechain.org'];
        const caTLSCACerts = caInfo.tlsCACerts.pem;
        const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

        // Create a new file system based wallet
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);

        // Create a new gateway for connecting to peer node
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'appUser', discovery: { enabled: true, asLocalhost: true } });

        // Get the network (channel) our contract is deployed to
        const network = await gateway.getNetwork('refugeechainchannel');

        // Get the contract from the network
        const contract = network.getContract('refugeeidentity');

        // Submit transaction
        const result = await contract.submitTransaction(
            'registerIdentity',
            'REFUGEE_001',
            'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
            'encrypted_metadata_here',
            'UNHCR001'
        );

        console.log('Transaction has been submitted:', result.toString());

        // Disconnect from the gateway
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        process.exit(1);
    }
}

registerIdentity();
EOF

# =============================================================================
# STEP 12: Create Test Files
# =============================================================================

echo "🧪 Step 12: Creating test files..."

cat > test/refugeeidentity-chaincode.test.js << 'EOF'
/*
 * RefugeeChain Identity Chaincode Tests
 */

'use strict';

const sinon = require('sinon');
const chai = require('chai');
const expect = chai.expect;
const { MockStub } = require('fabric-mock-stub');
const RefugeeIdentityChaincode = require('../chaincode/refugeeidentity/lib/refugeeidentity-chaincode');

describe('RefugeeIdentityChaincode', () => {
    let mockStub;
    let chaincode;

    beforeEach(() => {
        mockStub = new MockStub('refugeeidentity', new RefugeeIdentityChaincode());
        chaincode = new RefugeeIdentityChaincode();
    });

    describe('#initLedger', () => {
        it('should initialize the ledger with default configuration', async () => {
            const response = await mockStub.mockInvoke('tx1', ['initLedger']);
            expect(response.status).to.equal(200);
        });
    });

    describe('#registerIdentity', () => {
        it('should register a new identity successfully', async () => {
            await mockStub.mockInvoke('tx1', ['initLedger']);

            const response = await mockStub.mockInvoke('tx2', [
                'registerIdentity',
                'TEST_001',
                'biometric_hash_123',
                'encrypted_metadata',
                'UNHCR001'
            ]);

            expect(response.status).to.equal(200);

            const identity = JSON.parse(response.payload.toString());
            expect(identity.identityId).to.equal('TEST_001');
            expect(identity.status).to.equal('ACTIVE');
        });
    });
});
EOF

echo "✅ RefugeeChain Identity development environment setup complete!"

# =============================================================================
# FINAL INSTRUCTIONS
# =============================================================================

cat << 'EOF'

🎉 SETUP COMPLETE!

📁 Project Structure:
~/refugeechain-identity/
├── chaincode/refugeeidentity/     # Node.js chaincode
├── application/                   # Client applications
├── network/                       # Network configuration
├── test/                         # Unit tests
└── config/                       # Configuration files

🔧 Next Steps:

1. Open VS Code in project directory:
   cd ~/refugeechain-identity
   code .

2. Install chaincode dependencies:
   cd chaincode/refugeeidentity
   npm install

3. Run tests:
   npm test

4. Start development network:
   cd network
   docker-compose -f docker-compose-dev.yaml up -d

5. Deploy chaincode (follow deployment guide)

📚 Useful Commands:

# Check Fabric version
peer version

# Package chaincode
peer lifecycle chaincode package refugeeidentity.tar.gz --path ./chaincode/refugeeidentity --lang node --label refugeeidentity_1.0

# Run tests
npm test

# Format code
npm run format

# Lint code
npm run lint

🔗 Resources:
- Hyperledger Fabric Docs: https://hyperledger-fabric.readthedocs.io/
- Node.js Contract API: https://hyperledger.github.io/fabric-chaincode-node/
- VS Code Fabric Extension: https://marketplace.visualstudio.com/items?itemName=IBMBlockchain.ibm-blockchain-platform

Happy coding! 🚀

EOF