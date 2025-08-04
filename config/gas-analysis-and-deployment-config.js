// Gas Analysis and Deployment Configuration for RefugeeChain Identity System

/**
 * Gas Cost Analysis for Smart Contract Operations
 * Based on Ethereum Mainnet gas prices and Hyperledger Fabric transaction costs
 */

const GasAnalysis = {
    // Ethereum Public Registry Gas Costs (in gas units)
    ethereum: {
        deployment: {
            RefugeeChainPublicRegistry: 3_247_891,
            RefugeeChainInteroperability: 1_876_543,
            totalDeployment: 5_124_434
        },

        operations: {
            // Read operations (view functions)
            getActiveAttestations: 45_000,
            getIdentityStats: 12_000,
            verifyServiceAccess: 35_000,
            getCrossChainRecords: 28_000,

            // Write operations
            addAttestation: 180_000,
            createBiometricChallenge: 95_000,
            completeBiometricChallenge: 75_000,
            grantServiceAccess: 120_000,
            enableCrossChainAccess: 110_000,
            emergencyRevokeIdentity: 85_000,

            // Batch operations
            batchAddAttestations: (count) => 120_000 + (count * 65_000),

            // Administrative operations
            addValidator: 45_000,
            addAttestor: 45_000,
            addOracle: 50_000,
            setFees: 35_000,
            pause: 25_000,
            unpause: 25_000
        }
    },

    // Hyperledger Fabric computational costs (in CPU/memory units)
    hyperledger: {
        operations: {
            registerIdentity: 0.015, // CPU seconds
            verifyIdentity: 0.008,
            addAttestation: 0.012,
            grantServiceAccess: 0.010,
            enableCrossBorderAccess: 0.009,
            queryIdentity: 0.003,
            queryIdentityByBiometric: 0.005,
            getAllIdentities: (pageSize) => 0.002 * pageSize
        },

        storage: {
            identityRecord: 2048, // bytes
            attestation: 512,
            serviceAccess: 256,
            biometricIndex: 128
        }
    }
};

/**
 * Calculate transaction costs based on current gas prices
 */
function calculateTransactionCosts(gasPrice = 20) { // gwei
    const costs = {};

    Object.entries(GasAnalysis.ethereum.operations).forEach(([operation, gasUsed]) => {
        if (typeof gasUsed === 'function') {
            costs[operation] = (count) => {
                const gas = gasUsed(count);
                return {
                    gasUsed: gas,
                    costETH: (gas * gasPrice) / 1e9,
                    costUSD: ((gas * gasPrice) / 1e9) * 2000 // Assuming $2000 ETH
                };
            };
        } else {
            costs[operation] = {
                gasUsed: gasUsed,
                costETH: (gasUsed * gasPrice) / 1e9,
                costUSD: ((gasUsed * gasPrice) / 1e9) * 2000
            };
        }
    });

    return costs;
}

/**
 * Deployment configuration for different networks
 */
const DeploymentConfig = {
    // Ethereum Mainnet
    mainnet: {
        rpcUrl: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        chainId: 1,
        gasPrice: 20_000_000_000, // 20 gwei
        gasLimit: 8_000_000,
        confirmations: 2,
        fees: {
            attestationFee: "1000000000000000", // 0.001 ETH
            verificationFee: "100000000000000"   // 0.0001 ETH
        }
    },

    // Polygon for lower costs
    polygon: {
        rpcUrl: "https://polygon-rpc.com",
        chainId: 137,
        gasPrice: 30_000_000_000, // 30 gwei
        gasLimit: 20_000_000,
        confirmations: 5,
        fees: {
            attestationFee: "10000000000000000", // 0.01 MATIC
            verificationFee: "1000000000000000"   // 0.001 MATIC
        }
    },

    // Ethereum Sepolia Testnet
    sepolia: {
        rpcUrl: "https://sepolia.infura.io/v3/YOUR_PROJECT_ID",
        chainId: 11155111,
        gasPrice: 10_000_000_000, // 10 gwei
        gasLimit: 8_000_000,
        confirmations: 1,
        fees: {
            attestationFee: "1000000000000000", // 0.001 ETH
            verificationFee: "100000000000000"   // 0.0001 ETH
        }
    },

    // Hyperledger Fabric Network
    hyperledger: {
        channelName: "refugeechainchannel",
        chaincodeName: "refugeeidentity",
        chaincodeVersion: "1.0",
        organizations: [
            {
                name: "UNHCR",
                mspId: "UNHCRMSP",
                peers: ["peer0.unhcr.refugeechain.org", "peer1.unhcr.refugeechain.org"],
                ca: "ca.unhcr.refugeechain.org"
            },
            {
                name: "IRC",
                mspId: "IRCMSP",
                peers: ["peer0.irc.refugeechain.org", "peer1.irc.refugeechain.org"],
                ca: "ca.irc.refugeechain.org"
            },
            {
                name: "UNICEF",
                mspId: "UNICEFMSP",
                peers: ["peer0.unicef.refugeechain.org", "peer1.unicef.refugeechain.org"],
                ca: "ca.unicef.refugeechain.org"
            }
        ],
        orderers: [
            "orderer0.refugeechain.org",
            "orderer1.refugeechain.org",
            "orderer2.refugeechain.org"
        ]
    }
};

/**
 * Deployment script for Ethereum contracts
 */
const EthereumDeployment = {
    async deploy(network = 'sepolia') {
        const { ethers } = require('hardhat');
        const config = DeploymentConfig[network];

        console.log(`Deploying to ${network}...`);

        // Deploy main registry contract
        const RefugeeChainPublicRegistry = await ethers.getContractFactory("RefugeeChainPublicRegistry");
        const registry = await RefugeeChainPublicRegistry.deploy({
            gasPrice: config.gasPrice,
            gasLimit: config.gasLimit
        });
        await registry.deployed();

        console.log(`RefugeeChainPublicRegistry deployed to: ${registry.address}`);

        // Deploy interoperability contract
        const RefugeeChainInteroperability = await ethers.getContractFactory("RefugeeChainInteroperability");
        const interop = await RefugeeChainInteroperability.deploy({
            gasPrice: config.gasPrice,
            gasLimit: config.gasLimit
        });
        await interop.deployed();

        console.log(`RefugeeChainInteroperability deployed to: ${interop.address}`);

        // Set initial configuration
        await registry.setFees(config.fees.attestationFee, config.fees.verificationFee);

        // Add initial validators (humanitarian organizations)
        const validators = [
            "0x1234567890123456789012345678901234567890", // UNHCR
            "0x2345678901234567890123456789012345678901", // IRC
            "0x3456789012345678901234567890123456789012"  // UNICEF
        ];

        for (const validator of validators) {
            await registry.addValidator(validator);
            await registry.addAttestor(validator);
            await registry.addOracle(validator);
        }

        return {
            registry: registry.address,
            interoperability: interop.address,
            network: network,
            deploymentTime: new Date().toISOString()
        };
    }
};

/**
 * Deployment script for Hyperledger Fabric chaincode
 */
const HyperledgerDeployment = {
    generateConnectionProfile() {
        const config = DeploymentConfig.hyperledger;

        return {
            name: "refugeechain-network",
            version: "1.0.0",
            client: {
                organization: "UNHCR",
                connection: {
                    timeout: {
                        peer: {
                            endorser: "300"
                        }
                    }
                }
            },
            organizations: config.organizations.reduce((orgs, org) => {
                orgs[org.name] = {
                    mspid: org.mspId,
                    peers: org.peers,
                    certificateAuthorities: [org.ca]
                };
                return orgs;
            }, {}),
            peers: config.organizations.reduce((peers, org) => {
                org.peers.forEach(peer => {
                    peers[peer] = {
                        url: `grpcs://${peer}:7051`,
                        tlsCACerts: {
                            path: `./crypto-config/peerOrganizations/${org.name.toLowerCase()}.refugeechain.org/tlsca/tlsca.${org.name.toLowerCase()}.refugeechain.org-cert.pem`
                        },
                        grpcOptions: {
                            "ssl-target-name-override": peer
                        }
                    };
                });
                return peers;
            }, {}),
            certificateAuthorities: config.organizations.reduce((cas, org) => {
                cas[org.ca] = {
                    url: `https://${org.ca}:7054`,
                    caName: `ca-${org.name.toLowerCase()}`,
                    tlsCACerts: {
                        path: `./crypto-config/peerOrganizations/${org.name.toLowerCase()}.refugeechain.org/ca/ca.${org.name.toLowerCase()}.refugeechain.org-cert.pem`
                    },
                    httpOptions: {
                        verify: false
                    }
                };
                return cas;
            }, {})
        };
    },

    generateDeploymentScript() {
        return `#!/bin/bash

# RefugeeChain Identity Hyperledger Fabric Deployment Script

set -e

# Environment variables
export CHANNEL_NAME="refugeechainchannel"
export CHAINCODE_NAME="refugeeidentity"
export CHAINCODE_VERSION="1.0"
export CHAINCODE_SEQUENCE="1"
export CC_PACKAGE_ID=""

# Package chaincode
echo "Packaging chaincode..."
peer lifecycle chaincode package refugeeidentity.tar.gz \\
    --path ./chaincode/refugeeidentity \\
    --lang node \\
    --label refugeeidentity_1.0

# Install chaincode on all peers
echo "Installing chaincode on peers..."
for ORG in UNHCR IRC UNICEF; do
    export CORE_PEER_LOCALMSPID="\${ORG}MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE="./crypto-config/peerOrganizations/\${ORG,,}.refugeechain.org/peers/peer0.\${ORG,,}.refugeechain.org/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="./crypto-config/peerOrganizations/\${ORG,,}.refugeechain.org/users/Admin@\${ORG,,}.refugeechain.org/msp"
    export CORE_PEER_ADDRESS="peer0.\${ORG,,}.refugeechain.org:7051"
    
    peer lifecycle chaincode install refugeeidentity.tar.gz
done

# Get package ID
export CC_PACKAGE_ID=$(peer lifecycle chaincode queryinstalled --output json | jq -r '.installed_chaincodes[0].package_id')

# Approve chaincode for each organization
echo "Approving chaincode definition..."
for ORG in UNHCR IRC UNICEF; do
    export CORE_PEER_LOCALMSPID="\${ORG}MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE="./crypto-config/peerOrganizations/\${ORG,,}.refugeechain.org/peers/peer0.\${ORG,,}.refugeechain.org/tls/ca.crt"
    export CORE_PEER_MSPCONFIGPATH="./crypto-config/peerOrganizations/\${ORG,,}.refugeechain.org/users/Admin@\${ORG,,}.refugeechain.org/msp"
    export CORE_PEER_ADDRESS="peer0.\${ORG,,}.refugeechain.org:7051"
    
    peer lifecycle chaincode approveformyorg \\
        -o orderer0.refugeechain.org:7050 \\
        --ordererTLSHostnameOverride orderer0.refugeechain.org \\
        --tls \\
        --cafile ./crypto-config/ordererOrganizations/refugeechain.org/orderers/orderer0.refugeechain.org/msp/tlscacerts/tlsca.refugeechain.org-cert.pem \\
        --channelID $CHANNEL_NAME \\
        --name $CHAINCODE_NAME \\
        --version $CHAINCODE_VERSION \\
        --package-id $CC_PACKAGE_ID \\
        --sequence $CHAINCODE_`
    }
}