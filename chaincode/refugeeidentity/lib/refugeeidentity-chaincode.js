/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * RefugeeChain Identity (RCI) - Hyperledger Fabric Chaincode
 * AI-Integrated Blockchain Identity System for Refugees and Stateless Populations
 *
 * PROGRAMMING LANGUAGE: Node.js (JavaScript)
 * FRAMEWORK: Hyperledger Fabric Contract API
 *
 * This chaincode implements the core identity management functionality
 * for displaced populations using Hyperledger Fabric
 *
 * FILE LOCATION: chaincode/refugeeidentity/lib/refugeeidentity-chaincode.js
 */

'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

class RefugeeIdentityChaincode extends Contract {

    /**
     * Initialize the ledger with default configuration
     */
    async initLedger(ctx) {
        console.info('============= START : Initialize Ledger ===========');

        // Initialize system configuration
        const config = {
            version: '1.0.0',
            networkName: 'RefugeeChain Identity Network',
            consensusType: 'RAFT',
            maxIdentities: 10000000, // 10 million identities
            biometricAlgorithm: 'SHA-256',
            encryptionStandard: 'AES-256-GCM',
            privacyLevel: 'MAXIMUM'
        };

        await ctx.stub.putState('NETWORK_CONFIG', Buffer.from(JSON.stringify(config)));

        // Initialize humanitarian organization registry
        const orgs = [
            {
                orgId: 'UNHCR001',
                name: 'United Nations High Commissioner for Refugees',
                role: 'VALIDATOR',
                permissions: ['REGISTER', 'VERIFY', 'ATTEST'],
                publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
            },
            {
                orgId: 'IRC001',
                name: 'International Rescue Committee',
                role: 'VALIDATOR',
                permissions: ['REGISTER', 'VERIFY', 'SERVICE'],
                publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
            }
        ];

        for (let org of orgs) {
            await ctx.stub.putState(`ORG_${org.orgId}`, Buffer.from(JSON.stringify(org)));
        }

        console.info('============= END : Initialize Ledger ===========');
    }

    /**
     * Register a new refugee identity with biometric data
     * @param {Context} ctx - Transaction context
     * @param {string} identityId - Unique identity identifier
     * @param {string} biometricHash - SHA-256 hash of biometric template
     * @param {string} encryptedMetadata - Encrypted personal metadata
     * @param {string} organizationId - Registering organization ID
     */
    async registerIdentity(ctx, identityId, biometricHash, encryptedMetadata, organizationId) {
        console.info('============= START : Register Identity ===========');

        // Validate organization permissions
        const org = await this._getOrganization(ctx, organizationId);
        if (!org || !org.permissions.includes('REGISTER')) {
            throw new Error(`Organization ${organizationId} not authorized to register identities`);
        }

        // Check if identity already exists
        const existingIdentity = await ctx.stub.getState(identityId);
        if (existingIdentity && existingIdentity.length > 0) {
            throw new Error(`Identity ${identityId} already exists`);
        }

        // Create identity record
        const identity = {
            identityId: identityId,
            biometricHash: biometricHash,
            encryptedMetadata: encryptedMetadata,
            registeredBy: organizationId,
            registrationTimestamp: new Date().toISOString(),
            status: 'ACTIVE',
            verificationLevel: 'BASIC',
            attestations: [],
            serviceAccess: [],
            crossBorderStatus: 'PENDING',
            aiVerificationScore: 0,
            lastUpdated: new Date().toISOString(),
            version: 1
        };

        // Store identity on ledger
        await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

        // Create biometric index for fast lookup
        const biometricIndex = {
            identityId: identityId,
            biometricHash: biometricHash,
            registrationTimestamp: identity.registrationTimestamp
        };
        await ctx.stub.putState(`BIO_${biometricHash}`, Buffer.from(JSON.stringify(biometricIndex)));

        // Emit registration event
        const eventPayload = {
            identityId: identityId,
            organizationId: organizationId,
            timestamp: identity.registrationTimestamp,
            eventType: 'IDENTITY_REGISTERED'
        };
        ctx.stub.setEvent('IdentityRegistered', Buffer.from(JSON.stringify(eventPayload)));

        console.info('============= END : Register Identity ===========');
        return JSON.stringify(identity);
    }

    /**
     * Verify identity using AI-enhanced biometric matching
     * @param {Context} ctx - Transaction context
     * @param {string} identityId - Identity to verify
     * @param {string} challengeBiometricHash - Challenge biometric hash
     * @param {string} verifierId - Organization performing verification
     */
    async verifyIdentity(ctx, identityId, challengeBiometricHash, verifierId) {
        console.info('============= START : Verify Identity ===========');

        // Get identity record
        const identityBytes = await ctx.stub.getState(identityId);
        if (!identityBytes || identityBytes.length === 0) {
            throw new Error(`Identity ${identityId} does not exist`);
        }

        const identity = JSON.parse(identityBytes.toString());

        // Validate verifier permissions
        const verifier = await this._getOrganization(ctx, verifierId);
        if (!verifier || !verifier.permissions.includes('VERIFY')) {
            throw new Error(`Organization ${verifierId} not authorized to verify identities`);
        }

        // Simulate AI-enhanced biometric verification
        const verificationResult = await this._performAIVerification(
            identity.biometricHash,
            challengeBiometricHash
        );

        // Update identity record with verification result
        identity.aiVerificationScore = verificationResult.confidenceScore;
        identity.lastVerification = {
            verifierId: verifierId,
            timestamp: new Date().toISOString(),
            confidenceScore: verificationResult.confidenceScore,
            method: 'AI_BIOMETRIC',
            result: verificationResult.result
        };
        identity.lastUpdated = new Date().toISOString();
        identity.version += 1;

        // Update verification level based on score
        if (verificationResult.confidenceScore >= 95) {
            identity.verificationLevel = 'HIGH';
        } else if (verificationResult.confidenceScore >= 80) {
            identity.verificationLevel = 'MEDIUM';
        } else {
            identity.verificationLevel = 'LOW';
        }

        await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

        // Emit verification event
        const eventPayload = {
            identityId: identityId,
            verifierId: verifierId,
            confidenceScore: verificationResult.confidenceScore,
            result: verificationResult.result,
            timestamp: identity.lastVerification.timestamp,
            eventType: 'IDENTITY_VERIFIED'
        };
        ctx.stub.setEvent('IdentityVerified', Buffer.from(JSON.stringify(eventPayload)));

        console.info('============= END : Verify Identity ===========');
        return JSON.stringify(verificationResult);
    }

    // ... (rest of the methods remain the same as in the original code)

    // Helper methods

    async _getOrganization(ctx, orgId) {
        const orgBytes = await ctx.stub.getState(`ORG_${orgId}`);
        if (!orgBytes || orgBytes.length === 0) {
            return null;
        }
        return JSON.parse(orgBytes.toString());
    }

    async _performAIVerification(originalHash, challengeHash) {
        // Simulate AI-enhanced biometric matching
        // In real implementation, this would call external AI service
        const similarity = this._calculateBiometricSimilarity(originalHash, challengeHash);

        return {
            result: similarity >= 0.8 ? 'MATCH' : 'NO_MATCH',
            confidenceScore: Math.round(similarity * 100),
            algorithm: 'AI_MULTIMODAL_FUSION',
            timestamp: new Date().toISOString()
        };
    }

    _calculateBiometricSimilarity(hash1, hash2) {
        // Simplified similarity calculation for demo
        // In real implementation, this would use advanced AI algorithms
        if (hash1 === hash2) return 1.0;

        // Simulate some variance in biometric matching
        const hammingDistance = this._hammingDistance(hash1, hash2);/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * RefugeeChain Identity (RCI) - Hyperledger Fabric Chaincode
 * AI-Integrated Blockchain Identity System for Refugees and Stateless Populations
 *
 * This chaincode implements the core identity management functionality
 * for displaced populations using Hyperledger Fabric
 */

        'use strict';

        const {Contract} = require('fabric-contract-api');
        const crypto = require('crypto');

        class RefugeeIdentityChaincode extends Contract {

            /**
             * Initialize the ledger with default configuration
             */
            async initLedger(ctx) {
                console.info('============= START : Initialize Ledger ===========');

                // Initialize system configuration
                const config = {
                    version: '1.0.0',
                    networkName: 'RefugeeChain Identity Network',
                    consensusType: 'RAFT',
                    maxIdentities: 10000000, // 10 million identities
                    biometricAlgorithm: 'SHA-256',
                    encryptionStandard: 'AES-256-GCM',
                    privacyLevel: 'MAXIMUM'
                };

                await ctx.stub.putState('NETWORK_CONFIG', Buffer.from(JSON.stringify(config)));

                // Initialize humanitarian organization registry
                const orgs = [
                    {
                        orgId: 'UNHCR001',
                        name: 'United Nations High Commissioner for Refugees',
                        role: 'VALIDATOR',
                        permissions: ['REGISTER', 'VERIFY', 'ATTEST'],
                        publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
                    },
                    {
                        orgId: 'IRC001',
                        name: 'International Rescue Committee',
                        role: 'VALIDATOR',
                        permissions: ['REGISTER', 'VERIFY', 'SERVICE'],
                        publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
                    }
                ];

                for (let org of orgs) {
                    await ctx.stub.putState(`ORG_${org.orgId}`, Buffer.from(JSON.stringify(org)));
                }

                console.info('============= END : Initialize Ledger ===========');
            }

            /**
             * Register a new refugee identity with biometric data
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Unique identity identifier
             * @param {string} biometricHash - SHA-256 hash of biometric template
             * @param {string} encryptedMetadata - Encrypted personal metadata
             * @param {string} organizationId - Registering organization ID
             */
            async registerIdentity(ctx, identityId, biometricHash, encryptedMetadata, organizationId) {
                console.info('============= START : Register Identity ===========');

                // Validate organization permissions
                const org = await this._getOrganization(ctx, organizationId);
                if (!org || !org.permissions.includes('REGISTER')) {
                    throw new Error(`Organization ${organizationId} not authorized to register identities`);
                }

                // Check if identity already exists
                const existingIdentity = await ctx.stub.getState(identityId);
                if (existingIdentity && existingIdentity.length > 0) {
                    throw new Error(`Identity ${identityId} already exists`);
                }

                // Create identity record
                const identity = {
                    identityId: identityId,
                    biometricHash: biometricHash,
                    encryptedMetadata: encryptedMetadata,
                    registeredBy: organizationId,
                    registrationTimestamp: new Date().toISOString(),
                    status: 'ACTIVE',
                    verificationLevel: 'BASIC',
                    attestations: [],
                    serviceAccess: [],
                    crossBorderStatus: 'PENDING',
                    aiVerificationScore: 0,
                    lastUpdated: new Date().toISOString(),
                    version: 1
                };

                // Store identity on ledger
                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Create biometric index for fast lookup
                const biometricIndex = {
                    identityId: identityId,
                    biometricHash: biometricHash,
                    registrationTimestamp: identity.registrationTimestamp
                };
                await ctx.stub.putState(`BIO_${biometricHash}`, Buffer.from(JSON.stringify(biometricIndex)));

                // Emit registration event
                const eventPayload = {
                    identityId: identityId,
                    organizationId: organizationId,
                    timestamp: identity.registrationTimestamp,
                    eventType: 'IDENTITY_REGISTERED'
                };
                ctx.stub.setEvent('IdentityRegistered', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Register Identity ===========');
                return JSON.stringify(identity);
            }

            /**
             * Verify identity using AI-enhanced biometric matching
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Identity to verify
             * @param {string} challengeBiometricHash - Challenge biometric hash
             * @param {string} verifierId - Organization performing verification
             */
            async verifyIdentity(ctx, identityId, challengeBiometricHash, verifierId) {
                console.info('============= START : Verify Identity ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate verifier permissions
                const verifier = await this._getOrganization(ctx, verifierId);
                if (!verifier || !verifier.permissions.includes('VERIFY')) {
                    throw new Error(`Organization ${verifierId} not authorized to verify identities`);
                }

                // Simulate AI-enhanced biometric verification
                const verificationResult = await this._performAIVerification(
                    identity.biometricHash,
                    challengeBiometricHash
                );

                // Update identity record with verification result
                identity.aiVerificationScore = verificationResult.confidenceScore;
                identity.lastVerification = {
                    verifierId: verifierId,
                    timestamp: new Date().toISOString(),
                    confidenceScore: verificationResult.confidenceScore,
                    method: 'AI_BIOMETRIC',
                    result: verificationResult.result
                };
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                // Update verification level based on score
                if (verificationResult.confidenceScore >= 95) {
                    identity.verificationLevel = 'HIGH';
                } else if (verificationResult.confidenceScore >= 80) {
                    identity.verificationLevel = 'MEDIUM';
                } else {
                    identity.verificationLevel = 'LOW';
                }

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Emit verification event
                const eventPayload = {
                    identityId: identityId,
                    verifierId: verifierId,
                    confidenceScore: verificationResult.confidenceScore,
                    result: verificationResult.result,
                    timestamp: identity.lastVerification.timestamp,
                    eventType: 'IDENTITY_VERIFIED'
                };
                ctx.stub.setEvent('IdentityVerified', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Verify Identity ===========');
                return JSON.stringify(verificationResult);
            }

            /**
             * Add attestation to identity (education, health, etc.)
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Target identity
             * @param {string} attestationType - Type of attestation
             * @param {string} encryptedData - Encrypted attestation data
             * @param {string} issuerId - Issuing organization
             */
            async addAttestation(ctx, identityId, attestationType, encryptedData, issuerId) {
                console.info('============= START : Add Attestation ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate issuer permissions
                const issuer = await this._getOrganization(ctx, issuerId);
                if (!issuer || !issuer.permissions.includes('ATTEST')) {
                    throw new Error(`Organization ${issuerId} not authorized to issue attestations`);
                }

                // Create attestation
                const attestation = {
                    attestationId: this._generateId(),
                    type: attestationType,
                    encryptedData: encryptedData,
                    issuerId: issuerId,
                    issueTimestamp: new Date().toISOString(),
                    expirationDate: this._calculateExpirationDate(attestationType),
                    status: 'ACTIVE',
                    verificationHash: crypto.createHash('sha256')
                        .update(identityId + attestationType + encryptedData + issuerId)
                        .digest('hex')
                };

                // Add to identity attestations
                identity.attestations.push(attestation);
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store attestation separately for querying
                await ctx.stub.putState(
                    `ATTESTATION_${attestation.attestationId}`,
                    Buffer.from(JSON.stringify(attestation))
                );

                // Emit attestation event
                const eventPayload = {
                    identityId: identityId,
                    attestationId: attestation.attestationId,
                    type: attestationType,
                    issuerId: issuerId,
                    timestamp: attestation.issueTimestamp,
                    eventType: 'ATTESTATION_ADDED'
                };
                ctx.stub.setEvent('AttestationAdded', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Add Attestation ===========');
                return JSON.stringify(attestation);
            }

            /**
             * Grant service access with selective disclosure
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Identity requesting access
             * @param {string} serviceProviderId - Service provider ID
             * @param {string} serviceType - Type of service (BANKING, EDUCATION, HEALTHCARE, AID)
             * @param {string} requiredAttributes - JSON string of required attributes
             */
            async grantServiceAccess(ctx, identityId, serviceProviderId, serviceType, requiredAttributes) {
                console.info('============= START : Grant Service Access ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate service provider
                const serviceProvider = await this._getOrganization(ctx, serviceProviderId);
                if (!serviceProvider || !serviceProvider.permissions.includes('SERVICE')) {
                    throw new Error(`Organization ${serviceProviderId} not authorized to provide services`);
                }

                // Check verification level requirements
                const serviceRequirements = this._getServiceRequirements(serviceType);
                if (identity.verificationLevel === 'LOW' && serviceRequirements.minVerificationLevel !== 'LOW') {
                    throw new Error(`Insufficient verification level for service ${serviceType}`);
                }

                // Create service access record with zero-knowledge proof simulation
                const serviceAccess = {
                    accessId: this._generateId(),
                    serviceProviderId: serviceProviderId,
                    serviceType: serviceType,
                    requiredAttributes: JSON.parse(requiredAttributes),
                    grantedTimestamp: new Date().toISOString(),
                    expirationDate: this._calculateServiceExpiration(serviceType),
                    status: 'ACTIVE',
                    accessCount: 0,
                    zkProofHash: crypto.createHash('sha256')
                        .update(identityId + serviceType + requiredAttributes)
                        .digest('hex')
                };

                // Add to identity service access
                identity.serviceAccess.push(serviceAccess);
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store service access record
                await ctx.stub.putState(
                    `SERVICE_ACCESS_${serviceAccess.accessId}`,
                    Buffer.from(JSON.stringify(serviceAccess))
                );

                // Emit service access event
                const eventPayload = {
                    identityId: identityId,
                    accessId: serviceAccess.accessId,
                    serviceProviderId: serviceProviderId,
                    serviceType: serviceType,
                    timestamp: serviceAccess.grantedTimestamp,
                    eventType: 'SERVICE_ACCESS_GRANTED'
                };
                ctx.stub.setEvent('ServiceAccessGranted', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Grant Service Access ===========');
                return JSON.stringify(serviceAccess);
            }

            /**
             * Enable cross-border identity portability
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Identity to make portable
             * @param {string} destinationCountry - Destination country code
             * @param {string} authorizingOrg - Authorizing organization
             */
            async enableCrossBorderAccess(ctx, identityId, destinationCountry, authorizingOrg) {
                console.info('============= START : Enable Cross-Border Access ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate authorizing organization
                const authorizer = await this._getOrganization(ctx, authorizingOrg);
                if (!authorizer) {
                    throw new Error(`Organization ${authorizingOrg} not found`);
                }

                // Create cross-border record
                const crossBorderAccess = {
                    accessId: this._generateId(),
                    destinationCountry: destinationCountry,
                    authorizingOrg: authorizingOrg,
                    authorizedTimestamp: new Date().toISOString(),
                    validUntil: this._calculateCrossBorderExpiration(),
                    status: 'AUTHORIZED',
                    portabilityHash: crypto.createHash('sha256')
                        .update(identityId + destinationCountry + authorizingOrg)
                        .digest('hex')
                };

                // Update identity
                identity.crossBorderStatus = 'AUTHORIZED';
                identity.crossBorderAccess = crossBorderAccess;
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store cross-border record
                await ctx.stub.putState(
                    `CROSS_BORDER_${crossBorderAccess.accessId}`,
                    Buffer.from(JSON.stringify(crossBorderAccess))
                );

                console.info('============= END : Enable Cross-Border Access ===========');
                return JSON.stringify(crossBorderAccess);
            }

            /**
             * Query identity by ID
             */
            async queryIdentity(ctx, identityId) {
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }
                return identityBytes.toString();
            }

            /**
             * Query identity by biometric hash
             */
            async queryIdentityByBiometric(ctx, biometricHash) {
                const indexBytes = await ctx.stub.getState(`BIO_${biometricHash}`);
                if (!indexBytes || indexBytes.length === 0) {
                    throw new Error(`No identity found for biometric hash`);
                }

                const index = JSON.parse(indexBytes.toString());
                return await this.queryIdentity(ctx, index.identityId);
            }

            /**
             * Get all identities (with pagination for scalability)
             */
            async getAllIdentities(ctx, startKey = '', endKey = '', pageSize = 100) {
                const allResults = [];

                for await (const {key, value} of ctx.stub.getStateByRange(startKey, endKey)) {
                    if (key.startsWith('BIO_') || key.startsWith('ORG_') || key.startsWith('ATTESTATION_') || key.startsWith('SERVICE_ACCESS_')) {
                        continue; // Skip non-identity records
                    }

                    const strValue = Buffer.from(value).toString('utf8');
                    let record;
                    try {
                        record = JSON.parse(strValue);
                    } catch (err) {
                        console.log(err);
                        record = strValue;
                    }
                    allResults.push({Key: key, Record: record});

                    if (allResults.length >= pageSize) {
                        break;
                    }
                }

                return JSON.stringify(allResults);
            }

            // Helper methods

            async _getOrganization(ctx, orgId) {
                const orgBytes = await ctx.stub.getState(`ORG_${orgId}`);
                if (!orgBytes || orgBytes.length === 0) {
                    return null;
                }
                return JSON.parse(orgBytes.toString());
            }

            async _performAIVerification(originalHash, challengeHash) {
                // Simulate AI-enhanced biometric matching
                // In real implementation, this would call external AI service
                const similarity = this._calculateBiometricSimilarity(originalHash, challengeHash);

                return {
                    result: similarity >= 0.8 ? 'MATCH' : 'NO_MATCH',
                    confidenceScore: Math.round(similarity * 100),
                    algorithm: 'AI_MULTIMODAL_FUSION',
                    timestamp: new Date().toISOString()
                };
            }

            _calculateBiometricSimilarity(hash1, hash2) {
                // Simplified similarity calculation for demo
                // In real implementation, this would use advanced AI algorithms
                if (hash1 === hash2) return 1.0;

                // Simulate some variance in biometric matching
                const hammingDistance = this._hammingDistance(hash1, hash2);
                const maxDistance = Math.max(hash1.length, hash2.length) * 4; // Hex chars
                const similarity = 1 - (hammingDistance / maxDistance);

                // Add some AI-based confidence adjustment
                const aiAdjustment = 0.05 * (Math.random() - 0.5); // ±2.5% random adjustment
                return Math.max(0, Math.min(1, similarity + aiAdjustment));
            }

            _hammingDistance(str1, str2) {
                let distance = 0;
                const length = Math.min(str1.length, str2.length);

                for (let i = 0; i < length; i++) {
                    if (str1[i] !== str2[i]) {
                        distance++;
                    }
                }

                distance += Math.abs(str1.length - str2.length);
                return distance;
            }

            _generateId() {
                return crypto.randomBytes(16).toString('hex');
            }

            _calculateExpirationDate(attestationType) {
                const expirationMonths = {
                    'EDUCATION': 60,    // 5 years
                    'HEALTH': 12,       // 1 year
                    'EMPLOYMENT': 24,   // 2 years
                    'RESIDENCE': 36     // 3 years
                };

                const months = expirationMonths[attestationType] || 12;
                const expiration = new Date();
                expiration.setMonth(expiration.getMonth() + months);
                return expiration.toISOString();
            }

            _calculateServiceExpiration(serviceType) {
                const expirationDays = {
                    'BANKING': 365,     // 1 year
                    'EDUCATION': 1095,  // 3 years
                    'HEALTHCARE': 365,  // 1 year
                    'AID': 90          // 3 months
                };

                const days = expirationDays[serviceType] || 365;
                const expiration = new Date();
                expiration.setDate(expiration.getDate() + days);
                return expiration.toISOString();
            }

            _calculateCrossBorderExpiration() {
                const expiration = new Date();
                expiration.setFullYear(expiration.getFullYear() + 2); // 2 years
                return expiration.toISOString();
            }

            _getServiceRequirements(serviceType) {
                const requirements = {
                    'BANKING': {minVerificationLevel: 'HIGH', requiredAttestations: ['IDENTITY']},
                    'EDUCATION': {minVerificationLevel: 'MEDIUM', requiredAttestations: ['IDENTITY']},
                    'HEALTHCARE': {minVerificationLevel: 'LOW', requiredAttestations: ['IDENTITY']},
                    'AID': {minVerificationLevel: 'LOW', requiredAttestations: ['IDENTITY']}
                };

                return requirements[serviceType] || {
                    minVerificationLevel: 'MEDIUM',
                    requiredAttestations: ['IDENTITY']
                };
            }

            /**
             * Add attestation to identity (education, health, etc.)
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Target identity
             * @param {string} attestationType - Type of attestation
             * @param {string} encryptedData - Encrypted attestation data
             * @param {string} issuerId - Issuing organization
             */
            async addAttestation(ctx, identityId, attestationType, encryptedData, issuerId) {
                console.info('============= START : Add Attestation ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate issuer permissions
                const issuer = await this._getOrganization(ctx, issuerId);
                if (!issuer || !issuer.permissions.includes('ATTEST')) {
                    throw new Error(`Organization ${issuerId} not authorized to issue attestations`);
                }

                // Create attestation
                const attestation = {
                    attestationId: this._generateId(),
                    type: attestationType,
                    encryptedData: encryptedData,
                    issuerId: issuerId,
                    issueTimestamp: new Date().toISOString(),
                    expirationDate: this._calculateExpirationDate(attestationType),
                    status: 'ACTIVE',
                    verificationHash: crypto.createHash('sha256')
                        .update(identityId + attestationType + encryptedData + issuerId)
                        .digest('hex')
                };

                // Add to identity attestations
                identity.attestations.push(attestation);
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store attestation separately for querying
                await ctx.stub.putState(
                    `ATTESTATION_${attestation.attestationId}`,
                    Buffer.from(JSON.stringify(attestation))
                );

                // Emit attestation event
                const eventPayload = {
                    identityId: identityId,
                    attestationId: attestation.attestationId,
                    type: attestationType,
                    issuerId: issuerId,
                    timestamp: attestation.issueTimestamp,
                    eventType: 'ATTESTATION_ADDED'
                };
                ctx.stub.setEvent('AttestationAdded', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Add Attestation ===========');
                return JSON.stringify(attestation);
            }

            /**
             * Grant service access with selective disclosure
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Identity requesting access
             * @param {string} serviceProviderId - Service provider ID
             * @param {string} serviceType - Type of service (BANKING, EDUCATION, HEALTHCARE, AID)
             * @param {string} requiredAttributes - JSON string of required attributes
             */
            async grantServiceAccess(ctx, identityId, serviceProviderId, serviceType, requiredAttributes) {
                console.info('============= START : Grant Service Access ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate service provider
                const serviceProvider = await this._getOrganization(ctx, serviceProviderId);
                if (!serviceProvider || !serviceProvider.permissions.includes('SERVICE')) {
                    throw new Error(`Organization ${serviceProviderId} not authorized to provide services`);
                }

                // Check verification level requirements
                const serviceRequirements = this._getServiceRequirements(serviceType);
                if (identity.verificationLevel === 'LOW' && serviceRequirements.minVerificationLevel !== 'LOW') {
                    throw new Error(`Insufficient verification level for service ${serviceType}`);
                }

                // Create service access record with zero-knowledge proof simulation
                const serviceAccess = {
                    accessId: this._generateId(),
                    serviceProviderId: serviceProviderId,
                    serviceType: serviceType,
                    requiredAttributes: JSON.parse(requiredAttributes),
                    grantedTimestamp: new Date().toISOString(),
                    expirationDate: this._calculateServiceExpiration(serviceType),
                    status: 'ACTIVE',
                    accessCount: 0,
                    zkProofHash: crypto.createHash('sha256')
                        .update(identityId + serviceType + requiredAttributes)
                        .digest('hex')
                };

                // Add to identity service access
                identity.serviceAccess.push(serviceAccess);
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store service access record
                await ctx.stub.putState(
                    `SERVICE_ACCESS_${serviceAccess.accessId}`,
                    Buffer.from(JSON.stringify(serviceAccess))
                );

                // Emit service access event
                const eventPayload = {
                    identityId: identityId,
                    accessId: serviceAccess.accessId,
                    serviceProviderId: serviceProviderId,
                    serviceType: serviceType,
                    timestamp: serviceAccess.grantedTimestamp,
                    eventType: 'SERVICE_ACCESS_GRANTED'
                };
                ctx.stub.setEvent('ServiceAccessGranted', Buffer.from(JSON.stringify(eventPayload)));

                console.info('============= END : Grant Service Access ===========');
                return JSON.stringify(serviceAccess);
            }

            /**
             * Enable cross-border identity portability
             * @param {Context} ctx - Transaction context
             * @param {string} identityId - Identity to make portable
             * @param {string} destinationCountry - Destination country code
             * @param {string} authorizingOrg - Authorizing organization
             */
            async enableCrossBorderAccess(ctx, identityId, destinationCountry, authorizingOrg) {
                console.info('============= START : Enable Cross-Border Access ===========');

                // Get identity record
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }

                const identity = JSON.parse(identityBytes.toString());

                // Validate authorizing organization
                const authorizer = await this._getOrganization(ctx, authorizingOrg);
                if (!authorizer) {
                    throw new Error(`Organization ${authorizingOrg} not found`);
                }

                // Create cross-border record
                const crossBorderAccess = {
                    accessId: this._generateId(),
                    destinationCountry: destinationCountry,
                    authorizingOrg: authorizingOrg,
                    authorizedTimestamp: new Date().toISOString(),
                    validUntil: this._calculateCrossBorderExpiration(),
                    status: 'AUTHORIZED',
                    portabilityHash: crypto.createHash('sha256')
                        .update(identityId + destinationCountry + authorizingOrg)
                        .digest('hex')
                };

                // Update identity
                identity.crossBorderStatus = 'AUTHORIZED';
                identity.crossBorderAccess = crossBorderAccess;
                identity.lastUpdated = new Date().toISOString();
                identity.version += 1;

                await ctx.stub.putState(identityId, Buffer.from(JSON.stringify(identity)));

                // Store cross-border record
                await ctx.stub.putState(
                    `CROSS_BORDER_${crossBorderAccess.accessId}`,
                    Buffer.from(JSON.stringify(crossBorderAccess))
                );

                console.info('============= END : Enable Cross-Border Access ===========');
                return JSON.stringify(crossBorderAccess);
            }

            /**
             * Query identity by ID
             */
            async queryIdentity(ctx, identityId) {
                const identityBytes = await ctx.stub.getState(identityId);
                if (!identityBytes || identityBytes.length === 0) {
                    throw new Error(`Identity ${identityId} does not exist`);
                }
                return identityBytes.toString();
            }

            /**
             * Query identity by biometric hash
             */
            async queryIdentityByBiometric(ctx, biometricHash) {
                const indexBytes = await ctx.stub.getState(`BIO_${biometricHash}`);
                if (!indexBytes || indexBytes.length === 0) {
                    throw new Error(`No identity found for biometric hash`);
                }

                const index = JSON.parse(indexBytes.toString());
                return await this.queryIdentity(ctx, index.identityId);
            }

            /**
             * Get all identities (with pagination for scalability)
             */
            async getAllIdentities(ctx, startKey = '', endKey = '', pageSize = 100) {
                const allResults = [];

                for await (const {key, value} of ctx.stub.getStateByRange(startKey, endKey)) {
                    if (key.startsWith('BIO_') || key.startsWith('ORG_') || key.startsWith('ATTESTATION_') || key.startsWith('SERVICE_ACCESS_')) {
                        continue; // Skip non-identity records
                    }

                    const strValue = Buffer.from(value).toString('utf8');
                    let record;
                    try {
                        record = JSON.parse(strValue);
                    } catch (err) {
                        console.log(err);
                        record = strValue;
                    }
                    allResults.push({Key: key, Record: record});

                    if (allResults.length >= pageSize) {
                        break;
                    }
                }

                return JSON.stringify(allResults);
            }
        }
    }
}

module.exports = RefugeeIdentityChaincode;
