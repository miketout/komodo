/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS initialization, notarization, and cross-chain token
 * transactions and enabling liquid or non-liquid tokens across the
 * Verus ecosystem.
 * 
 * 
 */

#ifndef PBAAS_H
#define PBAAS_H

#include <vector>
#include <univalue.h>

#include "cc/CCinclude.h"
#include "streams.h"
#include "script/script.h"
#include "amount.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/reserves.h"
#include "mmr.h"

#include <boost/algorithm/string.hpp>

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex, bool fIncludeAsm=true);

class CPBaaSNotarization;

// these are output cryptoconditions for the Verus reserve liquidity system
// VRSC can be proxied to other PBaaS chains and sent back for use with this system
// The assumption that Verus is either the proxy on the PBaaS chain or the native
// coin on Verus enables us to reduce data requirements systemwide

// this is for transaction outputs with a Verus proxy on a PBaaS chain cryptoconditions with these outputs
// must also be funded with the native chain for fees, unless the chain is a Verus reserve chain, in which
// case the fee will be autoconverted from the Verus proxy through the conversion rules of this chain

static const uint32_t PBAAS_NODESPERNOTARIZATION = 2;       // number of nodes to reference in each notarization
static const int64_t PBAAS_MINNOTARIZATIONOUTPUT = 10000;   // enough for one fee worth to finalization and notarization thread
static const int32_t PBAAS_MINSTARTBLOCKDELTA = 50;         // minimum number of blocks to wait for starting a chain after definition
static const int32_t PBAAS_MAXPRIORBLOCKS = 16;             // maximum prior block commitments to include in prior blocks chain object

// we wil uncomment service types as they are implemented
// commented service types are here as guidance and reminders
enum PBAAS_SERVICE_TYPES {
    SERVICE_INVALID = 0,
    SERVICE_NOTARIZATION = 1,
    SERVICE_LAST = 1
};

// these are object types that can be stored and recognized in an opret array
enum CHAIN_OBJECT_TYPES
{
    CHAINOBJ_INVALID = 0,
    CHAINOBJ_HEADER = 1,            // serialized full block header w/proof
    CHAINOBJ_HEADER_REF = 2,        // equivalent to header, but only includes non-canonical data
    CHAINOBJ_TRANSACTION_PROOF = 3,       // serialized transaction or partial transaction with proof
    CHAINOBJ_PROOF_ROOT = 4,        // merkle proof of preceding block or transaction
    CHAINOBJ_PRIORBLOCKS = 5,       // prior block commitments to ensure recognition of overlapping notarizations
    CHAINOBJ_RESERVETRANSFER = 6,   // serialized transaction, sometimes without an opret, which will be reconstructed
    CHAINOBJ_COMPOSITEOBJECT = 7,   // can hold and index a variety and multiplicity of objects
    CHAINOBJ_CROSSCHAINPROOF = 8    // specific composite object, which is a single or multi-proof
};

// the proof of an opret output, which is simply the types of objects and hashes of each
class COpRetProof
{
public:
    uint32_t orIndex;                   // index into the opret objects to begin with
    std::vector<uint8_t>    types;
    std::vector<uint256>    hashes;

    COpRetProof() : orIndex(0), types(0), hashes(0) {}
    COpRetProof(std::vector<uint8_t> &rTypes, std::vector<uint256> &rHashes, uint32_t opretIndex = 0) : types(rTypes), hashes(rHashes), orIndex(opretIndex) {}

    void AddObject(CHAIN_OBJECT_TYPES typeCode, uint256 objHash)
    {
        types.push_back(typeCode);
        hashes.push_back(objHash);
    }

    template <typename CHAINOBJTYPE>
    void AddObject(CHAINOBJTYPE &co, uint256 objHash)
    {
        types.push_back(ObjTypeCode(co));
        hashes.push_back(objHash);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(orIndex);
        READWRITE(types);
        READWRITE(hashes);
    }
};

class CHeaderRef
{
public:
    uint256 hash;               // block hash
    CPBaaSPreHeader preHeader;  // non-canonical pre-header data of source chain

    CHeaderRef() : hash() {}
    CHeaderRef(uint256 &rHash, CPBaaSPreHeader ph) : hash(rHash), preHeader(ph) {}
    CHeaderRef(const CBlockHeader &bh) : hash(bh.GetHash()), preHeader(bh) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(hash);
        READWRITE(preHeader);
    }

    uint256 GetHash() { return hash; }
};

class CPriorBlocksCommitment
{
public:
    std::vector<uint256> priorBlocks;       // prior block commitments, which are node hashes that include merkle root, block hash, and compact power
    uint256 pastBlockType;                  // 1 = POS, 0 = POW indicators for past blocks, enabling selective, pseudorandom proofs of past blocks by type

    CPriorBlocksCommitment() : priorBlocks() {}
    CPriorBlocksCommitment(const std::vector<uint256> &priors, const uint256 &pastTypes) : priorBlocks(priors), pastBlockType(pastTypes) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(priorBlocks);
        READWRITE(pastBlockType);
    }
};

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

class CBaseChainObject
{
public:
    uint16_t objectType;                    // type of object, such as blockheader, transaction, proof, tokentx, etc.

    CBaseChainObject() : objectType(CHAINOBJ_INVALID) {}
    CBaseChainObject(uint16_t objType) : objectType(objType) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(objectType);
    }
};

template <typename SERIALIZABLE>
class CChainObject : public CBaseChainObject
{
public:
    SERIALIZABLE object;                    // the actual object

    CChainObject() : CBaseChainObject() {}

    CChainObject(uint16_t objType, const SERIALIZABLE &rObject) : CBaseChainObject(objType), object(rObject) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*(CBaseChainObject *)this);
        READWRITE(object);
    }

    uint256 GetHash() const
    {
        CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);

        hw << object;
        return GetHash();
    }
};

// each notarization will have an opret object that contains various kind of proof of the notarization itself
// as well as recent POW and POS headers and entropy sources.
class CCrossChainProof
{
public:
    enum
    {
        VERSION_INVALID = 0,
        VERSION_FIRST = 1,
        VERSION_CURRENT = 1,
        VERSION_LAST = 1
    };
    uint32_t version;
    std::vector<CBaseChainObject *> chainObjects;    // this owns the memory associated with chainObjects and deletes it on destructions

    CCrossChainProof() : version(VERSION_CURRENT) {}
    CCrossChainProof(const CCrossChainProof &oldObj)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << oldObj;
        s >> *this;
    }
    CCrossChainProof(const std::vector<CBaseChainObject *> &objects, int Version=VERSION_CURRENT) : version(Version), chainObjects(objects) { }

    ~CCrossChainProof()
    {
        DeleteOpRetObjects(chainObjects);
        version = VERSION_INVALID;
    }

    const CCrossChainProof &operator=(const CCrossChainProof &operand)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << operand;
        DeleteOpRetObjects(chainObjects);
        s >> *this;
        return *this;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        if (ser_action.ForRead())
        {
            int32_t proofSize;
            READWRITE(VARINT(proofSize));

            bool error = false;
            for (int i = 0; i < proofSize && !error; i++)
            {
                try
                {
                    uint16_t objType;
                    READWRITE(objType);
                    union {
                        CChainObject<CBlockHeaderAndProof> *pNewHeader;
                        CChainObject<CPartialTransactionProof> *pNewTx;
                        CChainObject<uint256> *pNewProof;
                        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
                        CChainObject<CPriorBlocksCommitment> *pPriors;
                        CChainObject<CReserveTransfer> *pExport;
                        CChainObject<CCrossChainProof> *pCrossChainProof;
                        CBaseChainObject *pobj;
                    };

                    pobj = nullptr;

                    switch(objType)
                    {
                        case CHAINOBJ_HEADER:
                        {
                            CBlockHeaderAndProof obj;
                            READWRITE(obj);
                            pNewHeader = new CChainObject<CBlockHeaderAndProof>();
                            if (pNewHeader)
                            {
                                pNewHeader->objectType = objType;
                                pNewHeader->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_TRANSACTION_PROOF:
                        {
                            CPartialTransactionProof obj;
                            READWRITE(obj);
                            pNewTx = new CChainObject<CPartialTransactionProof>();
                            if (pNewTx)
                            {
                                pNewTx->objectType = objType;
                                pNewTx->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_PROOF_ROOT:
                        {
                            uint256 obj;
                            READWRITE(obj);
                            pNewProof = new CChainObject<uint256>();
                            if (pNewProof)
                            {
                                pNewProof->objectType = objType;
                                pNewProof->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_HEADER_REF:
                        {
                            CBlockHeaderProof obj;
                            READWRITE(obj);
                            pNewHeaderRef = new CChainObject<CBlockHeaderProof>();
                            if (pNewHeaderRef)
                            {
                                pNewHeaderRef->objectType = objType;
                                pNewHeaderRef->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_PRIORBLOCKS:
                        {
                            CPriorBlocksCommitment obj;
                            READWRITE(obj);
                            pPriors = new CChainObject<CPriorBlocksCommitment>();
                            if (pPriors)
                            {
                                pPriors->objectType = objType;
                                pPriors->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_RESERVETRANSFER:
                        {
                            CReserveTransfer obj;
                            READWRITE(obj);
                            pExport = new CChainObject<CReserveTransfer>();
                            if (pExport)
                            {
                                pExport->objectType = objType;
                                pExport->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_CROSSCHAINPROOF:
                        {
                            CCrossChainProof obj;
                            READWRITE(obj);
                            pCrossChainProof = new CChainObject<CCrossChainProof>();
                            if (pCrossChainProof)
                            {
                                pCrossChainProof->objectType = objType;
                                pCrossChainProof->object = obj;
                            }
                            break;
                        }
                        case CHAINOBJ_COMPOSITEOBJECT:
                        {
                            CCrossChainProof obj;
                            READWRITE(obj);
                            pCrossChainProof = new CChainObject<CCrossChainProof>();
                            if (pCrossChainProof)
                            {
                                pCrossChainProof->objectType = CHAINOBJ_COMPOSITEOBJECT;
                                pCrossChainProof->object = obj;
                            }
                            break;
                        }
                    }

                    if (pobj)
                    {
                        //printf("%s: storing object, code %u\n", __func__, objType);
                        chainObjects.push_back(pobj);
                    }
                }
                catch(const std::exception& e)
                {
                    error = true;
                    break;
                }
            }

            if (error)
            {
                printf("%s: ERROR: opret is likely corrupt\n", __func__);
                LogPrintf("%s: ERROR: opret is likely corrupt\n", __func__);
                DeleteOpRetObjects(chainObjects);
            }
        }
        else
        {
            //printf("entering CCrossChainProof serialize\n");
            int32_t proofSize = chainObjects.size();
            READWRITE(VARINT(proofSize));
            for (auto &oneVal : chainObjects)
            {
                DehydrateChainObject(s, oneVal);
            }
        }
    }

    bool IsValid() const
    {
        return (version >= VERSION_FIRST || version <= VERSION_LAST);
    }

    bool Empty() const
    {
        return chainObjects.size() == 0;
    }

    const std::vector<uint16_t> TypeVector() const
    {
        std::vector<uint16_t> retVal;
        for (auto &pChainObj : chainObjects)
        {
            if (pChainObj)
            {
                retVal.push_back(pChainObj->objectType);
            }
        }
        return retVal;
    }

    const CCrossChainProof &operator<<(const CPartialTransactionProof &partialTxProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CPartialTransactionProof>(CHAINOBJ_TRANSACTION_PROOF, partialTxProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBlockHeaderAndProof &headerRefProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderAndProof>(CHAINOBJ_HEADER_REF, headerRefProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CBlockHeaderProof &headerProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CBlockHeaderProof>(CHAINOBJ_HEADER, headerProof)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CPriorBlocksCommitment &priorBlocks)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CPriorBlocksCommitment>(CHAINOBJ_PRIORBLOCKS, priorBlocks)));
        return *this;
    }

    const CCrossChainProof &operator<<(const uint256 &proofRoot)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<uint256>(CHAINOBJ_PROOF_ROOT, proofRoot)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CReserveTransfer &reserveTransfer)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CReserveTransfer>(CHAINOBJ_RESERVETRANSFER, reserveTransfer)));
        return *this;
    }

    const CCrossChainProof &operator<<(const CCrossChainProof &crossChainProof)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CCrossChainProof>(CHAINOBJ_CROSSCHAINPROOF, crossChainProof)));
        return *this;
    }
};

// this must remain cast/data compatible with CCompositeChainObject
class CCompositeChainObject : public CCrossChainProof
{
public:
    CCompositeChainObject() : CCrossChainProof() {}
    CCompositeChainObject(const std::vector<CBaseChainObject *> &proofs, int Version=VERSION_CURRENT) : 
        CCrossChainProof(proofs, Version) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CCrossChainProof *)this);
    }

    const CCompositeChainObject &operator<<(const CCompositeChainObject &compositeChainObject)
    {
        chainObjects.push_back(static_cast<CBaseChainObject *>(new CChainObject<CCompositeChainObject>(CHAINOBJ_COMPOSITEOBJECT, compositeChainObject)));
        return *this;
    }
};

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo);

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
CBaseChainObject *RehydrateChainObject(OStream &s)
{
    int16_t objType;

    try
    {
        s >> objType;
    }
    catch(const std::exception& e)
    {
        return NULL;
    }

    union {
        CChainObject<CBlockHeaderAndProof> *pNewHeader;
        CChainObject<CPartialTransactionProof> *pNewTx;
        CChainObject<uint256> *pNewProof;
        CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        CChainObject<CPriorBlocksCommitment> *pPriors;
        CChainObject<CReserveTransfer> *pExport;
        CChainObject<CCrossChainProof> *pCrossChainProof;
        CChainObject<CCompositeChainObject> *pCompositeChainObject;
        CBaseChainObject *retPtr;
    };

    retPtr = NULL;

    switch(objType)
    {
        case CHAINOBJ_HEADER:
            pNewHeader = new CChainObject<CBlockHeaderAndProof>();
            if (pNewHeader)
            {
                s >> pNewHeader->object;
                pNewHeader->objectType = objType;
            }
            break;
        case CHAINOBJ_TRANSACTION_PROOF:
            pNewTx = new CChainObject<CPartialTransactionProof>();
            if (pNewTx)
            {
                s >> pNewTx->object;
                pNewTx->objectType = objType;
            }
            break;
        case CHAINOBJ_PROOF_ROOT:
            pNewProof = new CChainObject<uint256>();
            if (pNewProof)
            {
                s >> pNewProof->object;
                pNewProof->objectType = objType;
            }
            break;
        case CHAINOBJ_HEADER_REF:
            pNewHeaderRef = new CChainObject<CBlockHeaderProof>();
            if (pNewHeaderRef)
            {
                s >> pNewHeaderRef->object;
                pNewHeaderRef->objectType = objType;
            }
            break;
        case CHAINOBJ_PRIORBLOCKS:
            pPriors = new CChainObject<CPriorBlocksCommitment>();
            if (pPriors)
            {
                s >> pPriors->object;
                pPriors->objectType = objType;
            }
            break;
        case CHAINOBJ_RESERVETRANSFER:
            pExport = new CChainObject<CReserveTransfer>();
            if (pExport)
            {
                s >> pExport->object;
                pExport->objectType = objType;
            }
            break;
        case CHAINOBJ_CROSSCHAINPROOF:
            pCrossChainProof = new CChainObject<CCrossChainProof>();
            if (pCrossChainProof)
            {
                s >> pCrossChainProof->object;
                pCrossChainProof->objectType = objType;
            }
            break;
        case CHAINOBJ_COMPOSITEOBJECT:
            pCompositeChainObject = new CChainObject<CCompositeChainObject>();
            if (pCompositeChainObject)
            {
                s >> pCompositeChainObject->object;
                pCompositeChainObject->objectType = objType;
            }
            break;
    }
    return retPtr;
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
template <typename OStream>
bool DehydrateChainObject(OStream &s, const CBaseChainObject *pobj)
{
    switch(pobj->objectType)
    {
        case CHAINOBJ_HEADER:
        {
            s << *(CChainObject<CBlockHeaderAndProof> *)pobj;
            return true;
        }

        case CHAINOBJ_TRANSACTION_PROOF:
        {
            s << *(CChainObject<CPartialTransactionProof> *)pobj;
            return true;
        }

        case CHAINOBJ_PROOF_ROOT:
        {
            s << *(CChainObject<uint256> *)pobj;
            return true;
        }

        case CHAINOBJ_HEADER_REF:
        {
            s << *(CChainObject<CBlockHeaderProof> *)pobj;
            return true;
        }

        case CHAINOBJ_PRIORBLOCKS:
        {
            s << *(CChainObject<CPriorBlocksCommitment> *)pobj;
            return true;
        }

        case CHAINOBJ_RESERVETRANSFER:
        {
            s << *(CChainObject<CReserveTransfer> *)pobj;
            return true;
        }
        case CHAINOBJ_CROSSCHAINPROOF:
        {
            s << *(CChainObject<CCrossChainProof> *)pobj;
            return true;
        }
        case CHAINOBJ_COMPOSITEOBJECT:
        {
            s << *(CChainObject<CCompositeChainObject> *)pobj;
            return true;
        }
    }
    return false;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj);

int8_t ObjTypeCode(const CPartialTransactionProof &obj);

int8_t ObjTypeCode(const CBlockHeaderProof &obj);

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj);

int8_t ObjTypeCode(const CReserveTransfer &obj);

int8_t ObjTypeCode(const CCrossChainProof &obj);

int8_t ObjTypeCode(const CCompositeChainObject &obj);

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs);

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora);

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript);

// This data structure is used on an output that provides proof of stake validation for other crypto conditions
// with rate limited spends based on a PoS contest
class CPoSSelector
{
public:
    uint32_t nBits;                         // PoS difficulty target
    uint32_t nTargetSpacing;                // number of 1/1000ths of a block between selections (e.g. 1 == 1000 selections per block)

    CPoSSelector(uint32_t bits, uint32_t TargetSpacing)
    {
        nBits = bits; 
        nTargetSpacing = TargetSpacing;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBits);
        READWRITE(nTargetSpacing);
    }

    CPoSSelector(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nBits != 0;
    }
};

// Additional data for an output pool used for a PBaaS chain's reward for service, such as mining, staking, node or electrum service
class CServiceReward
{
public:
    uint32_t nVersion;                      // version of this chain definition data structure to allow for extensions (not daemon version)
    uint16_t serviceType;                   // type of service
    int32_t billingPeriod;                  // this is used to identify to which billing period of a chain, this reward applies

    CServiceReward() : nVersion(PBAAS_VERSION_INVALID), serviceType(SERVICE_INVALID) {}

    CServiceReward(PBAAS_SERVICE_TYPES ServiceType, int32_t period) : nVersion(PBAAS_VERSION), serviceType(ServiceType), billingPeriod(period) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(serviceType);
        READWRITE(billingPeriod);
    }

    CServiceReward(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CServiceReward(const UniValue &obj) : nVersion(PBAAS_VERSION)
    {
        serviceType = uni_get_str(find_value(obj, "servicetype")) == "notarization" ? SERVICE_NOTARIZATION : SERVICE_INVALID;
        billingPeriod = uni_get_int(find_value(obj, "billingperiod"));
        if (!billingPeriod)
        {
            serviceType = SERVICE_INVALID;
        }
    }

    CServiceReward(const CTransaction &tx, bool validate = false);

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("servicetype", serviceType == SERVICE_NOTARIZATION ? "notarization" : "unknown"));
        obj.push_back(Pair("billingperiod", billingPeriod));
        return obj;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return serviceType != SERVICE_INVALID;
    }
};

class CInputDescriptor
{
public:
    CScript scriptPubKey;
    CAmount nValue;
    CTxIn txIn;
    CInputDescriptor() : nValue(0) {}
    CInputDescriptor(CScript script, CAmount value, CTxIn input) : scriptPubKey(script), nValue(value), txIn(input) {}
};

class CRPCChainData
{
public:
    CCurrencyDefinition chainDefinition;  // chain information for the specific chain
    std::string     rpcHost;                // host of the chain's daemon
    int32_t         rpcPort;                // port of the chain's daemon
    std::string     rpcUserPass;            // user and password for this daemon

    CRPCChainData() {}
    CRPCChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass) :
        chainDefinition(chainDef), rpcHost{host}, rpcPort(port), rpcUserPass(userPass) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return chainDefinition.IsValid();
    }

    uint160 GetID()
    {
        return chainDefinition.GetID();
    }
};

// Each merge mined chain gets an entry that includes information required to connect to a live daemon
// for that block, cross notarize, and validate notarizations.
class CPBaaSMergeMinedChainData : public CRPCChainData
{
public:
    static const uint32_t MAX_MERGE_CHAINS = 15;
    CBlock          block;                  // full block to submit upon winning header

    CPBaaSMergeMinedChainData() {}
    CPBaaSMergeMinedChainData(CCurrencyDefinition &chainDef, std::string host, int32_t port, std::string userPass, CBlock &blk) :
        CRPCChainData(chainDef, host, port, userPass), block(blk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(chainDefinition);
        READWRITE(rpcHost);
        READWRITE(rpcPort);
        READWRITE(rpcUserPass);
        READWRITE(block);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

class CConnectedChains
{
protected:
    CPBaaSMergeMinedChainData *GetChainInfo(uint160 chainID);

public:
    std::map<uint160, CPBaaSMergeMinedChainData> mergeMinedChains;
    std::map<arith_uint256, CPBaaSMergeMinedChainData *> mergeMinedTargets;
    std::map<uint160, CCurrencyDefinition> currencyDefCache;                            // protected by cs_main, which is used for lookup

    std::string notaryChainVersion;
    int32_t notaryChainHeight;
    CRPCChainData notaryChain;                  // notary chain information

    // if this is a fractional, liquid currency, reserve definitions go here
    std::map<uint160, CCurrencyDefinition> reserveCurrencies;

    CCurrencyDefinition thisChain;
    bool readyToStart;
    std::vector<CNodeData> defaultPeerNodes;    // updated by notarizations
    std::vector<std::pair<int, CScript>> latestMiningOutputs; // accessible from all merge miners - can be invalid
    CTxDestination  latestDestination;          // latest destination from miner output 0 - can be invalid
    int64_t lastAggregation = 0;                // adjusted time of last aggregation

    int32_t earnedNotarizationHeight;           // zero or the height of one or more potential submissions
    CBlock earnedNotarizationBlock;
    int32_t earnedNotarizationIndex;            // index of earned notarization in block

    bool dirty;
    bool lastSubmissionFailed;                  // if we submit a failed block, make another
    std::map<arith_uint256, CBlockHeader> qualifiedHeaders;

    CCriticalSection cs_mergemining;
    CSemaphore sem_submitthread;

    CConnectedChains() : readyToStart(0), sem_submitthread(0), earnedNotarizationHeight(0), dirty(0), lastSubmissionFailed(0) {}

    arith_uint256 LowestTarget()
    {
        if (mergeMinedTargets.size())
        {
            return mergeMinedTargets.begin()->first;
        }
        else
        {
            return arith_uint256(0);
        }
    }

    void SubmissionThread();
    static void SubmissionThreadStub();
    std::vector<std::pair<std::string, UniValue>> SubmitQualifiedBlocks();

    void QueueNewBlockHeader(CBlockHeader &bh);
    void QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height);
    void CheckImports();
    void SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions);
    // send new imports from this chain to the specified chain, which generally will be the notary chain
    void ProcessLocalImports();

    bool AddMergedBlock(CPBaaSMergeMinedChainData &blkData);
    bool RemoveMergedBlock(uint160 chainID);
    bool GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData);
    void PruneOldChains(uint32_t pruneBefore);
    uint32_t CombineBlocks(CBlockHeader &bh);

    // returns false if destinations are empty or first is not either pubkey or pubkeyhash
    bool SetLatestMiningOutputs(const std::vector<std::pair<int, CScript>> &minerOutputs, CTxDestination &firstDestinationOut);
    void AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight);
    CCurrencyDefinition GetCachedCurrency(const uint160 &currencyID);

    bool NewImportNotarization(const CCurrencyDefinition &_curDef, 
                               uint32_t height, 
                               const CTransaction &lastImportTx, 
                               uint32_t exportHeight, 
                               const CTransaction &exportTx, 
                               CMutableTransaction &mnewTx,
                               CCoinbaseCurrencyState &newCurState);

    bool GetLastImport(const uint160 &systemID, 
                       CTransaction &lastImport, 
                       CPartialTransactionProof &crossChainExport, 
                       CCrossChainImport &ccImport, 
                       CCrossChainExport &ccCrossExport);

    // returns newly created import transactions to the specified chain from exports on this chain specified chain
    bool CreateLatestImports(const CCurrencyDefinition &chainDef, 
                             const CTransaction &lastCrossChainImport, 
                             const CTransaction &importTxTemplate,
                             const CTransaction &lastConfirmedNotarization,
                             const CCurrencyValueMap &totalAvailableInput,
                             CAmount TotalNativeInput,
                             std::vector<CTransaction> &newImports);

    CRPCChainData &NotaryChain()
    {
        return notaryChain;
    }

    uint32_t NotaryChainHeight();

    CCurrencyDefinition &ThisChain()
    {
        return thisChain;
    }

    int GetThisChainPort() const;

    CCoinbaseCurrencyState GetCurrencyState(int32_t height);

    bool CheckVerusPBaaSAvailable(UniValue &chainInfo, UniValue &chainDef);
    bool CheckVerusPBaaSAvailable();      // may use RPC to call Verus
    bool IsVerusPBaaSAvailable();
    std::vector<CCurrencyDefinition> GetMergeMinedChains()
    {
        std::vector<CCurrencyDefinition> ret;
        LOCK(cs_mergemining);
        for (auto &chain : mergeMinedChains)
        {
            ret.push_back(chain.second.chainDefinition);
        }
        return ret;
    }

    const std::map<uint160, CCurrencyDefinition> &ReserveCurrencies()
    {
        return reserveCurrencies;
    }

    bool LoadReserveCurrencies();
};

template <typename TOBJ>
CTxOut MakeCC1of1Vout(uint8_t evalcode, CAmount nValue, CPubKey pk, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    assert(vDest.size() < 256);

    CTxOut vout;
    CC *payoutCond = MakeCCcond1(evalcode, pk);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1ofAnyVout(uint8_t evalcode, CAmount nValue, std::vector<CTxDestination> vDest, const TOBJ &obj, const CPubKey &pk=CPubKey())
{
    // if pk is valid, we will make sure that it is one of the signature options on this CC
    if (pk.IsValid())
    {
        CCcontract_info C;
        CCcontract_info *cp;
        cp = CCinit(&C, evalcode);
        int i;
        bool addPubKey = false;
        for (i = 0; i < vDest.size(); i++)
        {
            CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), vDest[i]));
            if ((oneKey.IsValid() && oneKey == pk) || CKeyID(GetDestinationID(vDest[i])) == pk.GetID())
            {
                // found, so don't add
                break;
            }
        }
        // if not found, add the pubkey
        if (i >= vDest.size())
        {
            vDest.push_back(CTxDestination(pk));
        }
    }

    CTxOut vout;
    CC *payoutCond = MakeCCcondAny(evalcode, vDest);
    vout = CTxOut(nValue, CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 0, (uint8_t)(vDest.size()), vDest, vvch);

    for (auto dest : vDest)
    {
        CPubKey oneKey(boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), dest));
        std::vector<unsigned char> bytes = GetDestinationBytes(dest);
        if ((!oneKey.IsValid() && bytes.size() != 20) || (bytes.size() != 33 && bytes.size() != 20))
        {
            printf("Invalid destination %s\n", EncodeDestination(dest).c_str());
        }
    }

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, 2, vpk, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

template <typename TOBJ>
CTxOut MakeCC1of2Vout(uint8_t evalcode, CAmount nValue, CPubKey pk1, CPubKey pk2, std::vector<CTxDestination> vDest, const TOBJ &obj)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode, pk1, pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);

    std::vector<CPubKey> vpk({pk1, pk2});
    std::vector<std::vector<unsigned char>> vvch({::AsVector((const TOBJ)obj)});
    COptCCParams vParams = COptCCParams(COptCCParams::VERSION_V2, evalcode, 1, (uint8_t)(vDest.size()), vDest, vvch);

    // add the object to the end of the script
    vout.scriptPubKey << vParams.AsVector() << OP_DROP;
    return(vout);
}

bool IsVerusActive();
bool IsVerusMainnetActive();

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCrossChainExportInput(const CScript &scriptSig);

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCrossChainImportInput(const CScript &scriptSig);

// used to validate a specific service reward based on the spending transaction
bool ValidateServiceReward(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsServiceRewardInput(const CScript &scriptSig);

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveOutputInput(const CScript &scriptSig);

// used to transfer a reserve currency between chains
bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveTransferInput(const CScript &scriptSig);

// used as exchange tokens between reserves and fractional reserves
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveExchangeInput(const CScript &scriptSig);

// used to deposit reserves into a reserve UTXO set
bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsReserveDepositInput(const CScript &scriptSig);

bool ValidateChainDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsChainDefinitionInput(const CScript &scriptSig);

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled);
bool IsCurrencyStateInput(const CScript &scriptSig);

bool GetCCParams(const CScript &scr, COptCCParams &ccParams);

bool SetPeerNodes(const UniValue &nodes);
bool SetThisChain(const UniValue &chainDefinition);
const uint256 &CurrencyDefHash(UniValue &chainDefinition);

extern CConnectedChains ConnectedChains;
extern uint160 ASSETCHAINS_CHAINID;
CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef);
CCurrencyValueMap CalculatePreconversions(const CCurrencyDefinition &chainDef, int32_t definitionHeight, CCurrencyValueMap &fees);

#endif
