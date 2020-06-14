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
 */

#include "main.h"
#include "rpc/pbaasrpc.h"
#include "base58.h"
#include "timedata.h"
#include "transaction_builder.h"

CConnectedChains ConnectedChains;

bool IsVerusActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0 || strcmp(ASSETCHAINS_SYMBOL, "VRSCTEST") == 0);
}

bool IsVerusMainnetActive()
{
    return (strcmp(ASSETCHAINS_SYMBOL, "VRSC") == 0);
}

// this adds an opret to a mutable transaction and returns the voutnum if it could be added
int32_t AddOpRetOutput(CMutableTransaction &mtx, const CScript &opRetScript)
{
    if (opRetScript.IsOpReturn() && opRetScript.size() <= MAX_OP_RETURN_RELAY)
    {
        CTxOut vOut = CTxOut();
        vOut.scriptPubKey = opRetScript;
        vOut.nValue = 0;
        mtx.vout.push_back(vOut);
        return mtx.vout.size() - 1;
    }
    else
    {
        return -1;
    }
}

// returns a pointer to a base chain object, which can be cast to the
// object type indicated in its objType member
uint256 GetChainObjectHash(const CBaseChainObject &bo)
{
    union {
        const CBaseChainObject *retPtr;
        const CChainObject<CBlockHeaderAndProof> *pNewHeader;
        const CChainObject<CPartialTransactionProof> *pNewTx;
        const CChainObject<CBlockHeaderProof> *pNewHeaderRef;
        const CChainObject<CPriorBlocksCommitment> *pPriors;
        const CChainObject<uint256> *pNewProofRoot;
        const CChainObject<CReserveTransfer> *pExport;
        const CChainObject<CCrossChainProof> *pCrossChainProof;
        const CChainObject<CCompositeChainObject> *pCompositeChainObject;
    };

    retPtr = &bo;

    switch(bo.objectType)
    {
        case CHAINOBJ_HEADER:
            return pNewHeader->GetHash();

        case CHAINOBJ_TRANSACTION_PROOF:
            return pNewTx->GetHash();

        case CHAINOBJ_HEADER_REF:
            return pNewHeaderRef->GetHash();

        case CHAINOBJ_PRIORBLOCKS:
            return pPriors->GetHash();

        case CHAINOBJ_PROOF_ROOT:
            return pNewProofRoot->object;

        case CHAINOBJ_RESERVETRANSFER:
            return pExport->GetHash();

        case CHAINOBJ_CROSSCHAINPROOF:
            return pCrossChainProof->GetHash();

        case CHAINOBJ_COMPOSITEOBJECT:
            return pCrossChainProof->GetHash();

    }
    return uint256();
}

// used to export coins from one chain to another, if they are not native, they are represented on the other
// chain as tokens
bool ValidateCrossChainExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsCrossChainExportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate import of coins from one chain to another. if they are not native and are supported,
// they are represented o the chain as tokens
bool ValidateCrossChainImport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCrossChainImportInput(const CScript &scriptSig)
{
    return true;
}

// used to validate a specific service reward based on the spending transaction
bool ValidateServiceReward(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // for each type of service reward, we need to check and see if the spender is
    // correctly formatted to be a valid spend of the service reward. for notarization
    // we ensure that the notarization and its outputs are valid and that the spend
    // applies to the correct billing period
    return true;
}
bool IsServiceRewardInput(const CScript &scriptSig)
{
    return true;
}

// used as a proxy token output for a reserve currency on its fractional reserve chain
bool ValidateReserveOutput(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveOutputInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateReserveTransfer(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveTransferInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateReserveDeposit(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveDepositInput(const CScript &scriptSig)
{
    return true;
}

bool ValidateCurrencyState(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsCurrencyStateInput(const CScript &scriptSig)
{
    return true;
}

// used to convert a fractional reserve currency into its reserve and back 
bool ValidateReserveExchange(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}
bool IsReserveExchangeInput(const CScript &scriptSig)
{
    return true;
}


/*
 * Verifies that the input objects match the hashes and returns the transaction.
 * 
 * If the opRetTx has the op ret, this calculates based on the actual transaction and
 * validates the hashes. If the opRetTx does not have the opRet itself, this validates
 * by ensuring that all objects are present on this chain, composing the opRet, and
 * ensuring that the transaction then hashes to the correct txid.
 * 
 */
bool ValidateOpretProof(CScript &opRet, COpRetProof &orProof)
{
    // enumerate through the objects and validate that they are objects of the expected type that hash
    // to the value expected. return true if so
    return true;
}

int8_t ObjTypeCode(const CBlockHeaderProof &obj)
{
    return CHAINOBJ_HEADER;
}

int8_t ObjTypeCode(const uint256 &obj)
{
    return CHAINOBJ_PROOF_ROOT;
}

int8_t ObjTypeCode(const CPartialTransactionProof &obj)
{
    return CHAINOBJ_TRANSACTION_PROOF;
}

int8_t ObjTypeCode(const CBlockHeaderAndProof &obj)
{
    return CHAINOBJ_HEADER_REF;
}

int8_t ObjTypeCode(const CPriorBlocksCommitment &obj)
{
    return CHAINOBJ_PRIORBLOCKS;
}

int8_t ObjTypeCode(const CReserveTransfer &obj)
{
    return CHAINOBJ_RESERVETRANSFER;
}

int8_t ObjTypeCode(const CCrossChainProof &obj)
{
    return CHAINOBJ_CROSSCHAINPROOF;
}

int8_t ObjTypeCode(const CCompositeChainObject &obj)
{
    return CHAINOBJ_COMPOSITEOBJECT;
}

// this adds an opret to a mutable transaction that provides the necessary evidence of a signed, cheating stake transaction
CScript StoreOpRetArray(const std::vector<CBaseChainObject *> &objPtrs)
{
    CScript vData;
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << (int32_t)OPRETTYPE_OBJECTARR;
    bool error = false;

    for (auto pobj : objPtrs)
    {
        try
        {
            if (!DehydrateChainObject(s, pobj))
            {
                error = true;
                break;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            error = true;
            break;
        }
    }

    //std::vector<unsigned char> schars(s.begin(), s.begin() + 200);
    //printf("stream vector chars: %s\n", HexBytes(&schars[0], schars.size()).c_str());

    std::vector<unsigned char> vch(s.begin(), s.end());
    return error ? CScript() : CScript() << OP_RETURN << vch;
}

void DeleteOpRetObjects(std::vector<CBaseChainObject *> &ora)
{
    for (auto pobj : ora)
    {
        switch(pobj->objectType)
        {
            case CHAINOBJ_HEADER:
            {
                delete (CChainObject<CBlockHeaderAndProof> *)pobj;
                break;
            }

            case CHAINOBJ_TRANSACTION_PROOF:
            {
                delete (CChainObject<CPartialTransactionProof> *)pobj;
                break;
            }

            case CHAINOBJ_PROOF_ROOT:
            {
                delete (CChainObject<uint256> *)pobj;
                break;
            }

            case CHAINOBJ_HEADER_REF:
            {
                delete (CChainObject<CBlockHeaderProof> *)pobj;
                break;
            }

            case CHAINOBJ_PRIORBLOCKS:
            {
                delete (CChainObject<CPriorBlocksCommitment> *)pobj;
                break;
            }

            case CHAINOBJ_RESERVETRANSFER:
            {
                delete (CChainObject<CReserveTransfer> *)pobj;
                break;
            }

            case CHAINOBJ_CROSSCHAINPROOF:
            {
                delete (CChainObject<CCrossChainProof> *)pobj;
                break;
            }

            case CHAINOBJ_COMPOSITEOBJECT:
            {
                delete (CChainObject<CCompositeChainObject> *)pobj;
                break;
            }

            default:
            {
                printf("ERROR: invalid object type (%u), likely corrupt pointer %p\n", pobj->objectType, pobj);
                printf("generate code that won't be optimized away %s\n", CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<CAmount>({200000000})).ToUniValue().write(1,2).c_str());
                printf("This is here to generate enough code for a good break point system chain name: %s\n", ConnectedChains.ThisChain().name.c_str());
                
                delete pobj;
            }
        }
    }
    ora.clear();
}

std::vector<CBaseChainObject *> RetrieveOpRetArray(const CScript &opRetScript)
{
    std::vector<unsigned char> vch;
    std::vector<CBaseChainObject *> vRet;
    if (opRetScript.IsOpReturn() && GetOpReturnData(opRetScript, vch) && vch.size() > 0)
    {
        CDataStream s = CDataStream(vch, SER_NETWORK, PROTOCOL_VERSION);

        int32_t opRetType;

        try
        {
            s >> opRetType;
            if (opRetType == OPRETTYPE_OBJECTARR)
            {
                CBaseChainObject *pobj;
                while (!s.empty() && (pobj = RehydrateChainObject(s)))
                {
                    vRet.push_back(pobj);
                }
                if (!s.empty())
                {
                    printf("failed to load all objects in opret");
                    DeleteOpRetObjects(vRet);
                    vRet.clear();
                }
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            DeleteOpRetObjects(vRet);
            vRet.clear();
        }
    }
    return vRet;
}

CServiceReward::CServiceReward(const CTransaction &tx, bool validate)
{
    nVersion = PBAAS_VERSION_INVALID;
    for (auto out : tx.vout)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(out.scriptPubKey, p))
        {
            // always take the first for now
            if (p.evalCode == EVAL_SERVICEREWARD)
            {
                FromVector(p.vData[0], *this);
                break;
            }
        }
    }

    if (validate)
    {
        
    }
}

CCrossChainExport::CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum)
{
    int32_t _ccxOutputNum = 0;
    int32_t &ccxOutputNum = pCCXOutputNum ? *pCCXOutputNum : _ccxOutputNum;
    
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_CROSSCHAIN_EXPORT)
        {
            FromVector(p.vData[0], *this);
            ccxOutputNum = i;
            break;
        }
    }
}

CCurrencyDefinition::CCurrencyDefinition(const CScript &scriptPubKey)
{
    nVersion = PBAAS_VERSION_INVALID;
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (p.evalCode == EVAL_CURRENCY_DEFINITION)
        {
            FromVector(p.vData[0], *this);
        }
    }
}

std::vector<CCurrencyDefinition> CCurrencyDefinition::GetCurrencyDefinitions(const CTransaction &tx)
{
    std::vector<CCurrencyDefinition> retVal;
    for (auto &out : tx.vout)
    {
        CCurrencyDefinition oneCur = CCurrencyDefinition(out.scriptPubKey);
        if (oneCur.IsValid())
        {
            retVal.push_back(oneCur);
        }
    }
    return retVal;
}

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY, ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;
extern uint160 VERUS_CHAINID;

// ensures that the chain definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool ValidateChainDefinition(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // the chain definition output can be spent when the chain is at the end of its life and only then
    // TODO
    return false;
}

// ensures that the chain definition is valid and that there are no other definitions of the same name
// that have been confirmed.
bool CheckChainDefinitionOutputs(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn)
{
    // checked before a chain definition output script is accepted as a valid transaction

    // basics - we need a chain definition transaction to kick off a PBaaS chain. it must have:
    // 1) valid chain definition output with parameters in proper ranges and no duplicate name
    // 2) notarization output with conformant values
    // 3) finalization output
    // 3) notarization funding
    //

    // get the source transaction
    uint256 blkHash;
    CTransaction thisTx;
    if (!GetTransaction(tx.vin[nIn].prevout.hash, thisTx, blkHash))
    {
        LogPrintf("failed to retrieve transaction %s\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
        return false;
    }

    std::vector<CCurrencyDefinition> chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(thisTx);
    CPBaaSNotarization notarization(thisTx);
    CTransactionFinalization finalization(thisTx);
    bool isVerusActive = IsVerusActive();

    if (!notarization.IsValid() || !finalization.IsValid())
    {
        LogPrintf("transaction specified, %s, must have valid notarization, and finaization outputs\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
        return false;
    }

    std::set<uint160> allCurrencyIDs;
    for (auto &curPair : ConnectedChains.ReserveCurrencies())
    {
        allCurrencyIDs.insert(curPair.first);
    }
    allCurrencyIDs.insert(ConnectedChains.ThisChain().GetID());
    if (!isVerusActive)
    {
        allCurrencyIDs.insert(ConnectedChains.notaryChain.GetID());
    }

    bool isCoinbase = thisTx.IsCoinBase();
    bool isVerified = false;
    CIdentity activatedID(thisTx);

    // currency definitions can be valid as follows:
    // 1. original definition in a transaction that simultaneously sets the active currency bit on the identity of the same
    //    name and ID.
    // 2. outputs of a coinbase transaction in block 1 that defines the parent currency, new currency, and any reserve currencies
    // 3. currency import from the defining chain of the currency, which has not been implemented as of this comment
    if (activatedID.IsValid() && 
        activatedID.HasActiveCurrency() && 
        chainDefs.size() == 1 &&
        activatedID.parent == ASSETCHAINS_CHAINID &&
        activatedID.GetID() == chainDefs[0].GetID())
    {
        isVerified = true;
    }
    else if (isCoinbase && chainDefs.size() >= 1 && !isVerusActive)
    {
        int32_t height1 = 1;
        CScript expect = CScript() << height1;
        opcodetype opcode = (opcodetype)*expect.begin();

        if (opcode >= OP_1 && opcode <= OP_16)
        {
            isVerified = (thisTx.vin[0].scriptSig.size() >= 1 && CScript::DecodeOP_N(opcode) == height1) || 
                            (thisTx.vin[0].scriptSig.size() >= 2 && thisTx.vin[0].scriptSig[0] == OP_PUSHDATA1 && (int)thisTx.vin[0].scriptSig[1] == height1);
        }
        else
        {
            isVerified = thisTx.vin[0].scriptSig.size() >= expect.size() && std::equal(expect.begin(), expect.end(), thisTx.vin[0].scriptSig.begin());
        }

        for (auto &chainDef : chainDefs)
        {
            uint160 chainID = chainDef.GetID();
            if (!chainDef.IsValid())
            {
                LogPrintf("transaction specified, %s, must not contain invalid chain definitions\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
                return false;
            }
            if (!allCurrencyIDs.count(chainID))
            {
                LogPrintf("transaction specified, %s, must not contain invalid chain definitions\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
                return false;
            }
            allCurrencyIDs.erase(chainID);
        }
        if (allCurrencyIDs.size())
        {
            LogPrintf("transaction specified, %s, does not contain all required chain definitions\n", tx.vin[nIn].prevout.hash.GetHex().c_str());
            return false;
        }
    }

    return isVerified;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee(const CCurrencyValueMap &fees, int numIn)
{
    CCurrencyValueMap retVal;

    if (numIn > MAX_EXPORT_INPUTS)
    {
        return retVal;
    }
    static const arith_uint256 satoshis(100000000);

    arith_uint256 ratio(50000000 + ((25000000 / MAX_EXPORT_INPUTS) * (numIn - 1)));

    for (auto &feePair : fees.valueMap)
    {
        retVal.valueMap[feePair.first] = (((arith_uint256(feePair.second) * ratio)) / satoshis).GetLow64();
    }
    return retVal;
}

CCurrencyValueMap CCrossChainExport::CalculateExportFee() const
{
    return CalculateExportFee(totalFees, numInputs);
}

CCurrencyValueMap CCrossChainExport::CalculateImportFee() const
{
    CCurrencyValueMap retVal;

    for (auto &feePair : CalculateExportFee().valueMap)
    {
        CAmount feeAmount = feePair.second;
        auto it = totalFees.valueMap.find(feePair.first);
        retVal.valueMap[feePair.first] = (it != totalFees.valueMap.end() ? it->second : 0) - feeAmount;
    }
    return retVal;
}

bool CConnectedChains::RemoveMergedBlock(uint160 chainID)
{
    bool retval = false;
    LOCK(cs_mergemining);

    //printf("RemoveMergedBlock ID: %s\n", chainID.GetHex().c_str());

    auto chainIt = mergeMinedChains.find(chainID);
    if (chainIt != mergeMinedChains.end())
    {
        arith_uint256 target;
        target.SetCompact(chainIt->second.block.nBits);
        for (auto removeRange = mergeMinedTargets.equal_range(target); removeRange.first != removeRange.second; removeRange.first++)
        {
            // make sure we don't just match by target
            if (removeRange.first->second->GetID() == chainID)
            {
                mergeMinedTargets.erase(removeRange.first);
                break;
            }
        }
        mergeMinedChains.erase(chainID);
        dirty = retval = true;

        // if we get to 0, give the thread a kick to stop waiting for mining
        //if (!mergeMinedChains.size())
        //{
        //    sem_submitthread.post();
        //}
    }
    return retval;
}

// remove merge mined chains added and not updated since a specific time
void CConnectedChains::PruneOldChains(uint32_t pruneBefore)
{
    vector<uint160> toRemove;

    LOCK(cs_mergemining);
    for (auto blkData : mergeMinedChains)
    {
        if (blkData.second.block.nTime < pruneBefore)
        {
            toRemove.push_back(blkData.first);
        }
    }

    for (auto id : toRemove)
    {
        //printf("Pruning chainID: %s\n", id.GetHex().c_str());
        RemoveMergedBlock(id);
    }
}

// adds or updates merge mined blocks
// returns false if failed to add
bool CConnectedChains::AddMergedBlock(CPBaaSMergeMinedChainData &blkData)
{
    // determine if we should replace one or add to the merge mine vector
    {
        LOCK(cs_mergemining);

        arith_uint256 target;
        uint160 cID = blkData.GetID();
        auto it = mergeMinedChains.find(cID);
        if (it != mergeMinedChains.end())
        {
            RemoveMergedBlock(cID);             // remove it if already there
        }
        target.SetCompact(blkData.block.nBits);

        //printf("AddMergedBlock name: %s, ID: %s\n", blkData.chainDefinition.name.c_str(), cID.GetHex().c_str());

        mergeMinedTargets.insert(make_pair(target, &(mergeMinedChains.insert(make_pair(cID, blkData)).first->second)));
        dirty = true;
    }
    return true;
}

bool CConnectedChains::GetChainInfo(uint160 chainID, CRPCChainData &rpcChainData)
{
    {
        LOCK(cs_mergemining);
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            rpcChainData = (CRPCChainData)chainIt->second;
            return true;
        }
        return false;
    }
}

// this returns a pointer to the data without copy and assumes the lock is held
CPBaaSMergeMinedChainData *CConnectedChains::GetChainInfo(uint160 chainID)
{
    {
        auto chainIt = mergeMinedChains.find(chainID);
        if (chainIt != mergeMinedChains.end())
        {
            return &chainIt->second;
        }
        return NULL;
    }
}

void CConnectedChains::QueueNewBlockHeader(CBlockHeader &bh)
{
    //printf("QueueNewBlockHeader %s\n", bh.GetHash().GetHex().c_str());
    {
        LOCK(cs_mergemining);

        qualifiedHeaders[UintToArith256(bh.GetHash())] = bh;
    }
    sem_submitthread.post();
}

void CConnectedChains::CheckImports()
{
    sem_submitthread.post();
}

// get the latest block header and submit one block at a time, returning after there are no more
// matching blocks to be found
vector<pair<string, UniValue>> CConnectedChains::SubmitQualifiedBlocks()
{
    std::set<uint160> inHeader;
    bool submissionFound;
    CPBaaSMergeMinedChainData chainData;
    vector<pair<string, UniValue>>  results;

    CBlockHeader bh;
    arith_uint256 lastHash;
    CPBaaSBlockHeader pbh;

    do
    {
        submissionFound = false;
        {
            LOCK(cs_mergemining);
            // attempt to submit with the lowest hash answers first to increase the likelihood of submitting
            // common, merge mined headers for notarization, drop out on any submission
            for (auto headerIt = qualifiedHeaders.begin(); !submissionFound && headerIt != qualifiedHeaders.end(); headerIt = qualifiedHeaders.begin())
            {
                // add the PBaaS chain ids from this header to a set for search
                for (uint32_t i = 0; headerIt->second.GetPBaaSHeader(pbh, i); i++)
                {
                    inHeader.insert(pbh.chainID);
                }

                uint160 chainID;
                // now look through all targets that are equal to or above the hash of this header
                for (auto chainIt = mergeMinedTargets.lower_bound(headerIt->first); !submissionFound && chainIt != mergeMinedTargets.end(); chainIt++)
                {
                    chainID = chainIt->second->GetID();
                    if (inHeader.count(chainID))
                    {
                        // first, check that the winning header matches the block that is there
                        CPBaaSPreHeader preHeader(chainIt->second->block);
                        preHeader.SetBlockData(headerIt->second);

                        // check if the block header matches the block's specific data, only then can we create a submission from this block
                        if (headerIt->second.CheckNonCanonicalData(chainID))
                        {
                            // save block as is, remove the block from merged headers, replace header, and submit
                            chainData = *chainIt->second;

                            *(CBlockHeader *)&chainData.block = headerIt->second;

                            submissionFound = true;
                        }
                        //else // not an error condition. code is here for debugging
                        //{
                        //    printf("Mismatch in non-canonical data for chain %s\n", chainIt->second->chainDefinition.name.c_str());
                        //}
                    }
                    //else // not an error condition. code is here for debugging
                    //{
                    //    printf("Not found in header %s\n", chainIt->second->chainDefinition.name.c_str());
                    //}
                }

                // if this header matched no block, discard and move to the next, otherwise, we'll drop through
                if (submissionFound)
                {
                    // once it is going to be submitted, remove block from this chain until a new one is added again
                    RemoveMergedBlock(chainID);
                    break;
                }
                else
                {
                    qualifiedHeaders.erase(headerIt);
                }
            }
        }
        if (submissionFound)
        {
            // submit one block and loop again. this approach allows multiple threads
            // to collectively empty the submission queue, mitigating the impact of
            // any one stalled daemon
            UniValue submitParams(UniValue::VARR);
            submitParams.push_back(EncodeHexBlk(chainData.block));
            UniValue result, error;
            try
            {
                result = RPCCall("submitblock", submitParams, chainData.rpcUserPass, chainData.rpcPort, chainData.rpcHost);
                result = find_value(result, "result");
                error = find_value(result, "error");
            }
            catch (exception e)
            {
                result = UniValue(e.what());
            }
            results.push_back(make_pair(chainData.chainDefinition.name, result));
            if (result.isStr() || !error.isNull())
            {
                printf("Error submitting block to %s chain: %s\n", chainData.chainDefinition.name.c_str(), result.isStr() ? result.get_str().c_str() : error.get_str().c_str());
            }
            else
            {
                printf("Successfully submitted block to %s chain\n", chainData.chainDefinition.name.c_str());
            }
        }
    } while (submissionFound);
    return results;
}

// add all merge mined chain PBaaS headers into the blockheader and return the easiest nBits target in the header
uint32_t CConnectedChains::CombineBlocks(CBlockHeader &bh)
{
    vector<uint160> inHeader;
    vector<UniValue> toCombine;
    arith_uint256 blkHash = UintToArith256(bh.GetHash());
    arith_uint256 target(0);
    
    CPBaaSBlockHeader pbh;

    {
        LOCK(cs_mergemining);

        CPBaaSSolutionDescriptor descr = CVerusSolutionVector::solutionTools.GetDescriptor(bh.nSolution);

        for (uint32_t i = 0; i < descr.numPBaaSHeaders; i++)
        {
            if (bh.GetPBaaSHeader(pbh, i))
            {
                inHeader.push_back(pbh.chainID);
            }
        }

        // loop through the existing PBaaS chain ids in the header
        // remove any that are not either this Chain ID or in our local collection and then add all that are present
        for (uint32_t i = 0; i < inHeader.size(); i++)
        {
            auto it = mergeMinedChains.find(inHeader[i]);
            if (inHeader[i] != ASSETCHAINS_CHAINID && (it == mergeMinedChains.end()))
            {
                bh.DeletePBaaSHeader(i);
            }
        }

        for (auto chain : mergeMinedChains)
        {
            // get the native PBaaS header for each chain and put it into the
            // header we are given
            // it must have itself in as a PBaaS header
            uint160 cid = chain.second.GetID();
            if (chain.second.block.GetPBaaSHeader(pbh, cid) != -1)
            {
                if (!bh.AddUpdatePBaaSHeader(pbh))
                {
                    LogPrintf("Failure to add PBaaS block header for %s chain\n", chain.second.chainDefinition.name.c_str());
                    break;
                }
                else
                {
                    arith_uint256 t;
                    t.SetCompact(chain.second.block.nBits);
                    if (t > target)
                    {
                        target = t;
                    }
                }
            }
            else
            {
                LogPrintf("Merge mined block for %s does not contain PBaaS information\n", chain.second.chainDefinition.name.c_str());
            }
        }
        dirty = false;
    }

    return target.GetCompact();
}

bool CConnectedChains::IsVerusPBaaSAvailable()
{
    return notaryChainVersion >= "0.6.4";
}

extern string PBAAS_HOST, PBAAS_USERPASS;
extern int32_t PBAAS_PORT;
bool CConnectedChains::CheckVerusPBaaSAvailable(UniValue &chainInfoUni, UniValue &chainDefUni)
{
    if (chainInfoUni.isObject() && chainDefUni.isObject())
    {
        UniValue uniVer = find_value(chainInfoUni, "VRSCversion");
        if (uniVer.isStr())
        {
            LOCK(cs_mergemining);
            notaryChainVersion = uni_get_str(uniVer);
            notaryChainHeight = uni_get_int(find_value(chainInfoUni, "blocks"));
            CCurrencyDefinition chainDef(chainDefUni);
            notaryChain = CRPCChainData(chainDef, PBAAS_HOST, PBAAS_PORT, PBAAS_USERPASS);
        }
    }
    return IsVerusPBaaSAvailable();
}

uint32_t CConnectedChains::NotaryChainHeight()
{
    LOCK(cs_mergemining);
    return notaryChainHeight;
}

bool CConnectedChains::CheckVerusPBaaSAvailable()
{
    if (IsVerusActive())
    {
        notaryChainVersion = "";
    }
    else
    {
        // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
        // tolerate only 15 second timeout
        UniValue chainInfo, chainDef;
        try
        {
            UniValue params(UniValue::VARR);
            chainInfo = find_value(RPCCallRoot("getinfo", params), "result");
            if (!chainInfo.isNull())
            {
                params.push_back(VERUS_CHAINNAME);
                chainDef = find_value(RPCCallRoot("getcurrency", params), "result");

                if (!chainDef.isNull() && CheckVerusPBaaSAvailable(chainInfo, chainDef))
                {
                    // if we have not past block 1 yet, store the best known update of our current state
                    if ((!chainActive.LastTip() || !chainActive.LastTip()->GetHeight()))
                    {
                        bool success = false;
                        params.clear();
                        params.push_back(EncodeDestination(CIdentityID(thisChain.GetID())));
                        chainDef = find_value(RPCCallRoot("getcurrency", params), "result");
                        if (!chainDef.isNull())
                        {
                            CCurrencyDefinition currencyDef(chainDef);
                            if (currencyDef.IsValid())
                            {
                                thisChain = currencyDef;
                                if (NotaryChainHeight() >= thisChain.startBlock)
                                {
                                    readyToStart = true;    // this only gates mining of block one, to be sure we have the latest definition
                                }
                                success = true;
                            }
                        }
                        return success;
                    }
                    return true;
                }
            }
        } catch (exception e)
        {
            LogPrintf("%s: Error communicating with %s chain\n", __func__, VERUS_CHAINNAME);
        }
    }
    notaryChainVersion = "";
    return false;
}

int CConnectedChains::GetThisChainPort() const
{
    int port;
    string host;
    for (auto node : defaultPeerNodes)
    {
        SplitHostPort(node.networkAddress, port, host);
        if (port)
        {
            return port;
        }
    }
    return 0;
}

CCoinbaseCurrencyState CConnectedChains::GetCurrencyState(int32_t height)
{
    CCoinbaseCurrencyState currencyState;
    CBlock block;
    LOCK(cs_main);
    bool isVerusActive = IsVerusActive();
    if (!isVerusActive && 
        CConstVerusSolutionVector::activationHeight.ActiveVersion(height) >= CActivationHeight::ACTIVATE_PBAAS &&
        height != 0 && 
        height <= chainActive.Height() && 
        chainActive[height] && 
        ReadBlockFromDisk(block, chainActive[height], Params().GetConsensus()) &&
        (currencyState = CCoinbaseCurrencyState(block.vtx[0])).IsValid())
    {
        return currencyState;
    }
    else
    {
        return GetInitialCurrencyState(thisChain);
    }
}

bool CConnectedChains::SetLatestMiningOutputs(const std::vector<pair<int, CScript>> &minerOutputs, CTxDestination &firstDestinationOut)
{
    LOCK(cs_mergemining);

    if (!minerOutputs.size() || !ExtractDestination(minerOutputs[0].second, firstDestinationOut))
    {
        return false;
    }
    latestMiningOutputs = minerOutputs;
    latestDestination = firstDestinationOut;
    return true;
}

CCurrencyDefinition CConnectedChains::GetCachedCurrency(const uint160 &currencyID)
{
    LOCK(cs_main);
    CCurrencyDefinition currencyDef;
    auto it = currencyDefCache.find(currencyID);
    if ((it != currencyDefCache.end() && !(currencyDef = it->second).IsValid()) ||
        (it == currencyDefCache.end() && !GetCurrencyDefinition(currencyID, currencyDef)))
    {
        printf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
        LogPrintf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(currencyID)).c_str());
        return currencyDef;
    }
    if (it == currencyDefCache.end())
    {
        currencyDefCache[currencyID] = currencyDef;
    }
    return currencyDefCache[currencyID];
}

void CConnectedChains::AggregateChainTransfers(const CTxDestination &feeOutput, uint32_t nHeight)
{
    // all chains aggregate reserve transfer transactions, so aggregate and add all necessary export transactions to the mem pool
    {
        if (!nHeight)
        {
            return;
        }

        std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> transferOutputs;

        LOCK(cs_main);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        // get all available transfer outputs to aggregate into export transactions
        if (GetUnspentChainTransfers(transferOutputs))
        {
            if (!transferOutputs.size())
            {
                return;
            }

            std::vector<pair<CInputDescriptor, CReserveTransfer>> txInputs;
            uint160 bookEnd({uint160(ParseHex("ffffffffffffffffffffffffffffffffffffffff"))});
            uint160 lastChain = bookEnd;
            transferOutputs.insert(std::make_pair(bookEnd, std::make_pair(CInputDescriptor(), CReserveTransfer())));
            CCurrencyDefinition lastChainDef;

            for (auto &output : transferOutputs)
            {
                CCurrencyDefinition sourceDef, destDef, systemDef;

                if (output.first != bookEnd)
                {
                    auto it = currencyDefCache.find(output.second.second.currencyID);
                    if ((it != currencyDefCache.end() && !(sourceDef = it->second).IsValid()) ||
                        (it == currencyDefCache.end() && !GetCurrencyDefinition(output.second.second.currencyID, sourceDef)))
                    {
                        printf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(output.second.second.currencyID)).c_str());
                        LogPrintf("%s: definition for transfer currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(output.second.second.currencyID)).c_str());
                        continue;
                    }
                    if (it == currencyDefCache.end())
                    {
                        currencyDefCache[output.second.second.currencyID] = sourceDef;
                    }

                    it = currencyDefCache.find(output.second.second.destCurrencyID);
                    if ((it != currencyDefCache.end() && !(destDef = it->second).IsValid()) ||
                        (it == currencyDefCache.end() && !GetCurrencyDefinition(output.second.second.destCurrencyID, destDef)))
                    {
                        printf("%s: definition for destination currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(output.second.second.destCurrencyID)).c_str());
                        LogPrintf("%s: definition for destination currency ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(output.second.second.destCurrencyID)).c_str());
                        continue;
                    }
                    if (it == currencyDefCache.end())
                    {
                        currencyDefCache[output.second.second.destCurrencyID] = destDef;
                    }

                    it = currencyDefCache.find(destDef.systemID);
                    if ((it != currencyDefCache.end() && !(systemDef = it->second).IsValid()) ||
                        (it == currencyDefCache.end() && !GetCurrencyDefinition(destDef.systemID, systemDef)))
                    {
                        printf("%s: definition for export system ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                        LogPrintf("%s: definition for export system ID %s not found\n\n", __func__, EncodeDestination(CIdentityID(destDef.systemID)).c_str());
                        continue;
                    }
                    if (it == currencyDefCache.end())
                    {
                        currencyDefCache[destDef.systemID] = systemDef;
                    }

                    // if destination is a token on the current chain, consider it its own system
                    if (destDef.systemID == thisChainID)
                    {
                        systemDef = destDef;
                    }
                }

                // get chain target and see if it is the same
                if (lastChain == bookEnd || output.first == lastChain)
                {
                    txInputs.push_back(output.second);
                }
                else
                {
                    // when we get here, we have a consecutive number of transfer outputs to consume in txInputs
                    // we need an unspent export output to export, or use the last one of it is an export to the same
                    // system
                    std::multimap<uint160, pair<int, CInputDescriptor>> exportOutputs;
                    lastChainDef = currencyDefCache[lastChain];

                    if (GetUnspentChainExports(lastChain, exportOutputs) && exportOutputs.size())
                    {
                        auto lastExport = *exportOutputs.begin();
                        bool oneFullSize = txInputs.size() >= CCrossChainExport::MIN_INPUTS;

                        if (((nHeight - lastExport.second.first) >= CCrossChainExport::MIN_BLOCKS) || oneFullSize)
                        {
                            boost::optional<CTransaction> oneExport;

                            // make one or more transactions that spends the last export and all possible cross chain transfers
                            while (txInputs.size())
                            {
                                TransactionBuilder tb(Params().GetConsensus(), nHeight);

                                int inputsLeft = txInputs.size();
                                int numInputs = inputsLeft > CCrossChainExport::MAX_EXPORT_INPUTS ? CCrossChainExport::MAX_EXPORT_INPUTS : inputsLeft;

                                if (numInputs > CCrossChainExport::MAX_EXPORT_INPUTS)
                                {
                                    numInputs = CCrossChainExport::MAX_EXPORT_INPUTS;
                                }
                                inputsLeft = txInputs.size() - numInputs;

                                // if we have already made one and don't have enough to make another
                                // without going under the input minimum, wait until next time for the others
                                if (numInputs > 0 && numInputs < CCrossChainExport::MIN_INPUTS && oneFullSize)
                                {
                                    break;
                                }

                                // each time through, we make one export transaction with the remainder or a subset of the
                                // reserve transfer inputs. inputs can be:
                                // 1. transfers of reserve for fractional reserve chains
                                // 2. pre-conversions for pre-launch participation in the premine
                                // 3. reserve market conversions to send between Verus and a fractional reserve chain and always output the native coin
                                //
                                // If we are on the Verus chain, all inputs will include native coins. On a PBaaS chain, inputs can either be native
                                // or reserve token inputs.
                                //
                                // On the Verus chain, total native amount, minus the fee, must be sent to the reserve address of the specific chain
                                // as reserve deposit with native coin equivalent. Pre-conversions and conversions will be realized on the PBaaS chain
                                // as part of the import process
                                // 
                                // If we are on the PBaaS chain, conversions must happen before coins are sent this way back to the reserve chain. 
                                // Verus reserve outputs can be directly aggregated and transferred, with fees paid through conversion and the 
                                // remaining Verus reserve coin will be burned on the PBaaS chain as spending it is allowed, once notarized, on the
                                // Verus chain.
                                //
                                CCurrencyValueMap totalTxFees;
                                CCurrencyValueMap totalAmounts;
                                CAmount exportOutVal = 0;
                                std::vector<CBaseChainObject *> chainObjects;

                                // first, we must add the export output from the current export thread to this chain
                                if (oneExport.is_initialized())
                                {
                                    // spend the last export transaction output
                                    CTransaction &tx = oneExport.get();
                                    COptCCParams p;
                                    int j;
                                    for (j = 0; j < tx.vout.size(); j++)
                                    {
                                        if (::IsPayToCryptoCondition(tx.vout[j].scriptPubKey, p) && p.evalCode == EVAL_CROSSCHAIN_EXPORT)
                                        {
                                            break;
                                        }
                                    }

                                    // had to be found and valid if we made the tx
                                    assert(j < tx.vout.size() && p.IsValid());

                                    tb.AddTransparentInput(COutPoint(tx.GetHash(), j), tx.vout[j].scriptPubKey, tx.vout[j].nValue);
                                    exportOutVal = tx.vout[j].nValue;
                                }
                                else
                                {
                                    // spend the recentExportIt output
                                    tb.AddTransparentInput(lastExport.second.second.txIn.prevout, lastExport.second.second.scriptPubKey, lastExport.second.second.nValue);
                                    exportOutVal = lastExport.second.second.nValue;
                                }

                                COptCCParams p;
                                std::vector<int> toRemove;

                                for (int j = 0; j < numInputs; j++)
                                {
                                    tb.AddTransparentInput(txInputs[j].first.txIn.prevout, txInputs[j].first.scriptPubKey, txInputs[j].first.nValue, txInputs[j].first.txIn.nSequence);
                                    CCurrencyValueMap newTransferInput = txInputs[j].first.scriptPubKey.ReserveOutValue();
                                    newTransferInput.valueMap[ASSETCHAINS_CHAINID] = txInputs[j].first.nValue;

                                    // TODO: make fee currency calculation more flexible on conversion
                                    // rules should be pay fee in native currency of destination system
                                    // if source is same currency
                                    CCurrencyValueMap newTransferOutput;
                                    bool isMint = (txInputs[j].second.flags & (CReserveTransfer::PREALLOCATE | CReserveTransfer::MINT_CURRENCY));
                                    if (isMint)
                                    {
                                        newTransferOutput.valueMap[txInputs[j].second.currencyID] = txInputs[j].second.nFees;
                                    }
                                    else
                                    {
                                        newTransferOutput.valueMap[txInputs[j].second.currencyID] = txInputs[j].second.nValue + txInputs[j].second.nFees;
                                    }

                                    //printf("input:\n%s\n", newTransferInput.ToUniValue().write().c_str());
                                    //printf("output:\n%s\n", newTransferOutput.ToUniValue().write().c_str());

                                    if ((newTransferInput - newTransferOutput).HasNegative())
                                    {
                                        // if this transfer is invalid and claims to carry more funds than it does, we consume it since it won't properly verify as a transfer, and
                                        // it is too expensive to let it force evaluation repeatedly. this condition should not get by normal checks, but just in case, don't let it slow transfers
                                        // we should formalize this into a chain contribution or amount adjustment.
                                        printf("%s: transaction %s claims incorrect value:\n%s\nactual:\n%s\n", __func__, 
                                                    txInputs[j].first.txIn.prevout.hash.GetHex().c_str(),
                                                    newTransferInput.ToUniValue().write().c_str(),
                                                    newTransferOutput.ToUniValue().write().c_str());
                                        LogPrintf("%s: transaction %s claims incorrect value:\n%s\nactual:\n%s\n", __func__, 
                                                    txInputs[j].first.txIn.prevout.hash.GetHex().c_str(),
                                                    newTransferInput.ToUniValue().write().c_str(),
                                                    newTransferOutput.ToUniValue().write().c_str());
                                        toRemove.push_back(j);
                                    }
                                    else
                                    {
                                        CAmount valueOut = isMint ? 0 : txInputs[j].second.nValue;
                                        CCurrencyValueMap newFees;
                                        totalTxFees += txInputs[j].second.CalculateFee(txInputs[j].second.flags, valueOut);
                                        totalAmounts += newTransferInput;
                                        chainObjects.push_back(new CChainObject<CReserveTransfer>(ObjTypeCode(txInputs[j].second), txInputs[j].second));
                                    }
                                }

                                // remove in reverse order so one removal does not affect the position of the next
                                for (int j = toRemove.size() - 1; j >= 0; j--)
                                {
                                    txInputs.erase(txInputs.begin() + toRemove[j]);
                                    numInputs--;
                                }

                                // this logic may cause us to create a tx that will get rejected, but we will never wait too long
                                if (!numInputs || (oneFullSize && (nHeight - lastExport.second.first) < CCrossChainExport::MIN_BLOCKS && numInputs < CCrossChainExport::MIN_INPUTS))
                                {
                                    continue;
                                }

                                //printf("%s: total export amounts:\n%s\n", __func__, totalAmounts.ToUniValue().write().c_str());

                                CCrossChainExport ccx(lastChain, numInputs, totalAmounts, totalTxFees);

                                // make extra outputs for fees in each currency
                                for (auto &outPair : ccx.CalculateExportFee().CanonicalMap().valueMap)
                                {
                                    CReserveTransfer feeOut(CReserveTransfer::VALID + CReserveTransfer::FEE_OUTPUT, 
                                                            outPair.first, outPair.second, 0, outPair.first, DestinationToTransferDestination(feeOutput));
                                    chainObjects.push_back(new CChainObject<CReserveTransfer>(ObjTypeCode(feeOut), feeOut));
                                }

                                // do a preliminary check
                                CReserveTransactionDescriptor rtxd;
                                std::vector<CTxOut> vOutputs;
                                CCoinbaseCurrencyState currencyState = GetInitialCurrencyState(lastChainDef);
                                if (!currencyState.IsValid() ||
                                    !rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain().GetID(), lastChainDef, currencyState, chainObjects, vOutputs))
                                {
                                    DeleteOpRetObjects(chainObjects);

                                    printf("%s: failed to create valid exports\n", __func__);
                                    LogPrintf("%s: failed to create valid exports\n", __func__);

                                    // debugging output
                                    printf("%s: failed to export outputs:\n", __func__);
                                    for (auto oneout : vOutputs)
                                    {
                                        UniValue uniOut;
                                        ScriptPubKeyToJSON(oneout.scriptPubKey, uniOut, false);
                                        printf("%s\n", uniOut.write(true, 2).c_str());
                                    }
                                }
                                else
                                {
                                    CCcontract_info CC;
                                    CCcontract_info *cp;

                                    /*
                                    // debugging out
                                    printf("%s: exported outputs:\n", __func__);
                                    for (auto &oneout : chainObjects)
                                    {
                                        if (oneout->objectType == CHAINOBJ_RESERVETRANSFER)
                                        {
                                            CReserveTransfer &rt = ((CChainObject<CReserveTransfer> *)(oneout))->object;
                                            printf("%s\n", rt.ToUniValue().write(true, 2).c_str());
                                        }
                                    }
                                    */

                                    CScript opRet = StoreOpRetArray(chainObjects);
                                    DeleteOpRetObjects(chainObjects);

                                    // now send transferred currencies to a reserve deposit
                                    cp = CCinit(&CC, EVAL_RESERVE_DEPOSIT);

                                    for (auto &oneCurrencyOut : ccx.totalAmounts.valueMap)
                                    {
                                        CCurrencyDefinition oneDef = currencyDefCache[oneCurrencyOut.first];

                                        // if the destination is the not the source currency, and
                                        // the destination is not another blockchain that controls the source currency, store in reserve
                                        if (!(oneCurrencyOut.first == lastChain ||
                                            (lastChainDef.systemID != ASSETCHAINS_CHAINID && oneDef.systemID == lastChainDef.systemID)))
                                        {
                                            CAmount nativeOut = oneDef.GetID() == ASSETCHAINS_CHAINID ? oneCurrencyOut.second : 0;

                                            // send the entire amount to a reserve deposit output of the specific chain
                                            // we receive our fee on the other chain, when it comes back, or if a token,
                                            // when it gets imported back to the chain
                                            std::vector<CTxDestination> indexDests({CKeyID(lastChainDef.GetConditionID(EVAL_RESERVE_DEPOSIT)), CKeyID(lastChainDef.GetID())});
                                            std::vector<CTxDestination> dests({CPubKey(ParseHex(CC.CChexstr))});

                                            CTokenOutput ro = CTokenOutput(oneCurrencyOut.first, nativeOut ? 0 : oneCurrencyOut.second);
                                            tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_DEPOSIT, dests, 1, &ro), &indexDests), 
                                                                    nativeOut);
                                        }
                                    }

                                    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);

                                    // send native amount of zero to a cross chain export output of the specific chain
                                    std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(lastChainDef.GetConditionID(EVAL_CROSSCHAIN_EXPORT))});
                                    if (lastChain != lastChainDef.systemID)
                                    {
                                        indexDests.push_back(CKeyID(CCrossChainRPCData::GetConditionID(lastChainDef.systemID, EVAL_CROSSCHAIN_EXPORT)));
                                    }
                                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});

                                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx), &indexDests),
                                                            exportOutVal);

                                    // when exports are confirmed as having been imported, they are finalized
                                    // until then, a finalization UTXO enables an index search to only find transactions
                                    // that have work to complete on this chain, or have not had their cross-chain import 
                                    // acknowledged
                                    cp = CCinit(&CC, EVAL_FINALIZE_EXPORT);
                                    CTransactionFinalization finalization(0);

                                    printf("%s: Finalizing export with index dest %s\n", __func__, CCrossChainRPCData::GetConditionID(lastChainDef.systemID, EVAL_FINALIZE_EXPORT).GetHex().c_str());

                                    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(lastChainDef.systemID, EVAL_FINALIZE_EXPORT))});
                                    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr)).GetID()});
                                    tb.AddTransparentOutput(MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_EXPORT, dests, 1, &finalization), &indexDests), 0);

                                    tb.AddOpRet(opRet);
                                    tb.SetFee(0);

                                    /* {
                                        UniValue uni(UniValue::VOBJ);
                                        TxToUniv(tb.mtx, uint256(), uni);
                                        printf("%s: about to send reserve deposits with tx:\n%s\n", __func__, uni.write(1,2).c_str());
                                    } */

                                    TransactionBuilderResult buildResult(tb.Build());

                                    if (!buildResult.IsError() && buildResult.IsTx())
                                    {
                                        // replace the last one only if we have a valid new one
                                        CTransaction tx = buildResult.GetTxOrThrow();

                                        LOCK2(cs_main, mempool.cs);
                                        static int lastHeight = 0;
                                        // remove conflicts, so that we get in
                                        std::list<CTransaction> removed;
                                        mempool.removeConflicts(tx, removed);

                                        // add to mem pool, prioritize according to the fee we will get, and relay
                                        //printf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                                        //LogPrintf("Created and signed export transaction %s\n", tx.GetHash().GetHex().c_str());
                                        if (myAddtomempool(tx))
                                        {
                                            uint256 hash = tx.GetHash();
                                            CAmount nativeExportFees = ccx.totalFees.valueMap[ASSETCHAINS_CHAINID];
                                            mempool.PrioritiseTransaction(hash, hash.GetHex(), (double)(nativeExportFees << 1), nativeExportFees);
                                        }
                                        else
                                        {
                                            UniValue uni(UniValue::VOBJ);
                                            TxToUniv(tx, uint256(), uni);
                                            //printf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                            LogPrintf("%s: created invalid transaction:\n%s\n", __func__, uni.write(1,2).c_str());
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        // we can't do any more useful work for this chain if we failed here
                                        printf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                                        LogPrintf("Failed to create export transaction: %s\n", buildResult.GetError().c_str());
                                        break;
                                    }
                                }

                                // erase the inputs we've attempted to spend
                                txInputs.erase(txInputs.begin(), txInputs.begin() + numInputs);
                            }
                        }
                    }
                }
                lastChain = output.first;
            }
            CheckImports();
        }
    }
}

void CConnectedChains::SignAndCommitImportTransactions(const CTransaction &lastImportTx, const std::vector<CTransaction> &transactions)
{
    int nHeight = chainActive.LastTip()->GetHeight();
    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());
    LOCK2(cs_main, mempool.cs);

    uint256 lastHash, lastSignedHash;
    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto &_tx : transactions)
    {
        CMutableTransaction newTx(_tx);

        if (!lastHash.IsNull())
        {
            //printf("last hash before signing: %s\n", lastHash.GetHex().c_str());
            for (auto &oneIn : newTx.vin)
            {
                //printf("checking input with hash: %s\n", oneIn.prevout.hash.GetHex().c_str());
                if (oneIn.prevout.hash == lastHash)
                {
                    oneIn.prevout.hash = lastSignedHash;
                    //printf("updated hash before signing: %s\n", lastSignedHash.GetHex().c_str());
                }
            }
        }
        lastHash = _tx.GetHash();
        CTransaction tx = newTx;

        // sign the transaction and submit
        bool signSuccess = false;
        for (int i = 0; i < tx.vin.size(); i++)
        {
            SignatureData sigdata;
            CAmount value;
            CScript outputScript;

            if (tx.vin[i].prevout.hash == lastImportTx.GetHash())
            {
                value = lastImportTx.vout[tx.vin[i].prevout.n].nValue;
                outputScript = lastImportTx.vout[tx.vin[i].prevout.n].scriptPubKey;
            }
            else
            {
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("%s: cannot get input coins from tx: %s, output: %d\n", __func__, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(nullptr, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"%s: failure to sign transaction\n", __func__);
                LogPrintf("%s: failure to sign transaction\n", __func__);
                break;
            } else {
                UpdateTransaction(newTx, i, sigdata);
            }
        }

        if (signSuccess)
        {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            CTransaction signedTx(newTx);

            //DEBUGGING
            //TxToJSON(tx, uint256(), jsonTX);
            //printf("signed transaction:\n%s\n", jsonTX.write(1, 2).c_str());

            if (!AcceptToMemoryPool(mempool, state, signedTx, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    fprintf(stderr,"%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                    LogPrintf("%s: rejected by memory pool for %s\n", __func__, state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"%s: missing inputs\n", __func__);
                        LogPrintf("%s: missing inputs\n", __func__);
                    }
                    else
                    {
                        fprintf(stderr,"%s: rejected by memory pool for\n", __func__);
                        LogPrintf("%s: rejected by memory pool for\n", __func__);
                    }
                }
                break;
            }
            else
            {
                UpdateCoins(signedTx, view, nHeight);
                lastSignedHash = signedTx.GetHash();
            }
        }
        else
        {
            break;
        }
    }
}

CCurrencyValueMap CalculatePreconversions(const CCurrencyDefinition &chainDef, int32_t definitionHeight, CCurrencyValueMap &fees)
{
    // if we are getting information on the current chain, we assume that preconverted amounts have been
    // pre-calculated. otherwise, we will calculate them.
    CCurrencyValueMap retVal;
    if (chainDef.GetID() != ConnectedChains.ThisChain().GetID())
    {
        std::multimap<uint160, pair<CInputDescriptor, CReserveTransfer>> transferInputs;
        CCurrencyValueMap preconvertedAmounts;

        if (GetChainTransfers(transferInputs, chainDef.GetID(), definitionHeight, chainDef.startBlock - 1, CReserveTransfer::PRECONVERT | CReserveTransfer::VALID))
        {
            auto curMap = chainDef.GetCurrenciesMap();
            for (auto &transfer : transferInputs)
            {
                if (!(transfer.second.second.flags & CReserveTransfer::PREALLOCATE) && curMap.count(transfer.second.second.currencyID))
                {
                    CAmount conversionFee = CReserveTransactionDescriptor::CalculateConversionFee(transfer.second.second.nValue);
                    preconvertedAmounts.valueMap[transfer.second.second.currencyID] += (transfer.second.second.nValue - conversionFee);
                    fees.valueMap[transfer.second.second.currencyID] += transfer.second.second.nFees + conversionFee;
                }
            }
            retVal = preconvertedAmounts;
            if (!chainDef.IsToken() && !(chainDef.ChainOptions() & chainDef.OPTION_FEESASRESERVE))
            {
                retVal += fees;
            }
        }
    }
    else
    {
        retVal = CCurrencyValueMap(chainDef.currencies, chainDef.preconverted);
    }
    return retVal;
}

// This creates a new token notarization input and output and attaches them to a new import transaction,
// given the next export transaction about to be imported and its height
bool CConnectedChains::NewImportNotarization(const CCurrencyDefinition &_curDef, 
                                             uint32_t height, 
                                             const CTransaction &lastImportTx, 
                                             uint32_t exportHeight, 
                                             const CTransaction &exportTx, 
                                             CMutableTransaction &mnewTx,
                                             CCoinbaseCurrencyState &newCurState)
{
    if (!_curDef.IsValid() || !_curDef.IsToken())
    {
        LogPrintf("%s: cannot create import notarization for invalid or non-token currencies\n", __func__);
        return false;
    }

    uint160 currencyID = _curDef.GetID();

    CCurrencyDefinition curDef = _curDef;

    CPBaaSNotarization lastNotarization(lastImportTx);
    if (!lastNotarization.IsValid())
    {
        LogPrintf("%s: error getting notarization transaction %s\n", __func__, lastImportTx.GetHash().GetHex().c_str());
        return false;
    }

    CCrossChainExport ccx(exportTx);
    if (!ccx.IsValid())
    {
        LogPrintf("%s: invalid export transaction %s\n", __func__, lastImportTx.GetHash().GetHex().c_str());
        return false;
    }

    std::vector<CCurrencyDefinition> txCurrencies = CCurrencyDefinition::GetCurrencyDefinitions(lastImportTx);

    bool isDefinition = false;
    for (auto &oneCur : txCurrencies)
    {
        if (oneCur.GetID() == currencyID)
        {
            isDefinition = true;
        }
    }

    int32_t definitionHeight = exportHeight;
    CChainNotarizationData cnd;
    if (isDefinition)
    {
        CTransaction dummyTx;
        uint256 blkHash;

        if (!myGetTransaction(lastImportTx.GetHash(), dummyTx, blkHash) || blkHash.IsNull())
        {
            LogPrintf("%s: invalid last import transaction for %s\n", __func__, curDef.name.c_str());
            return false;
        }
        definitionHeight = mapBlockIndex[blkHash]->GetHeight();
    }
    else if (GetNotarizationData(curDef.GetID(), EVAL_ACCEPTEDNOTARIZATION, cnd) && cnd.vtx.size())
    {
        lastNotarization = cnd.vtx[cnd.forks[cnd.bestChain].back()].second;
    }
    else
    {
        LogPrintf("%s: cannot get last notarization for %s\n", __func__, curDef.name.c_str());
        return false;
    }
    

    CBlockIndex *pindex;
    CTxDestination notarizationID = VERUS_DEFAULTID.IsNull() ? CTxDestination(CIdentityID(currencyID)) : CTxDestination(VERUS_DEFAULTID);

    // if this is the first notarization after start, make the notarization and determine if we should
    // launch or refund
    if (isDefinition)
    {
        bool refunding = false;

        pindex = chainActive[curDef.startBlock];

        // check if the chain is qualified for a refund
        CCurrencyValueMap minPreMap, preConvertedMap, fees;
        preConvertedMap = CalculatePreconversions(curDef, definitionHeight, fees).CanonicalMap();
        curDef.preconverted = preConvertedMap.AsCurrencyVector(curDef.currencies);

        CCoinbaseCurrencyState initialCur = GetInitialCurrencyState(curDef);
        newCurState = initialCur;

        if (curDef.minPreconvert.size() && curDef.minPreconvert.size() == curDef.currencies.size())
        {
            minPreMap = CCurrencyValueMap(curDef.currencies, curDef.minPreconvert).CanonicalMap();
        }

        if (minPreMap.valueMap.size() && preConvertedMap < minPreMap)
        {
            // we force the supply to zero
            // in any case where there was a minimum participation,
            // the result of the supply cannot be zero, enabling us to easily determine that this
            // represents a failed launch
            newCurState.supply = 0;
            newCurState.SetRefunding(true);
            refunding = true;
        }
        else if (curDef.IsFractional() &&
                 exportTx.vout.size() &&
                 exportTx.vout.back().scriptPubKey.IsOpReturn())
        {
            // we are not refunding, and it is possible that we also have
            // normal conversions in addition to pre-conversions. add any conversions that may 
            // be present into the new currency state
            CReserveTransactionDescriptor rtxd;
            std::vector<CBaseChainObject *> exportObjects;
            std::vector<CTxOut> vOutputs;

            exportObjects = RetrieveOpRetArray(exportTx.vout.back().scriptPubKey);

            bool isValidExport = rtxd.AddReserveTransferImportOutputs(currencyID, curDef, initialCur, exportObjects, vOutputs, &newCurState);
            DeleteOpRetObjects(exportObjects);
            if (!isValidExport)
            {
                LogPrintf("%s: invalid export opreturn for transaction %s\n", __func__, exportTx.GetHash().GetHex().c_str());
                return false;
            }
        }
    }
    else
    {
        pindex = chainActive.LastTip();
        if (!pindex)
        {
            LogPrintf("%s: invalid active chain\n", __func__);
            return false;
        }

        // this is not the first notarization, so the last notarization will let us know if this is a refund or not
        CCurrencyValueMap minPreMap;

        CCoinbaseCurrencyState initialCur = lastNotarization.currencyState;
        newCurState = initialCur;

        if (curDef.minPreconvert.size() && curDef.minPreconvert.size() == curDef.currencies.size())
        {
            minPreMap = CCurrencyValueMap(curDef.currencies, curDef.minPreconvert).CanonicalMap();
        }

        // we won't change currency state in notarizations after failure to launch, if success, recalculate as needed
        if (!(lastNotarization.currencyState.IsRefunding()))
        {
            // calculate new currency state from this import
            // we are not refunding, and it is possible that we also have
            // normal conversions in addition to pre-conversions. add any conversions that may 
            // be present into the new currency state
            CReserveTransactionDescriptor rtxd;
            std::vector<CBaseChainObject *> exportObjects;
            std::vector<CTxOut> vOutputs;

            exportObjects = RetrieveOpRetArray(exportTx.vout.back().scriptPubKey);

            bool isValidExport = rtxd.AddReserveTransferImportOutputs(currencyID, curDef, initialCur, exportObjects, vOutputs, &newCurState);
            DeleteOpRetObjects(exportObjects);
            if (!isValidExport)
            {
                LogPrintf("%s: invalid export opreturn for transaction %s\n", __func__, exportTx.GetHash().GetHex().c_str());
                return false;
            }
        }
    }

    uint256 lastImportTxHash = lastImportTx.GetHash();

    // now, add the initial notarization to the import tx
    // we will begin refund or import after notarization is accepted and returned by GetNotarizationData
    CPBaaSNotarization pbn = CPBaaSNotarization(curDef.notarizationProtocol,
                                                currencyID,
                                                notarizationID,
                                                pindex->GetHeight(),
                                                chainActive.GetMMV().GetRoot(),
                                                chainActive.GetMMRNode(pindex->GetHeight()).hash,
                                                ArithToUint256(GetCompactPower(pindex->nNonce, pindex->nBits, pindex->nVersion)),
                                                newCurState,
                                                lastImportTxHash,
                                                lastNotarization.notarizationHeight,
                                                uint256(), 0, COpRetProof(), std::vector<CNodeData>());

    // create notarization output
    CCcontract_info CC;
    CCcontract_info *cp;

    std::vector<CTxDestination> dests;
    std::vector<CTxDestination> indexDests;

    // make the accepted notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);

    if (curDef.notarizationProtocol == curDef.NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CIdentityID(currencyID)});
    }
    else if (curDef.notarizationProtocol == curDef.NOTARIZATION_AUTO)
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }
    else
    {
        return false;
    }
    indexDests = std::vector<CTxDestination>({CKeyID(curDef.GetConditionID(EVAL_ACCEPTEDNOTARIZATION))});
    mnewTx.vout.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &pbn), &indexDests)));

    // make the finalization output
    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);

    if (curDef.notarizationProtocol == curDef.NOTARIZATION_AUTO)
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    // finish transaction by adding the prior input and finalization, sign, then put it in the mempool
    // all output for notarizing will be paid as mining fees, so there's no need to relay
    uint32_t confirmedOut, finalizeOut;
    if (!GetNotarizationAndFinalization(EVAL_ACCEPTEDNOTARIZATION, lastImportTx, pbn, &confirmedOut, &finalizeOut))
    {
        printf("ERROR: could not find expected initial notarization for currency %s\n", curDef.name.c_str());
        return false;
    }

    mnewTx.vin.push_back(CTxIn(COutPoint(lastImportTxHash, confirmedOut)));
    mnewTx.vin.push_back(CTxIn(COutPoint(lastImportTxHash, finalizeOut)));

    // we need to store the input that we confirmed if we spent finalization outputs
    CTransactionFinalization nf(mnewTx.vin.size() - 1);

    indexDests = std::vector<CTxDestination>({CKeyID(curDef.GetConditionID(EVAL_FINALIZE_NOTARIZATION))});

    // update crypto condition with final notarization output data
    mnewTx.vout.push_back(CTxOut(0, 
            MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &nf), &indexDests)));

    return true;
}

// process token related, local imports and exports
void CConnectedChains::ProcessLocalImports()
{
    // first determine all export threads on the current chain that are valid to import
    std::multimap<uint160, std::pair<int, CInputDescriptor>> exportOutputs;
    std::multimap<uint160, CTransaction> importThreads;
    uint160 thisChainID = thisChain.GetID();

    LOCK2(cs_main, mempool.cs);
    uint32_t nHeight = chainActive.Height();

    // get all pending, local exports and put them into a map
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
    std::map<uint160, std::pair<uint32_t, CTransaction>> currenciesToImport;    // height of earliest tx
    CCurrencyDefinition oneCurrency;
    //printf("%s: Searching for %s\n", __func__, ConnectedChains.ThisChain().GetConditionID(EVAL_FINALIZE_EXPORT).GetHex().c_str());
    if (GetAddressUnspent(ConnectedChains.ThisChain().GetConditionID(EVAL_FINALIZE_EXPORT), 1, unspentOutputs))
    {
        CCrossChainExport ccx, ccxDummy;
        CTransaction txOut, txImport;
        CPartialTransactionProof lastExport;
        CCrossChainImport cci;
        uint256 blkHash;
        for (auto &oneOut : unspentOutputs)
        {
            COptCCParams p;
            if (oneOut.second.script.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_FINALIZE_EXPORT &&
                p.vData.size() &&
                CTransactionFinalization(p.vData[0]).IsValid() &&
                myGetTransaction(oneOut.first.txhash, txOut, blkHash) &&
                (ccx = CCrossChainExport(txOut)).IsValid() &&
                (oneCurrency = GetCachedCurrency(ccx.systemID)).IsValid() &&
                oneCurrency.startBlock <= nHeight &&
                !currenciesToImport.count(ccx.systemID) &&
                GetLastImport(ccx.systemID, txImport, lastExport, cci, ccxDummy))
            {
                auto blockIt = mapBlockIndex.find(blkHash);
                if (blockIt != mapBlockIndex.end() && chainActive.Contains(blockIt->second))
                {
                    currenciesToImport.insert(make_pair(ccx.systemID, make_pair(blockIt->second->GetHeight(), txImport)));
                }
            }
        }
    }

    CMutableTransaction txTemplate = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);
    for (auto &oneIT : currenciesToImport)
    {
        std::vector<CTransaction> importTxes;
        int32_t importOutNum = 0;
        CCrossChainImport oneImportInput(oneIT.second.second, &importOutNum);
        if (oneImportInput.IsValid())
        {
            std::vector<CAddressUnspentDbEntry> reserveDeposits;
            GetAddressUnspent(currencyDefCache[oneIT.first].GetConditionID(EVAL_RESERVE_DEPOSIT), CScript::P2CC, reserveDeposits);
            CCurrencyValueMap tokenImportAvailable;
            CAmount nativeImportAvailable = 0;
            for (auto &oneOut : reserveDeposits)
            {
                nativeImportAvailable += oneOut.second.satoshis;
                tokenImportAvailable += oneOut.second.script.ReserveOutValue();
                //printf("nativeImportAvailable:%ld, tokenImportAvailable:%s\n", nativeImportAvailable, tokenImportAvailable.ToUniValue().write().c_str());
            }
            nativeImportAvailable += oneIT.second.second.vout[importOutNum].nValue;
            tokenImportAvailable += oneIT.second.second.vout[importOutNum].ReserveOutValue();
            //printf("nativeImportAvailable:%ld, tokenImportAvailable:%s\n", nativeImportAvailable, tokenImportAvailable.ToUniValue().write().c_str());
            if (CreateLatestImports(currencyDefCache[oneIT.first], oneIT.second.second, txTemplate, CTransaction(), tokenImportAvailable, nativeImportAvailable, importTxes))
            {
                // fund the first import transaction with all reserveDeposits
                // change amounts are passed through on the import thread
                //
                // TODO: manage when this becomes to large by splitting reserve deposits over the
                // transactions
                if (importTxes.size())
                {
                    CMutableTransaction oneImport = importTxes[0];
                    int32_t outNum = 0;
                    CCrossChainImport cci(importTxes[0], &outNum);
                    if (cci.IsValid())
                    {
                        // add the reserve deposit inputs to the first transaction
                        // the  outputs should have been automatically propagated through
                        // fixup inputs if necessary
                        if (reserveDeposits.size())
                        {
                            UniValue jsonTX(UniValue::VOBJ);
                            std::vector<uint256> prevHashes;

                            for (int i = 0; i < importTxes.size() - 1; i++)
                            {
                                prevHashes.push_back(importTxes[i].GetHash());
                            }

                            // TODO - get reserve deposits from exports, not all at once, as in refunds
                            for (auto &oneOut : reserveDeposits)
                            {
                                oneImport.vin.push_back(CTxIn(oneOut.first.txhash, oneOut.first.index));
                            }

                            importTxes[0] = oneImport;

                            for (int i = 0; i < importTxes.size() - 1; i++)
                            {
                                oneImport = importTxes[i + 1];
                                for (auto &oneIn : oneImport.vin)
                                {
                                    if (oneIn.prevout.hash == prevHashes[i])
                                    {
                                        //printf("updating hash before signing to new value\nold: %s\nnew: %s\n", oneIn.prevout.hash.GetHex().c_str(), importTxes[i].GetHash().GetHex().c_str());
                                        oneIn.prevout.hash = importTxes[i].GetHash();
                                    }
                                }
                                importTxes[i + 1] = oneImport;
                            }

                        }
                        SignAndCommitImportTransactions(oneIT.second.second, importTxes);
                    }
                }
            }
        }
    }
}

void CConnectedChains::SubmissionThread()
{
    try
    {
        arith_uint256 lastHash;
        int64_t lastImportTime = 0;
        uint32_t lastHeight = 0;
        
        // wait for something to check on, then submit blocks that should be submitted
        while (true)
        {
            boost::this_thread::interruption_point();

            if (IsVerusActive())
            {
                // blocks get discarded after no refresh for 5 minutes by default, probably should be more often
                //printf("SubmissionThread: pruning\n");
                PruneOldChains(GetAdjustedTime() - 300);
                bool submit = false;
                {
                    LOCK(cs_mergemining);
                    if (mergeMinedChains.size() == 0 && qualifiedHeaders.size() != 0)
                    {
                        qualifiedHeaders.clear();
                    }
                    submit = qualifiedHeaders.size() != 0 && mergeMinedChains.size() != 0;

                    //printf("SubmissionThread: qualifiedHeaders.size(): %lu, mergeMinedChains.size(): %lu\n", qualifiedHeaders.size(), mergeMinedChains.size());
                }
                if (submit)
                {
                    //printf("SubmissionThread: calling submit qualified blocks\n");
                    SubmitQualifiedBlocks();
                }

                ProcessLocalImports();

                if (!submit)
                {
                    sem_submitthread.wait();
                }
            }
            else
            {
                // if this is a PBaaS chain, poll for presence of Verus / root chain and current Verus block and version number
                if (CheckVerusPBaaSAvailable())
                {
                    // check to see if we have recently earned a block with an earned notarization that qualifies for
                    // submitting an accepted notarization
                    if (earnedNotarizationHeight)
                    {
                        CBlock blk;
                        int32_t txIndex = -1, height;
                        {
                            LOCK(cs_mergemining);
                            if (earnedNotarizationHeight && earnedNotarizationHeight <= chainActive.Height() && earnedNotarizationBlock.GetHash() == chainActive[earnedNotarizationHeight]->GetBlockHash())
                            {
                                blk = earnedNotarizationBlock;
                                earnedNotarizationBlock = CBlock();
                                txIndex = earnedNotarizationIndex;
                                height = earnedNotarizationHeight;
                                earnedNotarizationHeight = 0;
                            }
                        }

                        if (txIndex != -1)
                        {
                            //printf("SubmissionThread: testing notarization\n");
                            CTransaction lastConfirmed;
                            uint256 txId = CreateAcceptedNotarization(blk, txIndex, height);

                            if (!txId.IsNull())
                            {
                                printf("Submitted notarization for acceptance: %s\n", txId.GetHex().c_str());
                                LogPrintf("Submitted notarization for acceptance: %s\n", txId.GetHex().c_str());
                            }
                        }
                    }

                    // every "n" seconds, look for imports to include in our blocks from the Verus chain
                    if ((GetAdjustedTime() - lastImportTime) >= 30 || lastHeight < (chainActive.LastTip() ? 0 : chainActive.LastTip()->GetHeight()))
                    {
                        lastImportTime = GetAdjustedTime();
                        lastHeight = (chainActive.LastTip() ? 0 : chainActive.LastTip()->GetHeight());

                        // see if our notary has a confirmed notarization for us
                        UniValue params(UniValue::VARR);
                        UniValue result;

                        params.push_back(thisChain.name);

                        try
                        {
                            result = find_value(RPCCallRoot("getlastimportin", params), "result");
                        } catch (exception e)
                        {
                            result = NullUniValue;
                        }

                        if (!result.isNull())
                        {
                            auto txUniStr = find_value(result, "lastimporttransaction");
                            auto txLastConfirmedStr = find_value(result, "lastconfirmednotarization");
                            auto txTemplateStr = find_value(result, "importtxtemplate");
                            CAmount nativeImportAvailable = uni_get_int64(find_value(result, "nativeimportavailable"));
                            CCurrencyValueMap tokenImportAvailable(find_value(params[0], "tokenimportavailable"));

                            CTransaction lastImportTx, lastConfirmedTx, templateTx;

                            if (txUniStr.isStr() && txTemplateStr.isStr() && 
                                DecodeHexTx(lastImportTx, txUniStr.get_str()) && 
                                DecodeHexTx(lastConfirmedTx, txLastConfirmedStr.get_str()) && 
                                DecodeHexTx(templateTx, txTemplateStr.get_str()))
                            {
                                std::vector<CTransaction> importTxes;
                                if (CreateLatestImports(notaryChain.chainDefinition, lastImportTx, templateTx, lastConfirmedTx, tokenImportAvailable, nativeImportAvailable, importTxes))
                                {
                                    for (auto importTx : importTxes)
                                    {
                                        UniValue txResult;
                                        params.setArray();
                                        params.push_back(EncodeHexTx(importTx));

                                        try
                                        {
                                            txResult = find_value(RPCCallRoot("signrawtransaction", params), "result");
                                            if (txResult.isObject() && !(txResult = find_value(txResult, "hex")).isNull() && txResult.isStr() && txResult.get_str().size())
                                            {
                                                params.setArray();
                                                params.push_back(txResult);
                                                txResult = find_value(RPCCallRoot("sendrawtransaction", params), "result");
                                            }
                                            else
                                            {
                                                txResult = NullUniValue;
                                            }
                                            
                                        } catch (exception e)
                                        {
                                            txResult = NullUniValue;
                                        }
                                        uint256 testId;
                                        if (txResult.isStr())
                                        {
                                            testId.SetHex(txResult.get_str());
                                        }
                                        if (testId.IsNull())
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                sleep(3);
            }
            boost::this_thread::interruption_point();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Verus merge mining thread terminated\n");
    }
}

void CConnectedChains::SubmissionThreadStub()
{
    ConnectedChains.SubmissionThread();
}

void CConnectedChains::QueueEarnedNotarization(CBlock &blk, int32_t txIndex, int32_t height)
{
    // called after winning a block that contains an earned notarization
    // the earned notarization and its height are queued for processing by the submission thread
    // when a new notarization is added, older notarizations are removed, but all notarizations in the current height are
    // kept
    LOCK(cs_mergemining);

    // we only care about the last
    earnedNotarizationHeight = height;
    earnedNotarizationBlock = blk;
    earnedNotarizationIndex = txIndex;
}

bool IsChainDefinitionInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_CURRENCY_DEFINITION;
}

