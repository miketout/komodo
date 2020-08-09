/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This implements the public blockchains as a service (PBaaS) notarization protocol, VerusLink.
 * VerusLink is a new distributed consensus protocol that enables multiple public blockchains 
 * to operate as a decentralized ecosystem of chains, which can interact and easily engage in cross 
 * chain transactions.
 * 
 */

#include <univalue.h>
#include "main.h"
#include "txdb.h"
#include "rpc/pbaasrpc.h"

#include <assert.h>

using namespace std;

extern uint160 VERUS_CHAINID;
extern uint160 ASSETCHAINS_CHAINID;
extern string VERUS_CHAINNAME;
extern string PBAAS_HOST;
extern string PBAAS_USERPASS;
extern int32_t PBAAS_PORT;

CPBaaSNotarization::CPBaaSNotarization(const CScript &scriptPubKey) :
                    nVersion(0),
                    protocol(CCurrencyDefinition::NOTARIZATION_AUTO),
                    notarizationHeight(0),
                    prevHeight(0),
                    crossHeight(0)
{
    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && 
        p.IsValid() &&
        (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
        p.vData.size())
    {
        ::FromVector(p.vData[0], *this);
    }
}

CPBaaSNotarization::CPBaaSNotarization(const CTransaction &tx, int32_t *pOutIdx) :
                    nVersion(0),
                    protocol(CCurrencyDefinition::NOTARIZATION_AUTO),
                    notarizationHeight(0),
                    prevHeight(0),
                    crossHeight(0)
{
    // the PBaaS notarization itself is a combination of proper inputs, one output, and
    // a sequence of opret chain objects as proof of the output values on the chain to which the
    // notarization refers, the opret can be reconstructed from chain data in order to validate
    // the txid of a transaction that does not contain the opret itself

    int32_t _outIdx;
    int32_t &outIdx = pOutIdx ? *pOutIdx : _outIdx;
    
    // a notarization must have notarization output that spends to the address indicated by the 
    // ChainID, an opret, that there is only one, and that it can be properly decoded to a notarization 
    // output, whether or not validate is true
    bool found = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && 
            p.IsValid() &&
            (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
            p.vData.size())
        {
            if (found)
            {
                this->mmrRoot.SetNull();
                break;
            }
            else
            {
                found = true;
                outIdx = i;
                ::FromVector(p.vData[0], *this);
            }
        }
    }
}

CPBaaSNotarization::CPBaaSNotarization(const UniValue &obj)
{
    nVersion = (uint32_t)uni_get_int(find_value(obj, "version"));

    CTxDestination currencyIDDest = DecodeDestination(uni_get_str(find_value(obj, "currencyid")));
    if (currencyIDDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        currencyID = GetDestinationID(currencyIDDest);
    }

    CBitcoinAddress notaryAddress(uni_get_str(find_value(obj, "notaryaddress")));
    CKeyID notaryKey;
    notaryAddress.GetKeyID(notaryKey);
    notaryDest = notaryKey;

    notarizationHeight = uni_get_int(find_value(obj, "notarizationheight"));
    mmrRoot = uint256S(uni_get_str(find_value(obj, "mmrroot")));
    notarizationPreHash = uint256S(uni_get_str(find_value(obj, "notarizationprehash")));
    compactPower = ArithToUint256((UintToArith256(uint256S(uni_get_str(find_value(obj, "stake")))) << 128) + 
                                   UintToArith256(uint256S(uni_get_str(find_value(obj, "work")))));

    auto currencyObj = find_value(obj, "currencystate");
    if (currencyObj.isObject())
    {
        currencyState = CCurrencyState(currencyObj);
    }

    prevNotarization = uint256S(uni_get_str(find_value(obj, "prevnotarization")));
    prevHeight = uni_get_int(find_value(obj, "prevheight"));
    crossNotarization = uint256S(uni_get_str(find_value(obj, "crossnotarization")));
    crossHeight = uni_get_int(find_value(obj, "crossheight"));
    auto nodesUni = find_value(obj, "nodes");
    if (nodesUni.isArray())
    {
        vector<UniValue> nodeVec = nodesUni.getValues();
        for (auto node : nodeVec)
        {
            nodes.push_back(CNodeData(uni_get_str(find_value(node, "networkaddress")), uni_get_str(find_value(node, "nodeidentity"))));
        }
    }
}

bool CPBaaSNotarization::GetLastNotarization(const uint160 &currencyID,
                                             uint32_t eCode, 
                                             int32_t startHeight,
                                             int32_t endHeight,
                                             uint256 *txIDOut,
                                             CTransaction *txOut)
{
    CPBaaSNotarization notarization;
    std::vector<CAddressIndexDbEntry> notarizationIndex;
    // get the last unspent notarization for this currency, which is valid by definition for a token
    if (GetAddressIndex(CCrossChainRPCData::GetConditionID(currencyID, eCode), 1, notarizationIndex, startHeight, endHeight))
    {
        // filter out all transactions that do not spend from the notarization thread, or originate as the
        // chain definition
        for (auto it = notarizationIndex.rbegin(); it != notarizationIndex.rend(); it++)
        {
            // first unspent notarization that is valid is the one we want, skip spending
            if (it->first.spending)
            {
                continue;
            }
            LOCK(mempool.cs);
            CTransaction oneTx;
            uint256 blkHash;
            if (myGetTransaction(it->first.txhash, oneTx, blkHash))
            {
                if ((notarization = CPBaaSNotarization(oneTx.vout[it->first.index].scriptPubKey)).IsValid())
                {
                    *this = notarization;
                    if (txIDOut)
                    {
                        *txIDOut = it->first.txhash;
                    }
                    if (txOut)
                    {
                        *txOut = oneTx;
                    }
                    break;
                }
            }
            else
            {
                LogPrintf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: error transaction %s not found, may need reindexing\n", __func__, it->first.txhash.GetHex().c_str());
                continue;
            }
        }
    }
    return notarization.IsValid();
}

CTransactionFinalization::CTransactionFinalization(const CTransaction &tx, uint32_t *pEcode, int32_t *pFinalizationOutNum)
{
    bool found = false;
    bool error = false;
    int32_t finalizeOutNum = -1;
    for (int i = 0; i < tx.vout.size() && !error; i++)
    {
        uint32_t _ecode;
        uint32_t &ecode = pEcode ? *pEcode : _ecode;
        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(&ecode))
        {
            if (ecode == EVAL_FINALIZE_NOTARIZATION || ecode == EVAL_FINALIZE_EXPORT)
            {
                if (finalizeOutNum != -1)
                {
                    error = true;
                    confirmedInput = finalizeOutNum = -1;
                }
                else
                {
                    COptCCParams p;
                    finalizeOutNum = i;

                    if (!IsPayToCryptoCondition(tx.vout[i].scriptPubKey, p, *this))
                    {
                        confirmedInput = -1;
                    }
                }
            }
        }
    }
    if (!error && finalizeOutNum != -1 && pFinalizationOutNum)
    {
        *pFinalizationOutNum = finalizeOutNum;
    }
}

CChainNotarizationData::CChainNotarizationData(UniValue &obj)
{
    version = (uint32_t)uni_get_int(find_value(obj, "version"));
    UniValue vtxUni = find_value(obj, "vtx");
    if (vtxUni.isArray())
    {
        vector<UniValue> vvtx = vtxUni.getValues();
        for (auto o : vvtx)
        {
            vtx.push_back(make_pair(uint256S(uni_get_str(find_value(o, "txid"))), CPBaaSNotarization(find_value(o, "notarization"))));
        }
    }

    lastConfirmed = (uint32_t)uni_get_int(find_value(obj, "lastconfirmed"));
    UniValue forksUni = find_value(obj, "forks");
    if (forksUni.isArray())
    {
        vector<UniValue> forksVec = forksUni.getValues();
        for (auto fv : forksVec)
        {
            if (fv.isArray())
            {
                forks.push_back(vector<int32_t>());
                vector<UniValue> forkVec = fv.getValues();
                for (auto fidx : forkVec)
                {
                    forks.back().push_back(uni_get_int(fidx));
                }
            }
        }
    }

    bestChain = (uint32_t)uni_get_int(find_value(obj, "bestchain"));
}

UniValue CChainNotarizationData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)version));
    UniValue notarizations(UniValue::VARR);
    for (int64_t i = 0; i < vtx.size(); i++)
    {
        UniValue notarization(UniValue::VOBJ);
        notarization.push_back(Pair("index", i));
        notarization.push_back(Pair("txid", vtx[i].first.GetHex()));
        notarization.push_back(Pair("notarization", vtx[i].second.ToUniValue()));
        notarizations.push_back(notarization);
    }
    obj.push_back(Pair("notarizations", notarizations));
    UniValue Forks(UniValue::VARR);
    for (int32_t i = 0; i < forks.size(); i++)
    {
        UniValue Fork(UniValue::VARR);
        for (int32_t j = 0; j < forks[i].size(); j++)
        {
            Fork.push_back(forks[i][j]);
        }
        Forks.push_back(Fork);
    }
    obj.push_back(Pair("forks", Forks));
    if (IsConfirmed())
    {
        obj.push_back(Pair("lastconfirmedheight", (int32_t)vtx[lastConfirmed].second.notarizationHeight));
    }
    obj.push_back(Pair("lastconfirmed", lastConfirmed));
    obj.push_back(Pair("bestchain", bestChain));
    return obj;
}

vector<CInputDescriptor> AddSpendsAndFinalizations(CChainNotarizationData &cnd, 
                                                   const uint256 &lastNotarizationID, 
                                                   CMutableTransaction &mnewTx, 
                                                   int32_t *pConfirmedInput, 
                                                   int32_t *pConfirmedIdx, 
                                                   CTxDestination *pConfirmedDest)
{
    // determine all finalized and orphaned transactions that should be spent as input
    // always spend the notarization thread
    vector<CInputDescriptor> txInputs;

    set<int32_t> finalized;
    int32_t &confirmedIdx = *pConfirmedIdx;
    confirmedIdx = -1;

    int32_t confirmOffset = (cnd.lastConfirmed == -1) ? 0 : 1;

    // if we are the second notarization after a block 1 notarization that is considered confirmed,
    // spend the one before us
    if (cnd.vtx.size() == 1 && !IsVerusActive() && cnd.lastConfirmed != -1)
    {
        finalized.insert(cnd.lastConfirmed);
        confirmedIdx = cnd.lastConfirmed;
    }

    // now, create inputs from the most recent notarization in cnd and the finalization outputs that we either confirm or invalidate
    for (int j = 0; j < cnd.forks.size(); j++)
    {
        int k;
        for (k = cnd.forks[j].size() - 1; k >= 0; k--)
        {
            // the first instance of the prior notarization we find represents the prior fork we are confirming
            // it may be intact or part of another. in any case, we may create a new fork or add on to an existing one
            // whether we create a new fork or add to an existing one, we may confirm an entry
            // if we do, we will spend the finalizatoin output of every fork that does no include that entry as well
            // as that entry itself
            if (cnd.vtx[cnd.forks[j][k]].first == lastNotarizationID)
            {
                // if we have a fork that is long enough that we will add to, we are confirming the entry final confirmations before us
                if (k >= CPBaaSNotarization::FINAL_CONFIRMATIONS + confirmOffset)
                {
                    int32_t confirmedEntry = k - CPBaaSNotarization::FINAL_CONFIRMATIONS;
                    confirmedIdx = cnd.forks[j][confirmedEntry];
                    finalized.insert(confirmedIdx);

                    // if we would add the 10th confirmation to the second in this fork, we are confirming 
                    // a new notarization, spend it's finalization output and all those that disagree with it
                    // the only chains that are confirmed to disagree will have a different index in the
                    // second position, which is the one we are confirming
                    for (int l = 0; l < cnd.forks.size(); l++)
                    {
                        // spend all forks that do not contain the notarization from the confirmed offset forward
                        if (cnd.forks[l][confirmOffset] != confirmedIdx)
                        {
                            for (int m = confirmOffset; m < cnd.forks[l].size(); m++)
                            {
                                // put indexes of all orphans into the finalized set
                                finalized.insert(cnd.forks[l][m]);
                            }
                        }
                    }
                    break;
                }
            }
        }
        // if we short circuited by confirmation, short circuit here too
        if (k >= 0)
        {
            break;
        }
    }

    LOCK2(cs_main, mempool.cs);

    // now, we should spend the last notarization output and all finalization outputs in the finalized set
    // first, we need to get the outpoint for the notarization, then each finalization as well
    uint256 notarizationThreadID, blkHash;
    CTransaction threadTx;
    uint32_t j;
    if (cnd.vtx.size())
    {
        notarizationThreadID = cnd.vtx.back().first;
        if (myGetTransaction(notarizationThreadID, threadTx, blkHash))
        {
            for (j = 0; j < threadTx.vout.size(); j++)
            {
                uint32_t code;
                if (threadTx.vout[j].scriptPubKey.IsPayToCryptoCondition(&code) && (code == EVAL_EARNEDNOTARIZATION || code == EVAL_ACCEPTEDNOTARIZATION))
                {
                    break;
                }
            }
        }
        else
        {
            notarizationThreadID.SetNull();
        }
    }

    // either we have no last notarization, or we found its notarization output
    assert(notarizationThreadID.IsNull() || j < threadTx.vout.size());

    // if this isn't the first notarization, setup inputs
    if (!notarizationThreadID.IsNull())
    {
        // spend notarization output of the last notarization
        txInputs.push_back(CInputDescriptor(threadTx.vout[j].scriptPubKey, threadTx.vout[j].nValue, CTxIn(notarizationThreadID, j, CScript())));
        mnewTx.vin.push_back(CTxIn(notarizationThreadID, j, CScript()));

        for (auto nidx : finalized)
        {
            // we need to reload all transactions and get their finalization outputs
            // this could be made more efficient by keeping them earlier or standardizing output numbers
            CCoins coins;
            uint256 hblk;
            if (!pcoinsTip->GetCoins(cnd.vtx[nidx].first, coins))
            {
                // if this fails, we can't follow consensus and must fail
                LogPrintf("%s: Cannot get coins to spend from finalized tx %s\n", __func__, cnd.vtx[nidx].first.GetHex().c_str());
                return vector<CInputDescriptor>();
            }
            int k;
            CPBaaSNotarization pbn;
            for (k = 0; k < coins.vout.size(); k++)
            {
                COptCCParams p;

                if (!coins.vout[k].IsNull() && IsPayToCryptoCondition(coins.vout[k].scriptPubKey, p))
                {
                    if (nidx == confirmedIdx && (p.evalCode == EVAL_EARNEDNOTARIZATION || p.evalCode == EVAL_ACCEPTEDNOTARIZATION))
                    {
                        pbn = CPBaaSNotarization(p.vData[0]);
                    }
                    else if (p.evalCode == EVAL_FINALIZE_NOTARIZATION)
                    {
                        break;
                    }
                }
            }
            assert(k < coins.vout.size());

            // printf("spending finalization output of hash: %s\nprevout.n: %d\n", cnd.vtx[nidx].first.GetHex().c_str(), k);

            // spend all of them
            txInputs.push_back(CInputDescriptor(coins.vout[k].scriptPubKey, coins.vout[k].nValue, CTxIn(cnd.vtx[nidx].first, k, CScript())));
            mnewTx.vin.push_back(CTxIn(cnd.vtx[nidx].first, k, CScript()));
            if (nidx == confirmedIdx)
            {
                *pConfirmedInput = mnewTx.vin.size() - 1;
                *pConfirmedDest = pbn.notaryDest;
                cnd.lastConfirmed = nidx;
            }
        }
    }
    return txInputs;
}

bool GetNotarizationAndFinalization(int32_t ecode, CMutableTransaction mtx, CPBaaSNotarization &pbn, uint32_t *pNotarizeOutIndex, uint32_t *pFinalizeOutIndex)
{
    bool notarize = false, finalize = false, duplicate = false;
    for (int j = 0; j < mtx.vout.size(); j++)
    {
        COptCCParams p;

        if (IsPayToCryptoCondition(mtx.vout[j].scriptPubKey, p))
        {
            if (p.evalCode == ecode)
            {
                *pNotarizeOutIndex = j;
                pbn = CPBaaSNotarization(p.vData[0]);
                if (notarize) duplicate = true;
                notarize = true;
            }
            else if (p.evalCode == EVAL_FINALIZE_NOTARIZATION)
            {
                *pFinalizeOutIndex = j;
                if (finalize) duplicate = true;
                finalize = true;
            }
        }
    }
    return finalize && notarize && !duplicate;
}

// This assumes we are running on a PBaaS chain.
// Creates a notarization that will be in the current block and use the prevMMR to prove the block before us
// we refer to the transactions on the Verus chain and on our chain with which we agree, and if we have added the
// 10th validation to a notarization in our lineage, we finalize it as validated and finalize any conflicting notarizations
// as invalidated.
// Currently may return with insufficient or excess input relative to outputs.
// If there is a notary connection availabe, lastConfirmed is set with the last confirmed notarization
// that enables a check for any cross chain imports that could be mined into a block, whether it is a notarization block or not.
// Usually, a miner will do this when they creat an earned notarization, but we should do it at every chance to prevent that from
// being a significant point of failure and earn more in return
bool CreateEarnedNotarization(CMutableTransaction &mnewTx, vector<CInputDescriptor> &inputs, CTransaction &lastTx, CTransaction &crossTx, CTransaction &lastConfirmed, int32_t height, int32_t *pConfirmedInput, CTxDestination *pConfirmedDest)
{
    // we can only create a notarization if there is an available Verus chain
    if (!ConnectedChains.IsVerusPBaaSAvailable())
    {
        return false;
    }

    UniValue params(UniValue::VARR);
    params.push_back(ASSETCHAINS_CHAINID.GetHex());

    CChainNotarizationData cnd;

    UniValue txidArr(UniValue::VARR);

    std::vector<pair<CTransaction, uint256>> txes;
    {
        LOCK2(cs_main, mempool.cs);
        if (GetNotarizationData(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION, cnd, &txes))
        {
            if (cnd.IsConfirmed())
            {
                lastConfirmed = txes[cnd.lastConfirmed].first;
            }

            // make an array of all possible txids on this chain
            for (auto it : cnd.vtx)
            {
                txidArr.push_back(it.first.GetHex());
            }
        }
        else if (height != 1)
        {
            return false;
        }
    }

    params.push_back(txidArr);

    //printf("%s: about to get cross notarization with %lu notarizations found\n", __func__, cnd.vtx.size());

    UniValue result;
    try
    {
        result = find_value(RPCCallRoot("getcrossnotarization", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }

    // if no error, prepare notarization
    auto uv1 = find_value(result, "crosstxid");
    auto uv2 = find_value(result, "txid");
    auto uv3 = find_value(result, "rawtx");
    auto uv4 = find_value(result, "newtx");

    uint256 lastNotarizationID;

    // if we passed no notarizations known to the other chain, the crosstxid returned can be null
    if (uv1.isStr())
    {
        lastNotarizationID.SetHex((uv1.get_str()));
    }

    if ((lastNotarizationID.IsNull() && (cnd.vtx.size() != 0)) || !uv2.isStr() || !uv3.isStr() || !uv4.isStr())
    {
        //printf("%s: no corresponding cross-notarization found\n", __func__);
        return false;
    }

    uint256 crossNotarizationID;
    crossNotarizationID.SetHex((uv2.get_str()));

    if (crossNotarizationID.IsNull() || !DecodeHexTx(crossTx, uv3.get_str()))
    {
        printf("%s: invalid parameters 2\n", __func__);
        return false;
    }

    CTransaction newTx;
    if (!DecodeHexTx(newTx, uv4.get_str()))
    {
        LogPrintf("%s: invalid transaction decode.\n", __func__);
        return false;
    }

    // we have more work to do on it
    mnewTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);
    // there should be no inputs, copy the outputs to the new transaction
    uint32_t notarizeOutIndex = -1, finalizeOutIndex = -1;
    CPBaaSNotarization pbn;
    for (int j = 0; j < newTx.vout.size(); j++)
    {
        COptCCParams p;

        if (IsPayToCryptoCondition(newTx.vout[j].scriptPubKey, p))
        {
            if (p.evalCode == EVAL_EARNEDNOTARIZATION)
            {
                notarizeOutIndex = j;
                pbn = CPBaaSNotarization(p.vData[0]);
            }
            else if (p.evalCode == EVAL_FINALIZE_NOTARIZATION)
            {
                finalizeOutIndex = j;
            }
        }
        mnewTx.vout.push_back(newTx.vout[j]);
    }

    if (notarizeOutIndex == -1 || finalizeOutIndex == -1 || !pbn.IsValid() || pbn.nVersion != PBAAS_VERSION)
    {
        LogPrintf("%s: invalid notarization transaction returned from %s\n", __func__, VERUS_CHAINNAME.c_str());
        return false;
    }

    LOCK2(cs_main, mempool.cs);

    vector<CBaseChainObject *> chainObjs = RetrieveOpRetArray(mnewTx.vout.back().scriptPubKey);
    vector<CBaseChainObject *> compressedChainObjs;

    // convert any op_return header to a smaller header_ref if it was merge mined, which modifies both the
    // op_return and the opRetProof in the notarization
    for (int j = 0; j < chainObjs.size(); j++)
    {
        uint256 hash;
        if (chainObjs[j]->objectType == CHAINOBJ_HEADER && 
            !((CChainObject<CBlockHeader> *)chainObjs[j])->object.IsVerusPOSBlock() && 
            mapBlockIndex.count(hash = ((CChainObject<CBlockHeader> *)chainObjs[j])->object.GetHash()))
        {
            // this is a common block between chains, replace the header with a header_ref in both the opret and proof
            pbn.opRetProof.types[j] = CHAINOBJ_HEADER_REF;
            CHeaderRef hr = CHeaderRef(hash, CPBaaSPreHeader(((CChainObject<CBlockHeader> *)chainObjs[j])->object));
            CBaseChainObject *hRef = new CChainObject<CHeaderRef>(CHAINOBJ_HEADER_REF, hr);
            compressedChainObjs.push_back(hRef);
            delete (CChainObject<CBlockHeader> *)chainObjs[j];
        }
        else
        {
            compressedChainObjs.push_back(chainObjs[j]);
        }
        if (height == 1)
        {
            // at block one, we use the compact target of the main chain divided by 8 as the default difficulty. if a chain can interest
            // at least 1/8th of the mining public, it launches at speed, otherwise slower or faster and adjusts
            CChainParams &params = Params(CBaseChainParams::MAIN);

            // TODO:PBAAS uncomment this and add a block 1 check that establishes the powAlternate and validity of block 1
            // block 1 must then be processed before others to confirm the notarization header target and validate a chain
            /*
            if (chainObjs[j]->objectType == CHAINOBJ_HEADER)
            {
                params.consensus.powAlternate = arith_uint256(((CChainObject<CBlockHeader> *)chainObjs[j])->object.nBits) >> (VERUSHASH2_SHIFT + 3);
            }
            else if (chainObjs[j]->objectType == CHAINOBJ_HEADER_REF)
            {
                params.consensus.powAlternate = arith_uint256(((CChainObject<CHeaderRef> *)chainObjs[j])->object.preHeader.nBits) >> (VERUSHASH2_SHIFT + 3);
            }
            */
        }
    }

    mnewTx.vout.back().scriptPubKey = StoreOpRetArray(compressedChainObjs);

    // now that we've finished making the opret, free the objects
    DeleteOpRetObjects(compressedChainObjs);

    if (!mnewTx.vout.back().scriptPubKey.size())
    {
        printf("%s: failed to create OP_RETURN output", __func__);
        return false;
    }

    // we need to update our earned notarization and finalization outputs, which should both be present and incomplete
    // add up inputs, and make sure that the main notarization output holds any excess over minimum, if not enough, we need
    // to spend a coinbase instant spend

    CPBaaSNotarization crossNotarizaton(crossTx);
    std::vector<CCurrencyDefinition> chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(crossTx);
    if (chainDefs.size())
    {
        // must either have a prior notarization or be the definition
        printf("%s: no prior notarization and no chain definition in cross notarization\n", __func__);
        return false;
    }

    CCurrencyDefinition chainDef = chainDefs[0];

    pbn.prevNotarization = lastNotarizationID;
    if (lastNotarizationID.IsNull())
    {
        pbn.prevHeight = 0;
    }
    else
    {
        uint256 hashBlk;
        // get the last notarization
        if (!myGetTransaction(lastNotarizationID, lastTx, hashBlk))
        {
            printf("Error: cannot find notarization transaction %s on %s chain\n", lastNotarizationID.GetHex().c_str(), ASSETCHAINS_SYMBOL);
            return false;
        }
        auto lastTxBlkIt = mapBlockIndex.find(hashBlk);
        if (lastTxBlkIt == mapBlockIndex.end())
        {
            printf("Error: cannot find block %s on %s chain\n", hashBlk.GetHex().c_str(), ASSETCHAINS_SYMBOL);
            return false;
        }

        CPBaaSNotarization prevNZ(lastTx);
        pbn.prevHeight = prevNZ.notarizationHeight;

        int32_t blocksToWait = (pbn.prevHeight + CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED) - pbn.notarizationHeight;
        if (blocksToWait > 0)
        {
            // can't make another notarization yet
            printf("%s: waiting for %d blocks to notarize - current height.%d\n", __func__, blocksToWait, pbn.notarizationHeight);
            return false;
        }
    }

    // determine all finalized transactions that should be spent as input
    int32_t confirmedIndex = -1;
    inputs = AddSpendsAndFinalizations(cnd, lastNotarizationID, mnewTx, pConfirmedInput, &confirmedIndex, pConfirmedDest);
    // update lastConfirmed if we should
    if (confirmedIndex != -1)
    {
        lastConfirmed = txes[confirmedIndex].first;
    }

    CCcontract_info CC;
    CCcontract_info *cp;
    std::vector<CTxDestination> dests;
    std::vector<CTxDestination> indexDests;

    // make the earned notarization output
    cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);

    if (chainDef.notarizationProtocol == chainDef.NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CIdentityID(chainDef.GetID())});
    }
    else
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION))});
    mnewTx.vout[notarizeOutIndex] = CTxOut(PBAAS_MINNOTARIZATIONOUTPUT, 
                                           MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &pbn), &indexDests));
    
    // make the finalization output
    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);

    // if not centrally controlled, change pubkey
    if (chainDef.notarizationProtocol != chainDef.NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    // we need to store the input that we confirmed if we spent finalization outputs
    CTransactionFinalization nf(*pConfirmedInput);

    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(VERUS_CHAINID, EVAL_FINALIZE_NOTARIZATION))});

    // update crypto condition with final notarization output data
    mnewTx.vout[finalizeOutIndex] = CTxOut(PBAAS_MINNOTARIZATIONOUTPUT, 
                                           MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &nf), &indexDests));

    // if this is block 1, add chain definition output with updated currency numbers

    return true;
}

// this validates that the data in the earned notarization, including its distance from the prior cross-notarization being adequate
// are all correct. it makes no calls outside of the current daemon to do its validation
// it requires that the cs_main is held, as it uses the mapBlockIndex
bool ValidateEarnedNotarization(CTransaction &ntx, CPBaaSNotarization *notarization)
{
    // validate:
    //  - the notarization refers to the first prior notarization on this chain that refers to the cross notarization commitment
    //  - the notarization is either in a PoS block, or a block that meets the hash qualification to be merge mined into
    //    our notary chain. this does not mean that it will be validated further, but it disqualifies all earned notarizations that
    //    are definitely not valid PoS or winners on both this and its notary chain. This ensures variable cross checking
    //    of PoS notarizations, depending on VRSC rewards for notaries, but keeps the weighted control of the chain's
    //    definition most in the hands of those with the stake in the chain.
    //  - all objects referred to by the cross notarization tx, which no longer contains its op_ret, are present on this chain
    //    and can be used to re-create the cross chain transaction's op_ret. ensure that when doing so, the cross-chain
    //    tranaction hashes to the same value as committed to in the notarization
    //

    CPBaaSNotarization pbn;

    // only recreate the notarization if we weren't passed one
    if (notarization == NULL)
    {
        if (!(pbn = CPBaaSNotarization(ntx)).IsValid())
        {
            LogPrintf("%s: invalid notarization transaction %s\n", __func__, ntx.GetHash().GetHex().c_str());
            return false;
        }
        notarization = &pbn;
    }

    CPBaaSNotarization &n = *notarization;

    // check all the basics
    // if we are running on the Verus chain, we assume it is checking against a chain we are notarizing
    if (IsVerusActive())
    {
        // for now, we fail in this case
        LogPrintf("%s: called from %s chain\n", __func__, ASSETCHAINS_SYMBOL);
        return false;
    }
    else if (n.currencyID != VERUS_CHAINID || !ntx.vout.size() || !ntx.vout.back().scriptPubKey.IsOpReturn())
    {
        LogPrintf("%s: earned notarization for chain %s for unrecognized chain ID %s\n", __func__, VERUS_CHAINNAME, n.currencyID.GetHex().c_str());
        return false;
    }

    vector<CBaseChainObject *> chainObjects = RetrieveOpRetArray(ntx.vout.back().scriptPubKey);

    // we now have ownership of all chain object memory to delete below, make sure the objects are as we expect
    // first object should be a header that is either PoS on this chain, or header ref and mined with a block hash that could meet the
    // requirements of the block in our notary chain
    bool retVal = false;
    CCrossChainProof notarizationProof;

    // all earned notarizations have chain objects, one header/headerref, one tx, and two proofs at least
    if (chainObjects.size() != 1 ||
        chainObjects[0]->objectType != CHAINOBJ_CROSSCHAINPROOF ||
        (notarizationProof = ((CChainObject<CCrossChainProof> *)chainObjects[0])->object).chainObjects.size() < 3 ||
        !(notarizationProof.chainObjects[0]->objectType == CHAINOBJ_HEADER || notarizationProof.chainObjects[0]->objectType == CHAINOBJ_HEADER_REF) ||
        !(notarizationProof.chainObjects[1]->objectType == CHAINOBJ_TRANSACTION_PROOF) ||
        !(notarizationProof.chainObjects[2]->objectType == CHAINOBJ_PRIORBLOCKS))
    {
        LogPrintf("%s: notarization must contain at least one block and one transaction proof\n", __func__);
    }
    else
    {
        // make a reference to the block header, either the full POS header, or a reconstructed, merge mined header
        CBlockHeaderProof *bhp = nullptr;
        CBlockHeaderAndProof *bhap = nullptr;

        CBlockHeader *pbh = NULL;
        CBlockHeader blockHeader;

        uint256 mmrProofResult;

        // either POS and a full header + proof, or merge mined and only a header ref + proof
        if (notarizationProof.chainObjects[0]->objectType == CHAINOBJ_HEADER)
        {
            bhap = &((CChainObject<CBlockHeaderAndProof> *)notarizationProof.chainObjects[0])->object;
            blockHeader = bhap->blockHeader;
            pbh = &blockHeader;
            mmrProofResult = bhap->ValidateBlockHash(pbh->GetHash(), bhap->BlockNum());
            if (bhap->ValidateBlockMMRRoot(bhap->BlockPreHeader().hashBlockMMRRoot, bhap->BlockNum()) != mmrProofResult)
            {
                LogPrintf("%s: POS block header proof failure for block %s at height %d\n", __func__, pbh->GetHash().GetHex().c_str(), bhap->BlockNum());
                pbh = nullptr;
            }
            // TODO: prove and validate POS header source and entropy
        }
        else
        {
            bhp = &((CChainObject<CBlockHeaderProof> *)notarizationProof.chainObjects[0])->object;
            auto blockIt = mapBlockIndex.find(bhp->BlockHash());
            if (blockIt == mapBlockIndex.end())
            {
                LogPrintf("%s: Expected merge mined block not found\n", __func__);
                pbh = nullptr;
            }
            else
            {
                // convert header to alternate chain
                *pbh = bhp->NonCanonicalHeader(*pbh);
                mmrProofResult = bhp->ValidateBlockHash(bhp->BlockHash(), bhp->BlockNum());
                if (bhp->ValidateBlockMMRRoot(bhap->BlockPreHeader().hashBlockMMRRoot, bhp->BlockNum()) != mmrProofResult)
                {
                    LogPrintf("%s: Merge mined block header proof failure for block %s at height %d\n", __func__, pbh->GetHash().GetHex().c_str(), bhap->BlockNum());
                    pbh = nullptr;
                }
            }
        }

        if (pbh)
        {
            CBlockHeader &bh = *pbh;

            CPartialTransactionProof &txProof = ((CChainObject<CPartialTransactionProof> *)notarizationProof.chainObjects[1])->object;
            CPriorBlocksCommitment &priorBlocks = ((CChainObject<CPriorBlocksCommitment> *)notarizationProof.chainObjects[2])->object;

            arith_uint256 target;
            target.SetCompact(bh.nBits);
            uint256 blkHash = bh.GetHash();
            arith_uint256 arithHash = UintToArith256(blkHash);
            bool fail = false;

            if (mmrProofResult == pbn.mmrRoot && arithHash <= target)
            {
                // block is correct, check tx
                CTransaction notTx;
                CPBaaSNotarization cpbn;
                if (txProof.GetPartialTransaction(notTx) != mmrProofResult)
                {
                    LogPrintf("%s: prior notarization fails proof validation on its home chain\n", __func__);
                    fail = true;
                }
                else
                {
                    // get prior cross notarization
                    cpbn = CPBaaSNotarization(notTx);
                }

                if (fail || !cpbn.IsValid() || cpbn.opRetProof.orIndex)
                {
                    LogPrintf("%s: notarization must be valid and opret must start at index 0\n", __func__);
                }
                else
                {
                    retVal = true;
                }
            }
        }
    }

    DeleteOpRetObjects(chainObjects);

    return retVal;
}

// This creates an accepted notarization from an earned notarization created by a PBaaS chain.
// this assumes it is running on the PBaaS chain when called.
// it creates much of the required accepted notarization, then passes it to the Verus daemon for completion.
// The earned notarization will have the last notarization that we agree with. In order to make a valid
// accepted notarization, we must meet the following requireents:
// 1) the last notarization must still be the last we agree with
// 2) the last notarization must be CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED or more blocks behind us
// 3) the earned notarization must be in either a POS block of the chain being notarized, or a block that is merge mined and
//    has the same block hash on both notary chain and chain being notarized.
// block is block of earned notarization, entx is earned notarization transaction, height is height of block
uint256 CreateAcceptedNotarization(const CBlock &blk, int32_t txIndex, int32_t height)
{
    uint256 nullRet = uint256();
    const CTransaction &entx = blk.vtx[txIndex];
   
    // we can only create a notarization if there is an available Verus chain
    if (!ConnectedChains.IsVerusPBaaSAvailable())
    {
        LogPrintf("%s: cannot connect to %s\n", __func__, VERUS_CHAINNAME.c_str());
        return nullRet;
    }

    int32_t outputIndex;
    CPBaaSNotarization crosspbn(entx, &outputIndex);
    if (!crosspbn.IsValid())
    {
        LogPrintf("%s: invalid earned notarization\n", __func__);
        return nullRet;
    }

    CChainObject<CBlockHeaderAndProof> latestHeaderObj;
    CChainObject<CBlockHeaderProof> latestHeaderObjRef;
    CChainObject<CPartialTransactionProof> strippedTxObj;
    CChainObject<CPriorBlocksCommitment> priorBlocksObj;

    COpRetProof orp;
    CPBaaSNotarization pbn;
    CCrossChainProof ccp;
    {
        LOCK(cs_main);
        if (height > chainActive.Height())
        {
            LogPrintf("%s: height requested is greater than chain height\n", __func__);
            return nullRet;
        }

        // prepare a partial notarization with all that is needed from this PBaaS chain at the height requested
        // if it is from a mined block, prepare the notarization assuming merge mined block
        // it will be rejected if it was not successfully merge mined
        auto mmv = chainActive.GetMMV();
        mmv.resize(height);
        uint256 preHash = mmv.mmr.GetNode(height).hash;

        CMMRProof blockProof;
        if (!chainActive.GetBlockProof(mmv, blockProof, height))
        {
            LogPrintf("%s: can't prove block\n", __func__);
            return nullRet;
        }

        // if this is a POS header, include the whole header, if merge mined,
        // only the proof and non-canonical data
        if (blk.IsVerusPOSBlock())
        {
            ccp << CBlockHeaderAndProof(blockProof, blk);
            orp.types.push_back(CHAINOBJ_HEADER);
        }
        else
        {
            ccp << CBlockHeaderProof(blockProof, blk);
            orp.types.push_back(CHAINOBJ_HEADER_REF);
        }
        orp.hashes.push_back(blk.GetHash());

        uint256 txHash = entx.GetHash();
        orp.types.push_back(CHAINOBJ_TRANSACTION_PROOF);
        orp.hashes.push_back(txHash);

        int i;
        for (i = 0; i < blk.vtx.size(); i++)
        {
            if (blk.vtx[i].GetHash() == txHash)
            {
                ccp << blk.GetPartialTransactionProof(blk.vtx[i], i, std::vector<std::pair<int16_t, int16_t>>({{CTransactionHeader::TX_OUTPUT, outputIndex}}));
                break;
            }
        }

        if (i == blk.vtx.size())
        {
            LogPrintf("%s: cannot locate earned notarization in block\n", __func__);
            return nullRet;
        }

        // add the MMR block nodes between the last notarization and this one, containing root that combines merkle, block, and compact power hashes
        CPriorBlocksCommitment priorBlocks;
        int numPriorBlocks = height - crosspbn.crossHeight;
        int maxPriorBlocks = PBAAS_MAXPRIORBLOCKS > (height - 1) ? ((height - 1) < 1 ? 0 : (height - 1)) : PBAAS_MAXPRIORBLOCKS;

        if (numPriorBlocks > maxPriorBlocks) numPriorBlocks = maxPriorBlocks;

        // push back the merkle, block hash, and block power commitments for prior blocks to ensure no
        // unintended notary overlap
        for (int i = numPriorBlocks - 1; i >= 0; i--)
        {
            priorBlocks.priorBlocks.push_back(mmv.mmr.GetNode(height - i).hash);
        }

        ccp << priorBlocks;

        orp.types.push_back(CHAINOBJ_PRIORBLOCKS);
        orp.hashes.push_back(::GetHash(priorBlocks));

        pbn.nVersion = CPBaaSNotarization::CURRENT_VERSION;
        pbn.currencyID = ASSETCHAINS_CHAINID;
        pbn.notaryDest = crosspbn.notaryDest;
        pbn.notarizationHeight = height;

        auto node = mmv.GetRootNode();
        pbn.mmrRoot = node->hash;
        pbn.notarizationPreHash = preHash;
        pbn.compactPower = node->power;

        pbn.currencyState = ConnectedChains.GetCurrencyState(height);

        pbn.prevNotarization = crosspbn.crossNotarization;
        pbn.prevHeight = crosspbn.crossHeight;
        pbn.crossNotarization = entx.GetHash();
        pbn.crossHeight = crosspbn.notarizationHeight;

        pbn.opRetProof = orp;
    }

    {
        LOCK(cs_vNodes);
        if (!vNodes.empty())
        {
            for (int i = 0; i < vNodes.size(); i++)
            {
                CNodeStats stats;
                vNodes[i]->copyStats(stats);
                if (vNodes[i]->fSuccessfullyConnected && !vNodes[i]->fInbound)
                {
                    pbn.nodes.push_back(CNodeData(vNodes[i]->addr.ToString(), vNodes[i]->hashPaymentAddress));
                }
            }
        }
    }

    // reduce number to max by removing randomly
    while (pbn.nodes.size() > CPBaaSNotarization::MAX_NODES)
    {
        int toErase = GetRandInt(pbn.nodes.size() - 1);
        pbn.nodes.erase(pbn.nodes.begin() + toErase);
    }

    CChainObject<CCrossChainProof> chainProof(CHAINOBJ_CROSSCHAINPROOF, ccp);
    CScript opRet = StoreOpRetArray(std::vector<CBaseChainObject *>({&chainProof}));

    // ready to create a transaction to send to the other chain

    // setup to create the accepted notarization transaction
    CMutableTransaction mnewTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), height);

    // create notarization output
    CCcontract_info CC;
    CCcontract_info *cp;

    std::vector<CTxDestination> dests;
    std::vector<CTxDestination> indexDests;

    // make the accepted notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);

    if (ConnectedChains.ThisChain().notarizationProtocol == CCurrencyDefinition::NOTARIZATION_NOTARY_CHAINID)
    {
        dests = std::vector<CTxDestination>({CIdentityID(ASSETCHAINS_CHAINID)});
    }
    else
    {
        dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    }

    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(ASSETCHAINS_CHAINID, EVAL_ACCEPTEDNOTARIZATION))});
    mnewTx.vout.push_back(CTxOut(PBAAS_MINNOTARIZATIONOUTPUT, 
                                 MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_EARNEDNOTARIZATION, dests, 1, &pbn), &indexDests)));

    mnewTx.vout.push_back(CTxOut(0, opRet));

    // finish transaction by sending it to the other notary chain for completion and submission
    CTransaction notarization(mnewTx);

    // call an API, submit notarization that takes a partially complete notarization tx
    // then completes and submits it if possible
    // we can only create a notarization if there is an available Verus chain

    UniValue params(UniValue::VARR);
    params.push_back(EncodeHexTx(notarization));
    UniValue result = NullUniValue;
    try
    {
        result = find_value(RPCCallRoot("submitacceptednotarization", params), "result");
    } catch (exception e)
    {
        result = NullUniValue;
    }
    uint256 notarizationId;
    if (result.isStr())
    {
        notarizationId.SetHex(result.get_str());
    }
    return notarizationId;
}

/*
 * Validates a notarization output spend by ensuring that the spending transaction fulfills all requirements.
 * to accept an earned notarization as valid on the Verus blockchain, it must prove a transaction on the alternate chain, which is 
 * either the original chain definition transaction, which CAN and MUST be proven ONLY in block 1, or the latest notarization transaction 
 * on the alternate chain that represents an accurate MMR for this chain.
 * In addition, any accepted notarization must fullfill the following requirements:
 * 1) Must prove either a PoS block from the alternate chain or a merge mined block that is owned by the submitter and in either case, 
 *    the block must be exactly 8 blocks behind the submitted MMR used for proof.
 * 2) Must prove a chain definition tx and be block 1 or asserts a previous, valid MMR for the notarizing
 *    chain and properly prove objects using that MMR.
 * 3) Must spend the main notarization thread as well as any finalization outputs of either valid or invalid prior
 *    notarizations, and any unspent notarization contributions for this era. May also spend other inputs.
 * 4) Must output:
 *      a) finalization output of the expected reward amount, which will be sent when finalized
 *      b) normal output of reward from validated/finalized input if present, 50% to recipient / 50% to block miner less miner fee this tx
 *      c) main notarization thread output with remaining funds, no other output or fee deduction
 * 
 */
bool ValidateAcceptedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // TODO: this validates the spending transaction
    // check the following things:
    // 1. It represents a valid PoS or merge mined block on the other chain, and contains the header in the opret
    // 2. The MMR and proof provided for the currently asserted block can prove the provided header. The provided
    //    header can prove the last block referenced.
    // 3. This notarization is not a superset of an earlier notarization posted before it that it does not
    //    reference. If that is the case, it is rejected.
    // 4. Has all relevant inputs, including finalizes all necessary transactions, both confirmed and orphaned
    //printf("ValidateAcceptedNotarization\n");
    return true;
}
bool IsAcceptedNotarizationInput(const CScript &scriptSig)
{
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_ACCEPTEDNOTARIZATION;
}


/*
 * Ensures that a spend in an earned notarization of either an OpRet support transaction or summary notarization
 * are valid with respect to this chain. Any transaction that spends from an opret trasaction is either disconnected,
 * or contains the correct hashes of each object and transaction data except for the opret, which can be validated by
 * reconstructing the opret from the hashes on the other chain and verifying that it hashes to the same input value. This
 * enables full validation without copying redundant data back to its original chain.
 * 
 * In addition, each earned notarization must reference the last earned notarization with which it agrees and prove the last
 * accepted notarization on the alternate chain with the latest MMR. The earned notarization will not be accepted if there is
 * a later notarization that agrees with it already present in the alternate chain when it is submitted. 
 * 
 */
bool ValidateEarnedNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // this needs to validate that the block is mined or staked, that the notarization is properly formed,
    // cryptographically correct, and that it spends the proper finalization outputs
    // if the notarization causes a fork, it must include additional proof of blocks and their
    // power based on random block hash bits
    //printf("ValidateEarnedNotarization\n");
    return true;
}
bool IsEarnedNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_EARNEDNOTARIZATION;
}

/*
 * Ensures that the finalization, either as validated or orphaned, is determined by
 * 10 confirmations, either of this transaction, or of an alternate transaction on the chain that we do not derive
 * from. If the former, then this should be asserted to be validated, otherwise, it should be asserted to be invalidated.
 *  
 */
bool ValidateFinalizeNotarization(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // this must be spent by a transaction that is either the correct number of transactions ahead in confirming
    // us, or the correct number ahead in confirming another
    //printf("ValidateFinalizeNotarization\n");
    return true;
}
bool IsFinalizeNotarizationInput(const CScript &scriptSig)
{
    // this is an output check, and is incorrect. need to change to input
    uint32_t ecode;
    return scriptSig.IsPayToCryptoCondition(&ecode) && ecode == EVAL_FINALIZE_NOTARIZATION;
}

