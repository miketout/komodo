// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#endif
#include "init.h"
#include "main.h"
#include "metrics.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "validationinterface.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "timedata.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

#include "rpc/pbaasrpc.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/identity.h"
#include "transaction_builder.h"

using namespace std;

extern uint32_t ASSETCHAINS_ALGO;
extern int32_t ASSETCHAINS_EQUIHASH, ASSETCHAINS_LWMAPOS;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint64_t ASSETCHAINS_STAKED;
extern int32_t KOMODO_MININGTHREADS;
extern bool VERUS_MINTBLOCKS;
extern uint8_t NOTARY_PUBKEY33[33];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t USE_EXTERNAL_PUBKEY;
extern std::string NOTARY_PUBKEY;

#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
extern uint64_t ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_TIMEUNLOCKFROM, ASSETCHAINS_TIMEUNLOCKTO;
extern int64_t ASSETCHAINS_SUPPLY;
extern uint64_t ASSETCHAINS_REWARD[3], ASSETCHAINS_DECAY[3], ASSETCHAINS_HALVING[3], ASSETCHAINS_ENDSUBSIDY[3], ASSETCHAINS_ERAOPTIONS[3];
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK, ASSETCHAINS_LWMAPOS;
extern uint32_t ASSETCHAINS_ALGO, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA;
extern std::string VERUS_CHAINNAME;


arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);

std::set<uint160> ClosedPBaaSChains({});

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {};

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    };
};

bool GetCurrencyDefinition(uint160 chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight)
{
    LOCK(cs_main);
    /*
    if (chainID == ConnectedChains.ThisChain().GetID())
    {
        chainDef = ConnectedChains.ThisChain();
        if (pDefHeight)
        {
            *pDefHeight = 0;
        }
        return true;
    }

    if (!IsVerusActive())
    {
        if (ConnectedChains.NotaryChain().IsValid() && (chainID == ConnectedChains.NotaryChain().chainDefinition.GetID()))
        {
            chainDef = ConnectedChains.NotaryChain().chainDefinition;
            if (pDefHeight)
            {
                *pDefHeight = 0;
            }
            return true;
        }
    }
    */

    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    bool found = false;

    if (!ClosedPBaaSChains.count(chainID)  && GetAddressIndex(CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.ThisChain().GetID(), EVAL_CURRENCY_DEFINITION)), 1, addressIndex))
    {
        for (auto txidx : addressIndex)
        {
            CTransaction tx;
            uint256 blkHash;

            if (GetTransaction(txidx.first.txhash, tx, blkHash))
            {
                std::vector<CCurrencyDefinition> chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(tx);
                for (auto &oneDef : chainDefs)
                {
                    if (found = oneDef.GetID() == chainID)
                    {
                        chainDef = oneDef;
                        // TODO: consider calculating the total contribution
                        // we can get it from either a total of all exports, or the block 1 notarization if there is one
                        if (pDefHeight)
                        {
                            auto it = mapBlockIndex.find(blkHash);
                            *pDefHeight = it != mapBlockIndex.end() ? it->second->GetHeight() : 0;
                        }
                        break;
                    }
                }
            }
            if (found)
            {
                break;
            }
        }
    }
    return found;
}

bool GetCurrencyDefinition(string &name, CCurrencyDefinition &chainDef)
{
    return GetCurrencyDefinition(CCrossChainRPCData::GetID(name), chainDef);
}

// set default peer nodes in the current connected chains
bool SetPeerNodes(const UniValue &nodes)
{
    if (!nodes.isArray() || nodes.size() == 0)
    {
        return false;
    }

    LOCK(ConnectedChains.cs_mergemining);
    ConnectedChains.defaultPeerNodes.clear();

    for (int i = 0; i < nodes.size(); i++)
    {
        CNodeData oneNode(nodes[i]);
        if (oneNode.networkAddress != "")
        {
            ConnectedChains.defaultPeerNodes.push_back(oneNode);
        }
    }
    // set all command line parameters into mapArgs from chain definition
    vector<string> nodeStrs;
    for (auto node : ConnectedChains.defaultPeerNodes)
    {
        nodeStrs.push_back(node.networkAddress);
    }
    if (nodeStrs.size())
    {
        mapMultiArgs["-seednode"] = nodeStrs;
    }
    if (int port = ConnectedChains.GetThisChainPort())
    {
        mapArgs["-port"] = to_string(port);
    }
    return true;
}

// adds the chain definition for this chain and nodes as well
// this also sets up the notarization chain, if there is one
uint256 CurrencyDefHash()
{
    return ::GetHash(ConnectedChains.ThisChain());
}

// adds the chain definition for this chain and nodes as well
// this also sets up the notarization chain, if there is one
bool SetThisChain(const UniValue &chainDefinition)
{
    ConnectedChains.ThisChain() = CCurrencyDefinition(chainDefinition);
    if (!ConnectedChains.ThisChain().IsValid())
    {
        return false;
    }
    SetPeerNodes(find_value(chainDefinition, "nodes"));

    if (!IsVerusActive())
    {
        CCurrencyDefinition &notaryChainDef = ConnectedChains.notaryChain.chainDefinition;
        // we set the notary chain to either Verus or VerusTest
        notaryChainDef.nVersion = PBAAS_VERSION;
        if (PBAAS_TESTMODE)
        {
            // setup Verus test parameters
            notaryChainDef.name = "VRSCTEST";
            notaryChainDef.preAllocation = {std::make_pair(uint160(), 5000000000000000)};
            notaryChainDef.rewards = std::vector<int64_t>({2400000000});
            notaryChainDef.rewardsDecay = std::vector<int64_t>({0});
            Split(GetArg("-ac_halving",""),  ASSETCHAINS_HALVING, 0);
            notaryChainDef.halving = std::vector<int32_t>({(int32_t)(ASSETCHAINS_HALVING[0])});
            notaryChainDef.eraEnd = std::vector<int32_t>({0});
        }
        else
        {
            // first setup Verus parameters
            notaryChainDef.name = "VRSC";
            notaryChainDef.rewards = std::vector<int64_t>({0,38400000000,2400000000});
            notaryChainDef.rewardsDecay = std::vector<int64_t>({100000000,0,0});
            notaryChainDef.halving = std::vector<int32_t>({1,43200,1051920});
            notaryChainDef.eraEnd = std::vector<int32_t>({10080,226080,0});
        }
        notaryChainDef.options = notaryChainDef.OPTION_ID_REFERRALS;
        notaryChainDef.idRegistrationAmount = CCurrencyDefinition::DEFAULT_ID_REGISTRATION_AMOUNT;
        notaryChainDef.idReferralLevels = CCurrencyDefinition::DEFAULT_ID_REFERRAL_LEVELS;
        notaryChainDef.systemID = notaryChainDef.GetID();

        ASSETCHAINS_TIMELOCKGTE = _ASSETCHAINS_TIMELOCKOFF;
        ASSETCHAINS_TIMEUNLOCKFROM = 0;
        ASSETCHAINS_TIMEUNLOCKTO = 0;
    }
    else
    {
        ConnectedChains.ThisChain().options = CCurrencyDefinition::OPTION_ID_REFERRALS;
        ConnectedChains.ThisChain().idRegistrationAmount = CCurrencyDefinition::DEFAULT_ID_REGISTRATION_AMOUNT;
        ConnectedChains.ThisChain().idReferralLevels = CCurrencyDefinition::DEFAULT_ID_REFERRAL_LEVELS;
        ConnectedChains.ThisChain().systemID = ConnectedChains.ThisChain().GetID();   
    }

    memset(ASSETCHAINS_SYMBOL, 0, sizeof(ASSETCHAINS_SYMBOL));
    assert(ConnectedChains.ThisChain().name.size() < sizeof(ASSETCHAINS_SYMBOL));
    strcpy(ASSETCHAINS_SYMBOL, ConnectedChains.ThisChain().name.c_str());

    auto numEras = ConnectedChains.ThisChain().rewards.size();
    ASSETCHAINS_LASTERA = numEras - 1;
    mapArgs["-ac_eras"] = to_string(numEras);

    mapArgs["-ac_end"] = "";
    mapArgs["-ac_reward"] = "";
    mapArgs["-ac_halving"] = "";
    mapArgs["-ac_decay"] = "";
    mapArgs["-ac_options"] = "";

    for (int j = 0; j < ASSETCHAINS_MAX_ERAS; j++)
    {
        if (j > ASSETCHAINS_LASTERA)
        {
            ASSETCHAINS_REWARD[j] = ASSETCHAINS_REWARD[j-1];
            ASSETCHAINS_DECAY[j] = ASSETCHAINS_DECAY[j-1];
            ASSETCHAINS_HALVING[j] = ASSETCHAINS_HALVING[j-1];
            ASSETCHAINS_ENDSUBSIDY[j] = 0;
            ASSETCHAINS_ERAOPTIONS[j] = 0;
        }
        else
        {
            ASSETCHAINS_REWARD[j] = ConnectedChains.ThisChain().rewards[j];
            ASSETCHAINS_DECAY[j] = ConnectedChains.ThisChain().rewardsDecay[j];
            ASSETCHAINS_HALVING[j] = ConnectedChains.ThisChain().halving[j];
            ASSETCHAINS_ENDSUBSIDY[j] = ConnectedChains.ThisChain().eraEnd[j];
            ASSETCHAINS_ERAOPTIONS[j] = ConnectedChains.ThisChain().options;
            if (j == 0)
            {
                mapArgs["-ac_reward"] = to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] = to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] = to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] = to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] = to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
            else
            {
                mapArgs["-ac_reward"] += "," + to_string(ASSETCHAINS_REWARD[j]);
                mapArgs["-ac_decay"] += "," + to_string(ASSETCHAINS_DECAY[j]);
                mapArgs["-ac_halving"] += "," + to_string(ASSETCHAINS_HALVING[j]);
                mapArgs["-ac_end"] += "," + to_string(ASSETCHAINS_ENDSUBSIDY[j]);
                mapArgs["-ac_options"] += "," + to_string(ASSETCHAINS_ERAOPTIONS[j]);
            }
        }
    }

    PBAAS_STARTBLOCK = ConnectedChains.ThisChain().startBlock;
    mapArgs["-startblock"] = to_string(PBAAS_STARTBLOCK);
    PBAAS_ENDBLOCK = ConnectedChains.ThisChain().endBlock;
    mapArgs["-endblock"] = to_string(PBAAS_ENDBLOCK);

    CCurrencyState currencyState = ConnectedChains.GetCurrencyState(0);

    ASSETCHAINS_SUPPLY = currencyState.supply;
    mapArgs["-ac_supply"] = to_string(ASSETCHAINS_SUPPLY);
    return true;
}

void GetCurrencyDefinitions(vector<CCurrencyDefinition> &chains, bool includeExpired)
{
    CCcontract_info CC;
    CCcontract_info *cp;

    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    if (GetAddressIndex(CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.ThisChain().GetID(), EVAL_CURRENCY_DEFINITION)), 1, addressIndex))
    {
        for (auto txidx : addressIndex)
        {
            CTransaction tx;
            uint256 blkHash;
            if (GetTransaction(txidx.first.txhash, tx, blkHash))
            {
                std::vector<CCurrencyDefinition> newChains = CCurrencyDefinition::GetCurrencyDefinitions(tx);
                chains.insert(chains.begin(), newChains.begin(), newChains.end());

                int downTo = chains.size() - newChains.size();
                for (int i = chains.size() - 1; i >= downTo; i--)
                {
                    UniValue valStr(UniValue::VSTR);

                    // TODO: remove/comment this if statement, as it is redundant with the one below
                    if (!valStr.read(chains[i].ToUniValue().write()))
                    {
                        printf("Invalid characters in blockchain definition: %s\n", chains[i].ToUniValue().write().c_str());
                    }

                    // remove after to use less storage
                    if (!valStr.read(chains[i].ToUniValue().write()) || ClosedPBaaSChains.count(chains[i].GetID()) || (!includeExpired && chains[i].endBlock != 0 && chains[i].endBlock < chainActive.Height()))
                    {
                        chains.erase(chains.begin() + i);
                    }
                }
            }
        }
    }
}

bool CConnectedChains::LoadReserveCurrencies()
{
    // we need to get the currency definition for all convertible currencies in addition to Verus
    // and store them in ConnectedChains. then, add currency definition outputs for each
    // currency to the coinbase
    for (auto &curID : thisChain.currencies)
    {
        // get the total amount pre-converted
        CCurrencyDefinition oneDef;
        UniValue params(UniValue::VARR);
        params.push_back(EncodeDestination(CIdentityID(curID)));

        UniValue result;
        try
        {
            result = find_value(RPCCallRoot("getcurrency", params), "result");
        } catch (exception e)
        {
            result = NullUniValue;
        }

        if (!result.isNull())
        {
            oneDef = CCurrencyDefinition(result);
        }

        if (result.isNull() || !oneDef.IsValid())
        {
            // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
            LogPrintf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            printf("Unable to get currency definition for %s\n", EncodeDestination(CIdentityID(curID)).c_str());
            return false;
        }

        {
            LOCK(cs_mergemining);
            reserveCurrencies[curID] = oneDef;
        }
    }
    return true;
}

bool CConnectedChains::GetLastImport(const uint160 &systemID, 
                                     CTransaction &lastImport, 
                                     CPartialTransactionProof &crossChainExport, 
                                     CCrossChainImport &ccImport, 
                                     CCrossChainExport &ccCrossExport)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK2(cs_main, mempool.cs);

    // get last import from the specified chain
    if (!GetAddressUnspent(CCrossChainRPCData::GetConditionID(systemID, EVAL_CROSSCHAIN_IMPORT), 1, unspentOutputs))
    {
        return false;
    }

    // make sure it isn't just a burned transaction to that address, drop out on first match
    const std::pair<CAddressUnspentKey, CAddressUnspentValue> *pOutput = NULL;
    COptCCParams p;
    for (const auto &output : unspentOutputs)
    {
        if (output.second.script.IsPayToCryptoCondition(p) && p.IsValid() && 
            p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
            p.vData.size())
        {
            pOutput = &output;
            break;
        }
    }
    if (!pOutput)
    {
        return false;
    }
    uint256 hashBlk;
    CCurrencyDefinition newCur;

    if (!myGetTransaction(pOutput->first.txhash, lastImport, hashBlk) || 
        !(lastImport.vout.size() &&
         (lastImport.vout.back().scriptPubKey.IsOpReturn() || CCurrencyDefinition::GetCurrencyDefinitions(lastImport).size())))
    {
        return false;
    }
    else if (!lastImport.vout.back().scriptPubKey.IsOpReturn())
    {
        ccCrossExport = CCrossChainExport();
        ccImport = CCrossChainImport(p.vData[0]);
        crossChainExport = CPartialTransactionProof();
    }
    else
    {
        ccImport = CCrossChainImport(p.vData[0]);
        CPartialTransactionProof *pTxProof;
        auto opRetArr = RetrieveOpRetArray(lastImport.vout.back().scriptPubKey);
        if (!opRetArr.size() || 
            opRetArr[0]->objectType != CHAINOBJ_TRANSACTION_PROOF || 
            (pTxProof = &(((CChainObject<CPartialTransactionProof> *)(opRetArr[0]))->object))->txProof.proofSequence.size() < 3)
        {
            DeleteOpRetObjects(opRetArr);
            return false;
        }
        else
        {
            crossChainExport = ((CChainObject<CPartialTransactionProof> *)opRetArr[0])->object;
            DeleteOpRetObjects(opRetArr);
            CTransaction tx;
            if (crossChainExport.GetPartialTransaction(tx).IsNull())
            {
                return false;
            }
            else
            {
                ccCrossExport = CCrossChainExport(tx);
            }
        }
    }
    return true;
}

// returns newly created import transactions to the specified chain/system from exports on this chain specified chain
// nHeight is the height for which we have an MMR that the chainID chain considers confirmed for this chain. it will
// accept proofs of any transactions with that MMR and height.
// Parameters should be validated before this call.
bool CConnectedChains::CreateLatestImports(const CCurrencyDefinition &currencyDef, 
                                           const CTransaction &lastCrossChainImport, 
                                           const CTransaction &importTxTemplate,
                                           const CTransaction &lastConfirmedNotarization,
                                           const CCurrencyValueMap &AvailableTokenInput,
                                           CAmount TotalNativeInput,
                                           std::vector<CTransaction> &newImports)
{
    uint160 systemID = currencyDef.systemID;
    uint160 thisChainID = thisChain.GetID();
    bool isTokenImport = currencyDef.IsToken() && systemID == thisChainID;
    bool isDefinition = false;

    CCurrencyValueMap availableTokenInput(AvailableTokenInput);
    CAmount totalNativeInput(TotalNativeInput);

    // printf("totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());

    CPBaaSNotarization lastConfirmed(lastConfirmedNotarization);
    if ((isTokenImport && chainActive.LastTip() == NULL) ||
        (!isTokenImport && (!lastConfirmed.IsValid() || (chainActive.LastTip() == NULL) || lastConfirmed.notarizationHeight > chainActive.LastTip()->GetHeight())))
    {
        LogPrintf("%s: Invalid lastConfirmedNotarization transaction\n", __func__);
        printf("%s: Invalid lastConfirmedNotarization transaction\n", __func__);
        return false;
    }

    CCrossChainImport lastCCI(lastCrossChainImport);
    if (!lastCCI.IsValid())
    {
        LogPrintf("%s: Invalid lastCrossChainImport transaction\n", __func__);
        printf("%s: Invalid lastCrossChainImport transaction\n", __func__);
        return false;
    }

    std::vector<CBaseChainObject *> chainObjs;

    // either a fully valid import with an export or the first import either in block 1 or the chain definition
    // on the Verus chain
    std::vector<CCurrencyDefinition> chainDefs;
    if (!(lastCrossChainImport.vout.back().scriptPubKey.IsOpReturn() &&
          (chainObjs = RetrieveOpRetArray(lastCrossChainImport.vout.back().scriptPubKey)).size() >= 1 &&
          chainObjs[0]->objectType == CHAINOBJ_TRANSACTION_PROOF) &&
        !(chainObjs.size() == 0 && 
          (chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(lastCrossChainImport)).size()))
    {
        DeleteOpRetObjects(chainObjs);
        LogPrintf("%s: Invalid last import tx\n", __func__);
        printf("%s: Invalid last import tx\n", __func__);
        return false;
    }

    bool isVerusActive = IsVerusActive();

    LOCK2(cs_main, mempool.cs);

    // confirmation of tokens are simultaneous to blocks
    if (isTokenImport)
    {
        lastConfirmed.notarizationHeight = chainActive.Height();
    }

    uint256 lastExportHash;
    CTransaction lastExportTx;
    uint256 blkHash;
    uint32_t blkHeight = 0;
    uint32_t nHeight = chainActive.Height() + 1;

    bool found = false;
    if (chainObjs.size())
    {
        CPartialTransactionProof oneExportProof(((CChainObject<CPartialTransactionProof> *)chainObjs[0])->object);
        if (oneExportProof.txProof.proofSequence.size() == 3)
        {
            lastExportHash = oneExportProof.TransactionHash();
        }

        BlockMap::iterator blkMapIt;
        DeleteOpRetObjects(chainObjs);
        if (!lastExportHash.IsNull() &&
            myGetTransaction(lastExportHash, lastExportTx, blkHash) &&
            (blkMapIt = mapBlockIndex.find(blkHash)) != mapBlockIndex.end() &&
            blkMapIt->second &&
            chainActive.Contains(blkMapIt->second))
        {
            found = true;
            blkHeight = blkMapIt->second->GetHeight();
        }
    }
    else
    {
        std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

        // we cannot get export to a chain that has shut down
        // if the chain definition is spent, a chain is inactive
        // TODO:PBAAS this check needs to be lifted one level out to any loop that processes multiple 
        // import/exports at a time to prevent complexity
        if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(thisChainID, EVAL_CURRENCY_DEFINITION)), 1, unspentOutputs) && unspentOutputs.size())
        {
            CCurrencyDefinition localChainDef;
            CTransaction tx;

            for (auto &txidx : unspentOutputs)
            {
                COptCCParams p;
                uint160 localChainID;
                if (txidx.second.script.IsPayToCryptoCondition(p) && 
                    p.IsValid() && 
                    p.evalCode == EVAL_CURRENCY_DEFINITION && 
                    p.vData[0].size() && 
                    (localChainDef = CCurrencyDefinition(p.vData[0])).IsValid() &&
                    (localChainDef.GetID()) == currencyDef.GetID())
                {
                    if (myGetTransaction(txidx.first.txhash, tx, blkHash))
                    {
                        CCrossChainExport ccx(tx);
                        if (ccx.IsValid() && (isVerusActive || tx.IsCoinBase()))
                        {
                            found = true;
                            isDefinition = true;
                            lastExportHash = txidx.first.txhash;
                            blkHeight = txidx.second.blockHeight;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!found)
    {
        //LogPrintf("%s: No export thread found\n", __func__);
        //printf("%s: No export thread found\n", __func__);
        return false;
    }

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // get all export transactions including and since this one up to the confirmed height
    if (blkHeight <= lastConfirmed.notarizationHeight && 
        GetAddressIndex(CCrossChainRPCData::GetConditionID(systemID, EVAL_CROSSCHAIN_EXPORT), 1, addressIndex, blkHeight, lastConfirmed.notarizationHeight))
    {
        // find this export, then check the next one that spends it and use it if also valid
        found = false;
        uint256 lastHash = lastExportHash;

        // indexed by input hash
        std::map<uint256, std::pair<CAddressIndexKey, CTransaction>> validExports;

        // validate, order, and relate them with their inputs
        for (auto &utxo : addressIndex)
        {
            // if current tx spends lastHash, then we have our next valid transaction to create an import with
            CTransaction tx, inputtx;
            uint256 blkHash1, blkHash2;
            BlockMap::iterator blkIt;
            CCrossChainExport ccx;
            COptCCParams p;
            if (!utxo.first.spending &&
                (utxo.first.txhash != lastExportHash) &&
                myGetTransaction(utxo.first.txhash, tx, blkHash1) &&
                (ccx = CCrossChainExport(tx)).IsValid() &&
                ccx.numInputs &&
                (!tx.IsCoinBase() && 
                tx.vin.size() && 
                myGetTransaction(tx.vin[0].prevout.hash, inputtx, blkHash2)) &&
                inputtx.vout[tx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && 
                p.IsValid() && 
                p.evalCode == EVAL_CROSSCHAIN_EXPORT)
            {
                validExports.insert(make_pair(tx.vin[0].prevout.hash, make_pair(utxo.first, tx)));
            }
            /*
            else
            {
                bool doNext = true;
                printf("!utxo.first.spending: %s\n", (doNext = !utxo.first.spending) ? "true" : "false");
                printf("!(utxo.first.txhash == lastExportHash): %s\n", (doNext = !(utxo.first.txhash == lastExportHash)) ? "true" : "false");
                printf("myGetTransaction(utxo.first.txhash, tx, blkHash1): %s\n", (doNext = myGetTransaction(utxo.first.txhash, tx, blkHash1)) ? "true" : "false");
                if (doNext)
                    printf("(ccx = CCrossChainExport(tx)).IsValid(): %s\n", (doNext = (ccx = CCrossChainExport(tx)).IsValid()) ? "true" : "false");
                if (doNext)
                    printf("ccx.numInputs: %d\n", (doNext = ccx.numInputs != 0) ? ccx.numInputs : 0);
                if (doNext)
                    printf("!tx.IsCoinBase(): %s\n", (doNext = !tx.IsCoinBase()) ? "true" : "false");
                if (doNext)
                    printf("tx.vin.size(): %lu\n", (doNext = tx.vin.size() != 0) ? tx.vin.size() : 0l);
                if (doNext)
                    printf("myGetTransaction(tx.vin[0].prevout.hash, inputtx, blkHash2)): %s\n", (doNext = myGetTransaction(tx.vin[0].prevout.hash, inputtx, blkHash2)) ? "true" : "false");
                if (doNext)
                    printf("inputtx.vout[tx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p): %s\n", (doNext = inputtx.vout[tx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p)) ? "true" : "false");
                if (doNext)
                    printf("p.IsValid(): %s\n", (doNext = p.IsValid()) ? "true" : "false");
                if (doNext)
                    printf("p.evalCode == EVAL_CROSSCHAIN_EXPORT: %s\n", (doNext = p.evalCode == EVAL_CROSSCHAIN_EXPORT) ? "true" : "false");
            }
            */
        }

        CTransaction lastImport(lastCrossChainImport);

        for (auto aixIt = validExports.find(lastExportHash); 
             aixIt != validExports.end(); 
             aixIt = validExports.find(lastExportHash))
        {
            // One pass - create an import transaction that spends the last import transaction from a confirmed export transaction that spends the last one of those
            // 1. Creates preconvert outputs that spend from the initial supply, which comes from the import transaction thread without fees
            // 2. Creates reserve outputs for unconverted imports
            // 3. Creates reserveExchange transactions requesting conversion at market for convert transfers
            // 4. Creates reserveTransfer outputs for outputs with the SEND_BACK flag set, unless they are under 5x the normal network fee
            // 5. Creates a pass-through EVAL_CROSSCHAIN_IMPORT output with the remainder of the non-preconverted coins
            // then signs the transaction considers it the latest import and the new export the latest export and
            // loops until there are no more confirmed, consecutive, valid export transactions to export

            // aixIt has an input from the export thread of last transaction, an optional deposit to the reserve, and an opret of all outputs + 1 fee
            assert(aixIt->second.second.vout.back().scriptPubKey.IsOpReturn());

            CMutableTransaction newImportTx(importTxTemplate);

            int ccxOutputNum = 0;
            CCrossChainExport ccx(aixIt->second.second, &ccxOutputNum);

            int32_t importOutNum = 0;
            lastCCI = CCrossChainImport(lastImport, &importOutNum);
            if (!lastCCI.IsValid() || !ccx.IsValid())
            {
                LogPrintf("%s: POSSIBLE CORRUPTION bad import/export data in transaction %s (import) or %s (export)\n", __func__, lastImport.GetHash().GetHex().c_str(), aixIt->first.GetHex().c_str());
                printf("%s: POSSIBLE CORRUPTION bad import/export data transaction %s (import) or %s (export)\n", __func__, lastImport.GetHash().GetHex().c_str(), aixIt->first.GetHex().c_str());
                return false;
            }

            // if no prepared input, make one
            if (!newImportTx.vin.size())
            {
                //printf("adding input: %s, %d\n", lastImport.GetHash().GetHex().c_str(), importOutNum);
                newImportTx.vin.push_back(CTxIn(lastImport.GetHash(), importOutNum));
            }

            newImportTx.vout.push_back(CTxOut()); // placeholder for the first output

            CCcontract_info CC;
            CCcontract_info *cp;
            CPubKey pk;

            CCurrencyValueMap availableReserveFees = ccx.totalFees;
            CCurrencyValueMap exportFees = ccx.CalculateExportFee();
            CCurrencyValueMap importFees = ccx.CalculateImportFee();
            CAmount feesOut = 0;

            CCoinbaseCurrencyState currencyState;
            if (isTokenImport)
            {
                // spend export finalization if there is one
                int32_t finalizeOutNum = -1;
                uint32_t eCode;
                CTransactionFinalization ccxFinalization = CTransactionFinalization(aixIt->second.second, &eCode, &finalizeOutNum);
                if (finalizeOutNum != -1)
                {
                    newImportTx.vin.push_back(CTxIn(aixIt->second.second.GetHash(), finalizeOutNum));
                }

                if (!NewImportNotarization(currencyDef, nHeight, lastImport, aixIt->second.first.blockHeight, aixIt->second.second, newImportTx, currencyState))
                {
                    LogPrintf("%s: cannot create notarization for transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                    printf("%s:  cannot create notarization for transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                    return false;
                }
            }
            else
            {
                // TODO: confirm that for non-tokens, we don't have to calculate initial state
                currencyState = lastConfirmed.currencyState;
            }

            CReserveTransactionDescriptor rtxd;
            std::vector<CBaseChainObject *> exportOutputs = RetrieveOpRetArray(aixIt->second.second.vout.back().scriptPubKey);

            if (!currencyState.IsValid() ||
                !rtxd.AddReserveTransferImportOutputs(thisChainID, currencyDef, currencyState, exportOutputs, newImportTx.vout))
            {
                LogPrintf("%s: POSSIBLE CORRUPTION bad export opret in transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                printf("%s: POSSIBLE CORRUPTION bad export opret in transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                // free the memory
                DeleteOpRetObjects(exportOutputs);
                return false;
            }

            // free the memory
            DeleteOpRetObjects(exportOutputs);

            // emit a crosschain import output as summary
            cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
            pk = CPubKey(ParseHex(CC.CChexstr));

            CCurrencyValueMap leftoverCurrency = ((availableTokenInput - rtxd.ReserveInputMap()) +
                                                  CCurrencyValueMap(std::vector<uint160>({systemID}), std::vector<CAmount>({totalNativeInput - rtxd.nativeIn})));

            /*
            printf("%s: leftoverCurrency:\n%s\nReserveInputMap():\n%s\nrtxd.nativeIn:\n%s\nconversionfees:\n%s\ntxreservefees:\n%s\ntxnativefees:\n%ld\nccx.totalfees:\n%s\nexportfees:\n%s\nccx.totalFees - exportFees:\n%s\n\n", 
                        __func__, 
                        leftoverCurrency.ToUniValue().write().c_str(),
                        rtxd.ReserveInputMap().ToUniValue().write().c_str(),
                        ValueFromAmount(rtxd.nativeIn).write().c_str(),
                        (rtxd.ReserveConversionFeesMap() + CCurrencyValueMap(std::vector<uint160>({thisChainID}), std::vector<CAmount>({rtxd.nativeConversionFees}))).ToUniValue().write().c_str(),
                        rtxd.ReserveFees().ToUniValue().write().c_str(),
                        rtxd.NativeFees(),
                        ccx.totalFees.ToUniValue().write().c_str(),
                        exportFees.ToUniValue().write().c_str(),
                        (ccx.totalFees - exportFees).ToUniValue().write().c_str());
            */

            if (leftoverCurrency.HasNegative())
            {
                LogPrintf("%s: ERROR - fees do not match. leftoverCurrency:\n%s\nReserveInputMap():\n%s\nrtxd.nativeIn:\n%s\nconversionfees:\n%s\ntxreservefees:\n%s\ntxnativefees:\n%ld\nccx.totalfees:\n%s\nexportfees:\n%s\nccx.totalFees - exportFees:\n%s\n\n", 
                        __func__, 
                        leftoverCurrency.ToUniValue().write().c_str(),
                        rtxd.ReserveInputMap().ToUniValue().write().c_str(),
                        ValueFromAmount(rtxd.nativeIn).write().c_str(),
                        (rtxd.ReserveConversionFeesMap() + CCurrencyValueMap(std::vector<uint160>({thisChainID}), std::vector<CAmount>({rtxd.nativeConversionFees}))).ToUniValue().write().c_str(),
                        rtxd.ReserveFees().ToUniValue().write().c_str(),
                        rtxd.NativeFees(),
                        ccx.totalFees.ToUniValue().write().c_str(),
                        exportFees.ToUniValue().write().c_str(),
                        (ccx.totalFees - exportFees).ToUniValue().write().c_str());
                return false;
            }

            std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(ccx.systemID, EVAL_CROSSCHAIN_IMPORT)))});
            std::vector<CTxDestination> dests;

            if (currencyDef.proofProtocol == CCurrencyDefinition::PROOF_PBAASMMR ||
                currencyDef.proofProtocol == CCurrencyDefinition::PROOF_CHAINID)
            {
                dests = std::vector<CTxDestination>({pk});
            }
            else
            {
                LogPrintf("%s: ERROR - invalid proof protocol\n", __func__);
                printf("%s: ERROR - invalid proof protocol\n", __func__);
                return false;
            }

            CAmount nativeOutConverted = 0;
            for (auto &oneNativeConversion : rtxd.NativeOutConvertedMap().valueMap)
            {
                nativeOutConverted += oneNativeConversion.second;
            }

            /*
            printf("DEBUGOUT: nativeOutConverted: %ld, rtxd.ReserveOutConvertedMap():%s\n", nativeOutConverted, rtxd.ReserveOutConvertedMap().ToUniValue().write().c_str());
            printf("totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());
            printf("rtxd.ReserveInputMap(): %s, ccx.totalAmounts: %s\n", rtxd.ReserveInputMap().ToUniValue().write().c_str(), ccx.totalAmounts.ToUniValue().write().c_str());
            printf("leftoverCurrency: %s\n", leftoverCurrency.ToUniValue().write().c_str());
            */

            // breakout native from leftover currency
            totalNativeInput = leftoverCurrency.valueMap[systemID];
            leftoverCurrency.valueMap.erase(systemID);

            /*
            printf("DEBUGOUT: totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());
            printf("DEBUGOUT: rtxd.nativeIn: %ld, rtxd.ReserveInputMap():%s\n", rtxd.nativeIn, rtxd.ReserveInputMap().ToUniValue().write().c_str());
            */

            CCrossChainImport cci = CCrossChainImport(ccx.systemID, 
                                                      rtxd.ReserveOutConvertedMap() + 
                                                      CCurrencyValueMap(std::vector<uint160>({systemID}), std::vector<CAmount>(nativeOutConverted)),
                                                      leftoverCurrency.CanonicalMap());

            newImportTx.vout[0] = CTxOut(totalNativeInput, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci), &indexDests));

            //printf("totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());
            if (totalNativeInput < 0 || (availableTokenInput - rtxd.ReserveInputMap()).HasNegative())
            {
                LogPrintf("%s: ERROR - importing more currency than available for %s\n", __func__, currencyDef.name.c_str());
                LogPrintf("totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());
                printf("%s: ERROR - importing more currency than available for %s\n", __func__, currencyDef.name.c_str());
                printf("totalNativeInput: %ld, availableTokenInput:%s\n", totalNativeInput, availableTokenInput.ToUniValue().write().c_str());
                return false;
            }

            availableTokenInput = leftoverCurrency;

            // add a proof of the export transaction at the notarization height
            CBlock block;
            if (!ReadBlockFromDisk(block, chainActive[aixIt->second.first.blockHeight], Params().GetConsensus(), false))
            {
                LogPrintf("%s: POSSIBLE CORRUPTION cannot read block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                printf("%s: POSSIBLE CORRUPTION cannot read block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                return false;
            }

            // prove ccx input 0, export output, and opret
            std::vector<std::pair<int16_t, int16_t>> parts({{CTransactionHeader::TX_HEADER, (int16_t)0},
                                                            {CTransactionHeader::TX_PREVOUTSEQ, (int16_t)0},
                                                            {CTransactionHeader::TX_OUTPUT, ccxOutputNum},
                                                            {CTransactionHeader::TX_OUTPUT, (int16_t)(aixIt->second.second.vout.size() - 1)}});

            // prove our transaction up to the MMR root of the last transaction
            CPartialTransactionProof exportProof = block.GetPartialTransactionProof(aixIt->second.second, aixIt->second.first.txindex, parts);
            if (!exportProof.components.size())
            {
                LogPrintf("%s: could not create partial transaction proof in block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                printf("%s: could not create partial transaction proof in block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                return false;
            }
            exportProof.txProof << block.MMRProofBridge();

            // TODO: don't include chain MMR proof for exports from the same chain
            ChainMerkleMountainView mmv(chainActive.GetMMR(), lastConfirmed.notarizationHeight);
            mmv.GetProof(exportProof.txProof, aixIt->second.first.blockHeight);

            CChainObject<CPartialTransactionProof> exportXProof(CHAINOBJ_TRANSACTION_PROOF, exportProof);

            CTransaction checkTx;

            uint256 checkTxID = exportProof.CheckPartialTransaction(checkTx);
            CMMRProof blockProof;
            chainActive.GetBlockProof(mmv, blockProof, aixIt->second.first.blockHeight);
            if (checkTxID != mmv.GetRoot())
            {
                /*
                printf("CTransactionHeaderCheck: %s\n\n", exportProof.components[0].CheckProof().GetHex().c_str());
                printf("CTransactionProof\n%s\n", exportProof.txProof.ToUniValue().write(1,2).c_str());
                printf("CTransactionProofCheck: %s\n\n", checkTxID.GetHex().c_str());
                printf("CBlockProof\n%s\n", blockProof.ToUniValue().write(1,2).c_str());
                printf("CBlockProofCheck: %s\n\n", blockProof.CheckProof(chainActive[aixIt->second.first.blockHeight]->GetBlockHash()).GetHex().c_str());
                printf("CBlockHash: %s\n\n", block.GetHash().GetHex().c_str());
                printf("CBlockMMRRoot: %s\n\n", block.GetBlockMMRRoot().GetHex().c_str());
                printf("CBlockMMViewRoot: %s\n\n", BlockMMView(block.GetBlockMMRTree()).GetRoot().GetHex().c_str());
                for (auto &oneNode : mmv.GetPeaks())
                {
                    printf("oneMerklePeakNode: %s:%s\n", oneNode.hash.GetHex().c_str(), oneNode.power.GetHex().c_str());
                }
                printf("MMVRoot: %s\n\n", mmv.GetRoot().GetHex().c_str());
                for (auto &oneTx : block.vtx)
                {
                    printf("oneTxRoot: %s\n", TransactionMMView(oneTx.GetTransactionMMR()).GetRoot().GetHex().c_str());
                }
                */

                printf("%s: invalid partial transaction proof, hash is\n%s, should be\n%s\n", __func__, checkTxID.GetHex().c_str(), mmv.GetRoot().GetHex().c_str());
                LogPrintf("%s: invalid partial transaction proof, hash is\n%s, should be\n%s\n", __func__, checkTxID.GetHex().c_str(), mmv.GetRoot().GetHex().c_str());
                return false;
            }
            uint256 lastProof = exportProof.components[0].CheckProof();
            for (int i = 1; i < exportProof.components.size(); i++)
            {
                if (lastProof != exportProof.components[i].CheckProof())
                {
                    printf("%s: error in new proof for component %d\n", __func__, i);
                }
            }

            // add the opret with the transaction and proof
            newImportTx.vout.push_back(CTxOut(0, StoreOpRetArray(std::vector<CBaseChainObject *>({&exportXProof}))));

            // we now have an Import transaction for the chainID chain, it is the latest, and the export we used is now the latest as well
            // work our way forward
            lastImport = newImportTx;
            newImports.push_back(lastImport);
            lastExportHash = aixIt->second.first.txhash;
            //printf("loop again with lastImport.GetHash(): %s, lastExportHash %s\n", lastImport.GetHash().GetHex().c_str(), lastExportHash.GetHex().c_str());
        }
    }
    return true;
}

void CheckPBaaSAPIsValid()
{
    //printf("Solution version running: %d\n\n", CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()));
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "PBaaS not activated on blockchain.");
    }
}

void CheckIdentityAPIsValid()
{
    if (!chainActive.LastTip() ||
        CConstVerusSolutionVector::activationHeight.ActiveVersion(chainActive.LastTip()->GetHeight()) < CConstVerusSolutionVector::activationHeight.ACTIVATE_IDENTITY)
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Identity APIs not activated on blockchain.");
    }
}

uint160 ValidateCurrencyName(std::string currencyStr, CCurrencyDefinition *pCurrencyDef=NULL)
{
    std::string extraName;
    uint160 retVal;
    currencyStr = TrimSpaces(currencyStr);
    if (!currencyStr.size())
    {
        return retVal;
    }
    ParseSubNames(currencyStr, extraName, true);
    if (currencyStr.back() == '@' || (extraName != "" && boost::to_lower_copy(extraName) != boost::to_lower_copy(VERUS_CHAINNAME)))
    {
        return retVal;
    }
    if (CCurrencyDefinition::GetID(currencyStr) == ConnectedChains.ThisChain().GetID())
    {
        return ConnectedChains.ThisChain().GetID();
    }
    CTxDestination currencyDest = DecodeDestination(currencyStr);
    if (currencyDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        currencyDest = DecodeDestination(currencyStr + "@");
    }
    if (currencyDest.which() != COptCCParams::ADDRTYPE_INVALID)
    {
        // make sure there is such a currency defined on this chain
        CCurrencyDefinition currencyDef;
        if (GetCurrencyDefinition(GetDestinationID(currencyDest), currencyDef))
        {
            retVal = currencyDef.GetID();
        }
        if (pCurrencyDef)
        {
            *pCurrencyDef = currencyDef;
        }
    }
    return retVal;
}

uint160 GetChainIDFromParam(const UniValue &param, CCurrencyDefinition *pCurrencyDef=NULL)
{
    return ValidateCurrencyName(uni_get_str(param), pCurrencyDef);
}

UniValue getcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getcurrency \"chainname\"\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "    \"version\" : \"n\",             (int) version of this chain definition\n"
            "    \"name\" : \"string\",           (string) name or symbol of the chain, same as passed\n"
            "    \"address\" : \"string\",        (string) cryptocurrency address to send fee and non-converted premine\n"
            "    \"currencyid\" : \"i-address\",  (string) string that represents the currency ID, same as the ID behind the currency\n"
            "    \"premine\" : \"n\",             (int) amount of currency paid out to the premine address in block #1, may be smart distribution\n"
            "    \"convertible\" : \"xxxx\"       (bool) if this currency is a fractional reserve currency of Verus\n"
            "    \"startblock\" : \"n\",          (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : \"n\",            (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"eras\" : \"[obj, ...]\",       (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",     (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",      (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",    (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",     (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\", (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",  (objectarray, optional) up to 8 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeidentity\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : \"n\", (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "    \"bestnotarization\" : {\n"
            "     }\n"
            "    \"besttxid\" : \"txid\"\n"
            "     }\n"
            "    \"confirmednotarization\" : {\n"
            "     }\n"
            "    \"confirmedtxid\" : \"txid\"\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrency", "\"chainname\"")
            + HelpExampleRpc("getcurrency", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();
    LOCK2(cs_main, mempool.cs);

    UniValue ret(UniValue::VOBJ);

    CCurrencyDefinition chainDef;
    uint160 chainID = GetChainIDFromParam(params[0], &chainDef);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    if (chainDef.IsValid())
    {
        CChainNotarizationData cnd;
        GetNotarizationData(chainID, IsVerusActive() ? EVAL_ACCEPTEDNOTARIZATION : EVAL_EARNEDNOTARIZATION, cnd);

        ret = chainDef.ToUniValue();

        std::vector<CNodeData> vNNodes;
        int32_t confirmedHeight = -1, bestHeight = -1;

        if (cnd.forks.size())
        {
            // get all nodes from notarizations of the best chain into a vector
            for (auto &oneNot : cnd.forks[cnd.bestChain])
            {
                vNNodes.insert(vNNodes.end(), cnd.vtx[oneNot].second.nodes.begin(), cnd.vtx[oneNot].second.nodes.end());
            }

            confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
            bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;

            // shuffle and take 8 nodes,
            // up to two of which will be from the last confirmed notarization if present
            std::random_shuffle(vNNodes.begin(), vNNodes.end());
            int numConfirmedNodes = cnd.lastConfirmed == -1 ? 0 : cnd.vtx[cnd.lastConfirmed].second.nodes.size();
            if (vNNodes.size() > (8 - numConfirmedNodes))
            {
                vNNodes.resize(8);
            }
            if (numConfirmedNodes)
            {
                vNNodes.insert(vNNodes.begin(), cnd.vtx[cnd.lastConfirmed].second.nodes.begin(), cnd.vtx[cnd.lastConfirmed].second.nodes.end());
            }
            if (vNNodes.size())
            {
                UniValue nodeArr(UniValue::VARR);
                for (auto &oneNode : vNNodes)
                {
                    nodeArr.push_back(oneNode.ToUniValue());
                }
                ret.push_back(Pair("nodes", nodeArr));
            }
        }

        if (!chainDef.IsToken())
        {
            ret.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
            if (confirmedHeight != -1)
            {
                ret.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.GetHex().c_str()));
                ret.push_back(Pair("lastconfirmedcurrencystate", cnd.vtx[cnd.lastConfirmed].second.currencyState.ToUniValue()));
            }
        }
        ret.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
        if (bestHeight != -1)
        {
            ret.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.GetHex().c_str()));
            ret.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue getpendingtransfers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "getpendingtransfers \"chainname\"\n"
            "\nReturns all pending transfers for a particular chain that have not yet been aggregated into an export\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getpendingtransfers", "\"chainname\"")
            + HelpExampleRpc("getpendingtransfers", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t defHeight;

    LOCK(cs_main);

    if ((IsVerusActive() && GetCurrencyDefinition(chainID, chainDef, &defHeight)) || (chainDef = ConnectedChains.NotaryChain().chainDefinition).GetID() == chainID)
    {
        // look for new exports
        multimap<uint160, pair<CInputDescriptor, CReserveTransfer>> inputDescriptors;

        if (GetUnspentChainTransfers(inputDescriptors, chainID))
        {
            UniValue ret(UniValue::VARR);

            for (auto &desc : inputDescriptors)
            {
                UniValue oneExport(UniValue::VOBJ);

                oneExport.push_back(Pair("currencyid", EncodeDestination(CIdentityID(desc.first))));
                oneExport.push_back(Pair("txid", desc.second.first.txIn.prevout.hash.GetHex()));
                oneExport.push_back(Pair("n", (int32_t)desc.second.first.txIn.prevout.n));
                oneExport.push_back(Pair("valueout", desc.second.first.nValue));
                oneExport.push_back(Pair("reservetransfer", desc.second.second.ToUniValue()));
                ret.push_back(oneExport);
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized chain name or chain ID");
    }
    
    return NullUniValue;
}

UniValue getexports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getexports \"chainname\"\n"
            "\nReturns all pending export transfers that are not yet provable with confirmed notarizations.\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getexports", "\"chainname\"")
            + HelpExampleRpc("getexports", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    LOCK2(cs_main, mempool.cs);

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t defHeight;

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CChainNotarizationData cnd;
        if (GetNotarizationData(chainID, IsVerusActive() ? EVAL_ACCEPTEDNOTARIZATION : EVAL_EARNEDNOTARIZATION, cnd))
        {
            // get all export transactions including and since this one up to the confirmed height
            if (GetAddressIndex(CCrossChainRPCData::GetConditionID(chainID, EVAL_CROSSCHAIN_EXPORT), 
                                1, addressIndex, cnd.IsConfirmed() ? cnd.vtx[cnd.lastConfirmed].second.crossHeight : defHeight))
            {
                UniValue ret(UniValue::VARR);

                for (auto &idx : addressIndex)
                {
                    uint256 blkHash;
                    CTransaction exportTx;
                    if (!idx.first.spending && myGetTransaction(idx.first.txhash, exportTx, blkHash))
                    {
                        std::vector<CBaseChainObject *> opretTransfers;
                        CCrossChainExport ccx;
                        if ((ccx = CCrossChainExport(exportTx)).IsValid() && exportTx.vout.back().scriptPubKey.IsOpReturn())
                        {
                            UniValue oneExport(UniValue::VOBJ);
                            UniValue transferArray(UniValue::VARR);
                            opretTransfers = RetrieveOpRetArray(exportTx.vout.back().scriptPubKey);
                            oneExport.push_back(Pair("blockheight", idx.first.blockHeight));
                            oneExport.push_back(Pair("exportid", idx.first.txhash.GetHex()));
                            oneExport.push_back(Pair("description", ccx.ToUniValue()));
                            for (auto oneTransfer : opretTransfers)
                            {
                                if (oneTransfer->objectType == CHAINOBJ_RESERVETRANSFER)
                                {
                                    transferArray.push_back(((CChainObject<CReserveTransfer> *)oneTransfer)->object.ToUniValue());
                                }
                            }
                            DeleteOpRetObjects(opretTransfers);
                            oneExport.push_back(Pair("transfers", transferArray));
                            ret.push_back(oneExport);
                        }
                    }
                }
                if (ret.size())
                {
                    return ret;
                }
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized chain name or chain ID");
    }
    
    return NullUniValue;
}

UniValue getimports(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getimports \"chainname\"\n"
            "\nReturns all imports from a specific chain.\n"

            "\nArguments\n"
            "1. \"chainname\"                     (string, optional) name of the chain to look for. no parameter returns current chain in daemon.\n"

            "\nResult:\n"
            "  {\n"
            "  }\n"

            "\nExamples:\n"
            + HelpExampleCli("getimports", "\"chainname\"")
            + HelpExampleRpc("getimports", "\"chainname\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CCurrencyDefinition chainDef;
    int32_t defHeight;

    LOCK(cs_main);

    if (GetCurrencyDefinition(chainID, chainDef, &defHeight))
    {
        // which transaction are we in this block?
        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        CBlockIndex *pIndex;

        CChainNotarizationData cnd;
        // get all import transactions including and since this one up to the confirmed height
        if (GetAddressIndex(CCrossChainRPCData::GetConditionID(chainID, EVAL_CROSSCHAIN_IMPORT), 1, addressIndex))
        {
            UniValue ret(UniValue::VARR);

            for (auto &idx : addressIndex)
            {
                uint256 blkHash;
                CTransaction importTx;
                if (!idx.first.spending && myGetTransaction(idx.first.txhash, importTx, blkHash))
                {
                    CCrossChainImport cci;
                    if ((cci = CCrossChainImport(importTx)).IsValid() && importTx.vout.back().scriptPubKey.IsOpReturn())
                    {
                        std::vector<CBaseChainObject *> opretImports;
                        CTransaction exportTx;
                        CCrossChainExport ccx;

                        opretImports = RetrieveOpRetArray(importTx.vout.back().scriptPubKey);

                        if (opretImports.size() >= 1 && 
                            opretImports[0]->objectType == CHAINOBJ_TRANSACTION_PROOF && 
                            !((CChainObject<CPartialTransactionProof> *)opretImports[0])->object.GetPartialTransaction(exportTx).IsNull() &&
                            (ccx = CCrossChainExport(exportTx)).IsValid() && 
                            ccx.numInputs &&
                            exportTx.vout.size() && 
                            exportTx.vout.back().scriptPubKey.IsOpReturn())
                        {
                            std::vector<CBaseChainObject *> opretTransfers;

                            UniValue oneImport(UniValue::VOBJ);
                            UniValue transferArray(UniValue::VARR);
                            opretTransfers = RetrieveOpRetArray(exportTx.vout.back().scriptPubKey);
                            oneImport.push_back(Pair("blockheight", idx.first.blockHeight));
                            oneImport.push_back(Pair("importid", idx.first.txhash.GetHex()));
                            oneImport.push_back(Pair("description", cci.ToUniValue()));
                            for (auto oneTransfer : opretTransfers)
                            {
                                if (oneTransfer->objectType == CHAINOBJ_RESERVETRANSFER)
                                {
                                    transferArray.push_back(((CChainObject<CReserveTransfer> *)oneTransfer)->object.ToUniValue());
                                }
                            }
                            DeleteOpRetObjects(opretTransfers);
                            oneImport.push_back(Pair("transfers", transferArray));
                            ret.push_back(oneImport);
                        }
                        DeleteOpRetObjects(opretImports);
                    }
                }
            }
            if (ret.size())
            {
                return ret;
            }
        }
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unrecognized chain name or chain ID");
    }
    return NullUniValue;
}

UniValue listcurrencies(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "listcurrencies (includeexpired)\n"
            "\nReturns a complete definition for any given chain if it is registered on the blockchain. If the chain requested\n"
            "\nis NULL, chain definition of the current chain is returned.\n"

            "\nArguments\n"
            "1. \"includeexpired\"                (bool, optional) if true, include chains that are no longer active\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"version\" : \"n\",             (int) version of this chain definition\n"
            "    \"name\" : \"string\",           (string) name or symbol of the chain, same as passed\n"
            "    \"address\" : \"string\",        (string) cryptocurrency address to send fee and non-converted premine\n"
            "    \"currencyid\" : \"hex-string\", (string) i-address that represents the chain ID, same as the ID that launched the chain\n"
            "    \"premine\" : \"n\",             (int) amount of currency paid out to the premine address in block #1, may be smart distribution\n"
            "    \"convertible\" : \"xxxx\"       (bool) if this currency is a fractional reserve currency of Verus\n"
            "    \"startblock\" : \"n\",          (int) block # on this chain, which must be notarized into block one of the chain\n"
            "    \"endblock\" : \"n\",            (int) block # after which, this chain's useful life is considered to be over\n"
            "    \"eras\" : \"[obj, ...]\",       (objarray) different chain phases of rewards and convertibility\n"
            "    {\n"
            "      \"reward\" : \"[n, ...]\",     (int) reward start for each era in native coin\n"
            "      \"decay\" : \"[n, ...]\",      (int) exponential or linear decay of rewards during each era\n"
            "      \"halving\" : \"[n, ...]\",    (int) blocks between halvings during each era\n"
            "      \"eraend\" : \"[n, ...]\",     (int) block marking the end of each era\n"
            "      \"eraoptions\" : \"[n, ...]\", (int) options (reserved)\n"
            "    }\n"
            "    \"nodes\"      : \"[obj, ..]\",  (objectarray, optional) up to 2 nodes that can be used to connect to the blockchain"
            "      [{\n"
            "         \"nodeaddress\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "         \"paymentaddress\" : \"n\", (int,     optional) rewards payment address\n"
            "       }, .. ]\n"
            "  }, ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listcurrencies", "true")
            + HelpExampleRpc("listcurrencies", "true")
        );
    }

    CheckPBaaSAPIsValid();

    UniValue ret(UniValue::VARR);

    bool includeExpired = params[0].isBool() ? params[0].get_bool() : false;

    vector<CCurrencyDefinition> chains;
    {
        LOCK2(cs_main, mempool.cs);
        GetCurrencyDefinitions(chains, includeExpired);
    }

    for (auto def : chains)
    {
        LOCK2(cs_main, mempool.cs);

        UniValue oneChain(UniValue::VOBJ);
        oneChain.push_back(Pair("currencydefinition", def.ToUniValue()));

        CChainNotarizationData cnd;
        GetNotarizationData(def.GetID(), IsVerusActive() ? EVAL_ACCEPTEDNOTARIZATION : EVAL_EARNEDNOTARIZATION, cnd);

        int32_t confirmedHeight = -1, bestHeight = -1;
        confirmedHeight = cnd.vtx.size() && cnd.lastConfirmed != -1 ? cnd.vtx[cnd.lastConfirmed].second.notarizationHeight : -1;
        bestHeight = cnd.vtx.size() && cnd.bestChain != -1 ? cnd.vtx[cnd.forks[cnd.bestChain].back()].second.notarizationHeight : -1;

        if (!def.IsToken())
        {
            oneChain.push_back(Pair("lastconfirmedheight", confirmedHeight == -1 ? 0 : confirmedHeight));
            if (confirmedHeight != -1)
            {
                oneChain.push_back(Pair("lastconfirmedtxid", cnd.vtx[cnd.lastConfirmed].first.GetHex().c_str()));
                oneChain.push_back(Pair("lastconfirmedcurrencystate", cnd.vtx[cnd.lastConfirmed].second.currencyState.ToUniValue()));
            }
        }
        oneChain.push_back(Pair("bestheight", bestHeight == -1 ? 0 : bestHeight));
        if (bestHeight != -1)
        {
            oneChain.push_back(Pair("besttxid", cnd.vtx[cnd.forks[cnd.bestChain].back()].first.GetHex().c_str()));
            oneChain.push_back(Pair("bestcurrencystate", cnd.vtx[cnd.forks[cnd.bestChain].back()].second.currencyState.ToUniValue()));
        }
        ret.push_back(oneChain);
    }
    return ret;
}

// returns all chain transfer outputs, both spent and unspent between a specific start and end block with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that system are returned
bool GetChainTransfers(multimap<uint160, pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter, int start, int end, uint32_t flags)
{
    if (!flags)
    {
        flags = CReserveTransfer::VALID;
    }
    bool nofilter = chainFilter.IsNull();

    // which transaction are we in this block?
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;
    std::set<uint256> countedTxes;                  // don't count twice

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressIndex(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER), 1, addressIndex, start, end))
    {
        return false;
    }
    else
    {
        for (auto it = addressIndex.begin(); it != addressIndex.end(); it++)
        {
            CTransaction ntx;
            uint256 blkHash;

            // each tx gets counted once
            if (countedTxes.count(it->first.txhash))
            {
                continue;
            }
            countedTxes.insert(it->first.txhash);

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                /*
                uint256 hashBlk;
                UniValue univTx(UniValue::VOBJ);
                TxToUniv(ntx, hashBlk, univTx);
                printf("tx: %s\n", univTx.write(1,2).c_str());
                */
                for (int i = 0; i < ntx.vout.size(); i++)
                {
                    // if this is a transfer output, optionally to this chain, add it to the input vector
                    /*
                    std::vector<CTxDestination> dests;
                    int numRequired = 0;
                    txnouttype typeRet;
                    if (ExtractDestinations(ntx.vout[i].scriptPubKey, typeRet, dests, numRequired))
                    {
                        if (!nofilter)
                        {
                            printf("filter: %s\n", EncodeDestination(CKeyID(chainFilter)).c_str());
                        }
                        for (auto &oneDest : dests)
                        {
                            printf("%s\n", EncodeDestination(oneDest).c_str());
                        }
                    }
                    */

                    COptCCParams p, m;
                    CReserveTransfer rt;
                    if (ntx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() > 1 && (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        (m = COptCCParams(p.vData[1])).IsValid() &&
                        (nofilter || (m.vKeys.size() > 1 && GetDestinationID(m.vKeys[1]) == chainFilter)) &&
                        (rt.flags & flags) == flags)
                    {
                        inputDescriptors.insert(make_pair(GetDestinationID(p.vKeys[1]),
                                                    make_pair(CInputDescriptor(ntx.vout[i].scriptPubKey, ntx.vout[i].nValue, CTxIn(COutPoint(it->first.txhash, i))), rt)));
                    }
                    else if (p.IsValid() &&
                             p.evalCode == EVAL_RESERVE_TRANSFER &&
                             p.version != p.VERSION_V3)
                    {
                        // if we change the version, stop here in case it wasn't caught
                        assert(false);
                    }
                }
            }
            else
            {
                LogPrintf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}

// returns all unspent chain transfer outputs with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that chain are returned
bool GetUnspentChainTransfers(multimap<uint160, pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter)
{
    bool nofilter = chainFilter.IsNull();

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressUnspent(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER), 1, unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // if this is a transfer output, optionally to this chain, add it to the input vector
                    // chain filter was applied in index search
                    COptCCParams p;
                    COptCCParams m;
                    CReserveTransfer rt;
                    if (::IsPayToCryptoCondition(coins.vout[it->first.index].scriptPubKey, p) && p.evalCode == EVAL_RESERVE_TRANSFER &&
                        p.vData.size() > 1 && 
                        p.version == p.VERSION_V3 &&
                        (m = COptCCParams(p.vData.back())).IsValid() &&
                        (rt = CReserveTransfer(p.vData[0])).IsValid() &&
                        m.vKeys.size() > 1 &&
                        (nofilter || GetDestinationID(m.vKeys[1]) == chainFilter))
                    {
                        inputDescriptors.insert(make_pair(GetDestinationID(m.vKeys[1]),
                                                make_pair(CInputDescriptor(coins.vout[it->first.index].scriptPubKey, 
                                                                           coins.vout[it->first.index].nValue, 
                                                                           CTxIn(COutPoint(it->first.txhash, it->first.index))), rt)));
                    }
                }
            }
            else
            {
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
            }
        }
        return true;
    }
}

// returns all unspent chain transfer outputs with an optional chainFilter. if the chainFilter is not
// NULL, only transfers to that chain are returned
bool GetUnspentChainExports(uint160 chainID, multimap<uint160, pair<int, CInputDescriptor>> &exportOutputs)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK2(cs_main, mempool.cs);

    if (!GetAddressUnspent(CCrossChainRPCData::GetConditionID(chainID, EVAL_CROSSCHAIN_EXPORT), 1, unspentOutputs))
    {
        return false;
    }
    else
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                for (int i = 0; i < coins.vout.size(); i++)
                {
                    if (coins.IsAvailable(i))
                    {
                        // if this is an export output, optionally to this chain, add it to the input vector
                        COptCCParams p;
                        CCrossChainExport cx;
                        if (coins.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                            p.vData.size() && (cx = CCrossChainExport(p.vData[0])).IsValid())
                        {
                            exportOutputs.insert(make_pair(cx.systemID,
                                                     make_pair(coins.nHeight, CInputDescriptor(coins.vout[i].scriptPubKey, coins.vout[i].nValue, CTxIn(COutPoint(it->first.txhash, i))))));
                        }
                    }
                }
            }
            else
            {
                printf("%s: cannot retrieve transaction %s\n", __func__, it->first.txhash.GetHex().c_str());
                return false;
            }
        }
        return true;
    }
}

bool GetNotarizationData(uint160 chainID, uint32_t ecode, CChainNotarizationData &notarizationData, vector<pair<CTransaction, uint256>> *optionalTxOut)
{
    notarizationData.version = PBAAS_VERSION;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentFinalizations;
    CCurrencyDefinition chainDef;

    bool isEarned = ecode == EVAL_EARNEDNOTARIZATION;
    bool allFinalized = false;

    // get the last unspent notarization for this currency
    if (!GetAddressUnspent(CCrossChainRPCData::GetConditionID(chainID, EVAL_FINALIZE_NOTARIZATION), 1, unspentFinalizations))
    {
        return false;
    }
    else
    {
        multimap<int32_t, pair<uint256, CPBaaSNotarization>> sorted;
        multimap<int32_t, pair<CTransaction, uint256>> sortedTxs;

        notarizationData.lastConfirmed = 0;

        // filter out all transactions that do not spend from the notarization thread, or originate as the
        // chain definition
        for (auto it = unspentFinalizations.begin(); it != unspentFinalizations.end(); it++)
        {
            // printf("txid: %s\n", it->first.txhash.GetHex().c_str());
            CTransaction ntx;
            uint256 blkHash;

            if (myGetTransaction(it->first.txhash, ntx, blkHash))
            {
                if (!chainDef.IsValid())
                {
                    // try to make a chain definition out of each transaction, and keep the first one that is valid
                    std::vector<CCurrencyDefinition> chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(ntx);
                    if (chainDefs.size())
                    {
                        chainDef = chainDefs[0];
                    }
                }
                CPBaaSNotarization notarization = CPBaaSNotarization(ntx);
                if (notarization.IsValid())
                {
                    auto blkit = mapBlockIndex.find(blkHash);
                    if (blkit != mapBlockIndex.end())
                    {
                        // sort by block height, index by transaction id
                        sorted.insert(make_pair(blkit->second->GetHeight(), make_pair(it->first.txhash, notarization)));
                        if (optionalTxOut)
                        {
                            sortedTxs.insert(make_pair(blkit->second->GetHeight(), make_pair(ntx, blkHash)));
                        }
                    }
                    // if we are not on block 1 of a PBaaS chain and we are a first notarization that is not confirmed, none can be confirmed yet
                    if (notarization.prevHeight == 0 && !isEarned)
                    {
                        notarizationData.lastConfirmed = -1;
                    }
                }
            }
            else
            {
                printf("cannot retrieve transaction %s, may need to reindex\n", it->first.txhash.GetHex().c_str());
                //return false;
            }
        }

        if (!sorted.size())
        {
            allFinalized = true;

            if (GetAddressUnspent(CCrossChainRPCData::GetConditionID(chainID, ecode), 1, unspentOutputs))
            {
                // filter out all transactions that do not spend from the notarization thread, or originate as the
                // chain definition
                for (auto it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
                {
                    // printf("txid: %s\n", it->first.txhash.GetHex().c_str());
                    CTransaction ntx;
                    uint256 blkHash;

                    if (myGetTransaction(it->first.txhash, ntx, blkHash))
                    {
                        if (!chainDef.IsValid())
                        {
                            // try to make a chain definition out of each transaction, and keep the first one that is valid
                            std::vector<CCurrencyDefinition> chainDefs = CCurrencyDefinition::GetCurrencyDefinitions(ntx);
                            if (chainDefs.size())
                            {
                                chainDef = chainDefs[0];
                            }
                        }
                        CPBaaSNotarization notarization = CPBaaSNotarization(ntx);
                        if (notarization.IsValid())
                        {
                            auto blkit = mapBlockIndex.find(blkHash);
                            if (blkit != mapBlockIndex.end())
                            {
                                // sort by block height, index by transaction id
                                sorted.insert(make_pair(blkit->second->GetHeight(), make_pair(it->first.txhash, notarization)));
                                if (optionalTxOut)
                                {
                                    sortedTxs.insert(make_pair(blkit->second->GetHeight(), make_pair(ntx, blkHash)));
                                }
                            }
                            // if we are not on block 1 of a PBaaS chain and we are a first notarization that is not confirmed, none can be confirmed yet
                            if (notarization.prevHeight == 0 && !isEarned)
                            {
                                notarizationData.lastConfirmed = -1;
                            }
                        }
                    }
                    else
                    {
                        printf("cannot retrieve transaction %s, may need to reindex 2\n", it->first.txhash.GetHex().c_str());
                        //return false;
                    }
                }
            }

            if (!sorted.size())
            {
                //printf("no notarizations found\n");
                return false;
            }
        }

        if (allFinalized)
        {
            notarizationData.vtx.push_back(sorted.begin()->second);
            if (optionalTxOut && sortedTxs.size())
            {
                optionalTxOut->push_back(sortedTxs.begin()->second);
            }
            notarizationData.forks.push_back(vector<int32_t>(0));
            notarizationData.forks.back().push_back(0);
            notarizationData.bestChain = 0;
            return true;
        }

        if (!chainDef.IsValid())
        {
            // the first entry of all forks must reference a confirmed transaction if there is one
            CTransaction rootTx;
            uint256 blkHash;
            auto prevHash = sorted.begin()->second.second.prevNotarization;
            if (!prevHash.IsNull())
            {
                if (!myGetTransaction(prevHash, rootTx, blkHash))
                {
                    return false;
                }

                // ensure that we have a finalization output
                COptCCParams p;
                CPBaaSNotarization notarization;
                CTransactionFinalization finalization;
                uint32_t notarizeIdx, finalizeIdx;

                if (GetNotarizationAndFinalization(ecode, CMutableTransaction(rootTx), notarization, &notarizeIdx, &finalizeIdx))
                {
                    notarizationData.vtx.insert(notarizationData.vtx.begin(), make_pair(prevHash, notarization));
                    notarizationData.lastConfirmed = 0;
                    if (optionalTxOut)
                    {
                        optionalTxOut->insert(optionalTxOut->begin(), make_pair(rootTx, blkHash));
                    }
                }
                // debugging, this else is not needed
                else
                {
                    printf("previous transaction does not have both notarization and finalizaton outputs\n");
                }
            }
            else
            {
                if (!isEarned)
                {
                    notarizationData.lastConfirmed = -1;
                }
            }
        }
        else if (!chainDef.IsToken())
        {
            if (!isEarned)
            {
                // we still have the chain definition in our forks, so no notarization has been confirmed yet
                notarizationData.lastConfirmed = -1;
            }
        }

        multimap<uint256, pair<int32_t, int32_t>> references;       // associates the txid, the fork index, and the index in the fork

        for (auto p : sorted)
        {
            notarizationData.vtx.push_back(make_pair(p.second.first, p.second.second));
        }

        if (optionalTxOut)
        {
            for (auto p : sortedTxs)
            {
                optionalTxOut->push_back(p.second);
            }
        }

        // we now have all unspent notarizations sorted by block height, and the last confirmed notarization as first, if there
        // is one. if there is a confirmed notarization, all forks should refer to it, or they are invalid and should be spent.

        // find roots and create a chain from each
        for (int32_t i = 0; i < notarizationData.vtx.size(); i++)
        {
            auto &nzp = notarizationData.vtx[i];
            auto it = nzp.second.prevNotarization.IsNull() ? references.end() : references.find(nzp.second.prevNotarization);

            int32_t chainIdx = 0;
            int32_t posIdx = 0;

            // do we refer to a notarization that is already in a fork?
            if (it != references.end())
            {
                std::vector<int32_t> &fork = notarizationData.forks[it->second.first];

                // if it is the end of the fork, put this entry there, if not the end, copy up to it and start another fork
                if (it->second.second == (fork.size() - 1))
                {
                    fork.push_back(i);
                    chainIdx = it->second.first;
                    posIdx = fork.size() - 1;
                }
                else
                {
                    notarizationData.forks.push_back(vector<int32_t>(&fork[0], &fork[it->second.second] + 1));
                    notarizationData.forks.back().push_back(i);
                    chainIdx = notarizationData.forks.size() - 1;
                    posIdx = notarizationData.forks.back().size() - 1;
                }
            }
            else
            {
                // start a new fork that references no one else
                notarizationData.forks.push_back(vector<int32_t>(0));
                notarizationData.forks.back().push_back(i);
                chainIdx = notarizationData.forks.size() - 1;
                posIdx = notarizationData.forks.back().size() - 1;
            }
            references.insert(make_pair(nzp.first, make_pair(chainIdx, posIdx)));
        }

        CChainPower best;

        // now, we should have all forks in vectors
        // they should all have roots that point to the same confirmed or initial notarization, which should be enforced by chain rules
        // the best chain should simply be the tip with most power
        for (int i = 0; i < notarizationData.forks.size(); i++)
        {
            CChainPower curPower = ExpandCompactPower(notarizationData.vtx[notarizationData.forks[i].back()].second.compactPower, i);
            if (curPower > best)
            {
                best = curPower;
            }
        }
        notarizationData.bestChain = best.nHeight;
        return true;
    }
}

UniValue getnotarizationdata(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "getnotarizationdata \"currencyid\" accepted\n"
            "\nReturns the latest PBaaS notarization data for the specifed currencyid.\n"

            "\nArguments\n"
            "1. \"currencyid\"                  (string, required) the hex-encoded ID or string name  search for notarizations on\n"
            "2. \"accepted\"                    (bool, optional) accepted, not earned notarizations, default: true if on\n"
            "                                                    VRSC or VRSCTEST, false otherwise\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                 (numeric) The notarization protocol version\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getnotarizationdata", "\"currencyid\" true")
            + HelpExampleRpc("getnotarizationdata", "\"currencyid\"")
        );
    }

    CheckPBaaSAPIsValid();

    uint160 chainID;
    CChainNotarizationData nData;
    uint32_t ecode;
    
    if (IsVerusActive())
    {
        ecode = EVAL_ACCEPTEDNOTARIZATION;
    }
    else
    {
        ecode = EVAL_EARNEDNOTARIZATION;
    }

    LOCK2(cs_main, mempool.cs);

    chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid");
    }

    if (params.size() > 1)
    {
        if (!params[1].get_bool())
        {
            ecode = EVAL_EARNEDNOTARIZATION;
        }
    }

    if (GetNotarizationData(chainID, ecode, nData))
    {
        return nData.ToUniValue();
    }
    else
    {
        return NullUniValue;
    }
}

// get inputs for all of the unspent reward outputs sent to a specific reward type for the range specified
// returns the total input amount
CAmount GetUnspentRewardInputs(const CCurrencyDefinition &chainDef, vector<CInputDescriptor> &inputs, int32_t serviceCode, int32_t height)
{
    CAmount retval = 0;
    uint160 chainID = chainDef.GetID();

    // look for unspent outputs that match the addressout hashed with service code
    CKeyID keyID(CCrossChainRPCData::GetConditionID(CCrossChainRPCData::GetConditionID(chainID, serviceCode), EVAL_SERVICEREWARD));

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    if (GetAddressUnspent(keyID, 1, unspentOutputs))
    {
        // spend all billing periods prior or equal to this one
        int billingPeriod = height / chainDef.billingPeriod;

        // we need to look through the inputs to ensure that they are
        // actual service reward outputs in the correct billing periof, since we don't currently prevent other types of transaction outputs from being
        // sent to the same address, though doing so would burn its value anyhow

        LOCK(cs_main);
        for (auto output : unspentOutputs)
        {
            // printf("txid: %s\n", it->first.txhash.GetHex().c_str());
            CServiceReward sr;
            CCoins coins;
            if (pcoinsTip->GetCoins(output.first.txhash, coins))
            {
                for (auto txout : coins.vout)
                {
                    COptCCParams p;
                    if (!txout.IsNull() && IsPayToCryptoCondition(txout.scriptPubKey, p) && p.evalCode == EVAL_SERVICEREWARD)
                    {
                        FromVector(p.vData[0], sr);
                        if (sr.IsValid())
                        {
                            inputs.push_back(CInputDescriptor(txout.scriptPubKey, txout.nValue, CTxIn(output.first.txhash, output.first.index)));
                            retval += txout.nValue;
                        }
                    }
                    else
                    {
                        LogPrintf("GetUnspentRewardInputs: cannot retrieve transaction %s\n", output.first.txhash.GetHex().c_str());
                        printf("GetUnspentRewardInputs: cannot retrieve transaction %s\n", output.first.txhash.GetHex().c_str());
                    }
                }
            }
        }
    }
    return retval;
}

// this adds any new notarization rewards that have been sent to the notarization reward pool for this
// billing period since last accepted notarization, up to a maximum number of inputs
CAmount AddNewNotarizationRewards(CCurrencyDefinition &chainDef, vector<CInputDescriptor> &inputs, CMutableTransaction mnewTx, int32_t height)
{
    // get current chain info
    CAmount newIn = 0;
    newIn = GetUnspentRewardInputs(chainDef, inputs, SERVICE_NOTARIZATION, height);
    for (auto input : inputs)
    {
        mnewTx.vin.push_back(input.txIn);
    }
    return newIn;
}

UniValue submitacceptednotarization(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "submitacceptednotarization \"hextx\"\n"
            "\nFinishes an almost complete notarization transaction based on the notary chain and the current wallet or pubkey.\n"
            "\nIf successful in submitting the transaction based on all rules, a transaction ID is returned, otherwise, NULL.\n"

            "\nArguments\n"
            "1. \"hextx\"                       (hexstring, required) partial hex-encoded notarization transaction to submit\n"
            "                                   transaction should have only one notarization and one opret output\n"

            "\nResult:\n"
            "txid                               (hexstring) transaction ID of submitted transaction\n"

            "\nExamples:\n"
            + HelpExampleCli("submitacceptednotarization", "\"hextx\"")
            + HelpExampleRpc("submitacceptednotarization", "\"hextx\"")
        );
    }

    CheckPBaaSAPIsValid();

    // decode the transaction and ensure that it is formatted as expected
    CTransaction notarization;
    CPBaaSNotarization pbn;

    if (!DecodeHexTx(notarization, params[0].get_str()) || 
        notarization.vin.size() || 
        notarization.vout.size() != 2 ||
        !(pbn = CPBaaSNotarization(notarization)).IsValid() ||
        !notarization.vout.back().scriptPubKey.IsOpReturn())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid notarization transaction");
    }

    LOCK2(cs_main, mempool.cs);

    CCurrencyDefinition chainDef;
    int32_t chainDefHeight;
    if (!GetCurrencyDefinition(pbn.currencyID, chainDef, &chainDefHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain notarization");
    }

    // ensure we are still eligible to submit
    // finalize all transactions we can and send the notarization reward, plus all orphaned finalization outputs
    // to the confirmed recipient

    CChainNotarizationData nData;
    vector<pair<CTransaction, uint256>> txesBlkHashes;

    bool success = GetNotarizationData(pbn.currencyID, EVAL_ACCEPTEDNOTARIZATION, nData, &txesBlkHashes);

    // get notarization data and check all transactions
    if (success)
    {

        //LogPrintf("Accepted notarization GetNotarizationData returns %lu entries\n", nData.vtx.size());
        //printf("Accepted notarization GetNotarizationData returns %lu entries\n", nData.vtx.size());

        // if any notarization exists that is accepted and more recent than the last one, but one we still agree with,
        // we cannot submit, aside from that, we will prepare and submit
        set<uint256> priorBlocks;
        map<uint256, CPBaaSNotarization *> notarizationData;

        // printf("opRet: %s\n", notarization.vout[notarization.vout.size() - 1].scriptPubKey.ToString().c_str());

        auto chainObjects = RetrieveOpRetArray(notarization.vout[notarization.vout.size() - 1].scriptPubKey);

        bool stillValid = false;
        if (chainObjects.size() && chainObjects.back()->objectType == CHAINOBJ_PRIORBLOCKS)
        {
            // once here, default to true
            stillValid = true;

            CPriorBlocksCommitment &pbc = ((CChainObject<CPriorBlocksCommitment> *)chainObjects.back())->object;
            for (auto prior : pbc.priorBlocks)
            {
                priorBlocks.insert(prior);
            }

            for (auto it = nData.vtx.rbegin(); it != nData.vtx.rend(); it++)
            {
                // if any existing, accepted notarization is a subset of us, don't post, we will be rejected anyhow
                if (priorBlocks.count(it->second.notarizationPreHash))
                {
                    stillValid = false;
                    break;
                }
                else
                {
                    notarizationData.insert(make_pair(it->first, &it->second));
                }
            }
        }

        DeleteOpRetObjects(chainObjects);

        auto lastIt = notarizationData.find(pbn.prevNotarization);

        if (!stillValid || (lastIt == notarizationData.end()))
        {
            //printf("Notarization not matched or invalidated by prior notarization\n");
            throw JSONRPCError(RPC_VERIFY_REJECTED, "Notarization not matched or invalidated by prior notarization");
        }

        if (pbn.prevHeight != lastIt->second->notarizationHeight)
        {
            printf("Notarization heights not matched with previous notarization\n");
            throw JSONRPCError(RPC_VERIFY_REJECTED, "Notarization heights not matched with previous notarization");
        }

        if (pbn.prevHeight != 0 && (pbn.prevHeight + CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED > pbn.notarizationHeight))
        {
            //printf("Less than minimum number of blocks between notarizations\n");
            throw JSONRPCError(RPC_VERIFY_REJECTED, "Less than minimum number of blocks between notarizations");
        }

        // valid, spend notarization outputs, all needed finalizations, add any applicable reward output for 
        // confirmation to confirmed notary and miner of block,
        // add our output address and submit
        CMutableTransaction mnewTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), chainActive.Height());
        vector<CInputDescriptor> notarizationInputs;
        for (auto input : notarization.vin)
        {
            mnewTx.vin.push_back(input);
        }
        for (auto output : notarization.vout)
        {
            mnewTx.vout.push_back(output);
        }

        CTransaction lastTx = txesBlkHashes.back().first;

        int32_t confirmedInput = -1;
        int32_t confirmedIndex;
        CTxDestination payee;

        uint32_t notarizationIdx = -1, finalizationIdx = -1;
        CPBaaSNotarization dummy;

        notarizationInputs = AddSpendsAndFinalizations(nData, pbn.prevNotarization, mnewTx, &confirmedInput, &confirmedIndex, &payee);

        // if we got our inputs, add finalization
        if (notarizationInputs.size())
        {
            CCcontract_info CC;
            CCcontract_info *cp;
            cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);

            // use public key of cc
            CPubKey pk(ParseHex(CC.CChexstr));
            std::vector<CTxDestination> indexDests({CKeyID(CCrossChainRPCData::GetConditionID(pbn.currencyID, EVAL_FINALIZE_NOTARIZATION))});

            std::vector<CTxDestination> dests;
            if (chainDef.notarizationProtocol == chainDef.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CIdentityID(chainDef.GetID())});
            }
            else
            {
                dests = std::vector<CTxDestination>({pk});
            }

            CTransactionFinalization nf(confirmedInput);

            mnewTx.vout.insert(mnewTx.vout.begin() + (mnewTx.vout.size() - 1), 
                                CTxOut(CCurrencyDefinition::DEFAULT_OUTPUT_VALUE, 
                                       MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &nf), &indexDests)));
        }

        if (notarizationInputs.size() && GetNotarizationAndFinalization(EVAL_ACCEPTEDNOTARIZATION, mnewTx, dummy, &notarizationIdx, &finalizationIdx))
        {
            // we need to add outputs to pay the reward to the confirmed notary and block miner/staker of that notarization
            // the rest goes back into the notarization thread
            // first input should be the notarization thread
            CTransaction newTx(mnewTx);
            CTransaction confirmedTx;
            CPBaaSNotarization confirmedPBN;
            CBlockIndex *pindex = NULL;
            uint256 hashBlock;
            CBlock confirmedBlock;

            CAmount valueIn;

            BlockMap::iterator it;
            {
                LOCK2(cs_main, mempool.cs);
                // get value in
                CCoinsViewCache view(pcoinsTip);
                int64_t dummyInterest;
                valueIn = view.GetValueIn(chainActive.LastTip()->GetHeight(), &dummyInterest, newTx, chainActive.LastTip()->nTime);

                if (!valueIn)
                {
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, "unable to spend necessary transaction outputs");
                }

                if (confirmedInput != -1)
                {
                    // get data from confirmed tx and block that contains confirmed tx
                    confirmedTx = txesBlkHashes[confirmedIndex].first;
                    hashBlock = txesBlkHashes[confirmedIndex].second;
                    if ((it = mapBlockIndex.find(hashBlock)) != mapBlockIndex.end())
                    {
                        pindex = mapBlockIndex.find(hashBlock)->second;
                    }

                    // add all inputs that might provide notary reward and calculate notary reward based on that plus current
                    // notarization input value divided by number of blocks left in billing period, times blocks per notarization
                    if (pindex)
                    {
                        valueIn += AddNewNotarizationRewards(chainDef, notarizationInputs, mnewTx, pindex->GetHeight());
                    }
                    else
                    {
                        LogPrintf("submitacceptednotarization: cannot find chain %s, possible corrupted database\n", chainDef.name.c_str());
                        printf("submitacceptednotarization: cannot find chain %s, possible corrupted database\n", chainDef.name.c_str());
                    }
                }
            }

            // recipient of notary rewards and miner to share it with
            // notary recipient is the one from the confirmed notarization
            // and miner recipient is from the block it was mined into
            CTxDestination notaryRecipient, minerRecipient;

            // get recipients of any reward output
            if (confirmedInput != -1)
            {
                LOCK(cs_main);
                if (pindex && ReadBlockFromDisk(confirmedBlock, pindex, Params().GetConsensus()) && 
                    (confirmedPBN = CPBaaSNotarization(confirmedTx)).IsValid() &&
                    ExtractDestination(confirmedBlock.vtx[0].vout[0].scriptPubKey, minerRecipient, false))
                {
                    notaryRecipient = confirmedPBN.notaryDest;
                }
                else
                {
                    throw JSONRPCError(RPC_DATABASE_ERROR, "unable to retrieve confirmed notarization data");
                }
            }

            // minimum amount must go to main thread and finalization, then divide what is left among blocks in the billing period
            uint64_t blocksLeft = chainDef.billingPeriod - ((confirmedPBN.notarizationHeight - chainDef.startBlock) % chainDef.billingPeriod);
            CAmount valueOut = 0;
            CAmount notaryValueOut;

            if (valueIn > (CCurrencyDefinition::DEFAULT_OUTPUT_VALUE << 1))
            {
                if (confirmedInput != -1)
                {
                    if (valueIn < (CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED * (CCurrencyDefinition::DEFAULT_OUTPUT_VALUE << 1)))
                    {
                        valueOut = valueIn - (CCurrencyDefinition::DEFAULT_OUTPUT_VALUE << 1);
                    }
                    else
                    {
                        valueOut = (CPBaaSNotarization::MIN_BLOCKS_BETWEEN_ACCEPTED * (valueIn - (CCurrencyDefinition::DEFAULT_OUTPUT_VALUE << 1))) / blocksLeft;
                    }
                }
                notaryValueOut = valueIn - ((CCurrencyDefinition::DEFAULT_OUTPUT_VALUE << 1) + valueOut);
            }
            else
            {
                notaryValueOut = 0;
            }

            if (notaryValueOut >= (PBAAS_MINNOTARIZATIONOUTPUT << 1))
            {
                // pay the confirmed notary with
                // notarization reward for this billing period / remaining blocks in the billing period * min blocks in notarization
                // the finalization out has minimum, the notarization out has all the remainder
                // outputs we should have here:
                // 1) notarization out
                // 2) finalization out
                // 3) op_ret
                //
                // send:
                // 66% of output to notary address
                // 33% of output to primary address of block reward
                auto insertIt = mnewTx.vout.begin() + (finalizationIdx + 1);
                if (valueOut)
                {
                    CAmount minerOutput = valueOut / 3;
                    CAmount notaryOutput = valueOut / 3 * 2;
                    mnewTx.vout.insert(insertIt, CTxOut(minerOutput, GetScriptForDestination(minerRecipient)));
                    mnewTx.vout.insert(insertIt, CTxOut(notaryOutput, GetScriptForDestination(notaryRecipient)));
                }
            }
            else
            {
                notaryValueOut += valueOut;
                valueOut = 0;
            }
            
            if ((notaryValueOut + valueOut + CCurrencyDefinition::DEFAULT_OUTPUT_VALUE) > valueIn)
            {
                notaryValueOut = valueIn;
                printf("Not enough funds to notarize %s\n", chainDef.name.c_str());
                LogPrintf("Not enough funds to notarize %s\n", chainDef.name.c_str());
            }

            CCcontract_info CC;
            CCcontract_info *cp;

            // make the output for the other chain's notarization
            cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
            CPubKey pk(ParseHex(CC.CChexstr));
            std::vector<CTxDestination> dests;

            std::vector<CTxDestination> indexDests({CKeyID(CCrossChainRPCData::GetConditionID(pbn.currencyID, EVAL_ACCEPTEDNOTARIZATION))});
            if (chainDef.notarizationProtocol == chainDef.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CIdentityID(chainDef.GetID())});
            }
            else
            {
                dests = std::vector<CTxDestination>({pk});
            }
            
            mnewTx.vout[notarizationIdx] = CTxOut(notaryValueOut, MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &pbn), &indexDests));

            CTransaction ntx(mnewTx);

            uint32_t consensusBranchId = CurrentEpochBranchId(chainActive.LastTip()->GetHeight(), Params().GetConsensus());

            // sign the transaction and submit
            for (int i = 0; i < ntx.vin.size(); i++)
            {
                bool signSuccess;
                SignatureData sigdata;
                CAmount value;
                const CScript *pScriptPubKey;

                if (i < notarizationInputs.size())
                {
                    pScriptPubKey = &notarizationInputs[i].scriptPubKey;
                    value = notarizationInputs[i].nValue;

                    signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &ntx, i, value, SIGHASH_ALL), *pScriptPubKey, sigdata, consensusBranchId);

                    if (!signSuccess)
                    {
                        fprintf(stderr,"submitacceptednotarization: failure to sign accepted notarization\n");
                        throw JSONRPCError(RPC_VERIFY_ERROR, "Failed to sign notarizaton for " + chainDef.name);
                    } else {
                        UpdateTransaction(mnewTx, i, sigdata);
                    }
                }
            }

            // add to mempool and submit transaction
            CTransaction tx(mnewTx);

            CValidationState state;
            bool fMissingInputs;
            bool accepted;
            {
                LOCK2(cs_main, mempool.cs);
                accepted = AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs);
            }
            if (!accepted) {
                if (state.GetRejectReason() != "")
                {
                    printf("Cannot enter notarization into mempool for chain %s, %s\n", chainDef.name.c_str(), state.GetRejectReason().c_str());
                }
                if (state.IsInvalid()) {
                    throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
                } else {
                    if (fMissingInputs) {
                        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                    }
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
                }
            }
            else
            {
                RelayTransaction(tx);
            }

            return newTx.GetHash().GetHex();
        }
    }
    throw JSONRPCError(RPC_VERIFY_REJECTED, "Failed to get notarizaton data for chainID: " + pbn.currencyID.GetHex());
}

UniValue getcrossnotarization(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        throw runtime_error(
            "getcrossnotarization \"systemid\" '[\"notarizationtxid1\", \"notarizationtxid2\", ...]'\n"
            "\nCreates and returns a cross notarization of this chain back to the system id caller,\n"
            "assuming that a prior notarization for that system is found.\n"

            "\nArguments\n"
            "1. \"systemid\"                    (string, required) the currency system id to search for notarizations on\n"
            "2. \"txidlist\"                    (stringarray, optional) list of transaction ids to check in preferred order, first found is returned\n"
            "3. \"accepted\"                    (bool, optional) accepted, not earned notarizations, default: true if on\n"
            "                                                    VRSC or VRSCTEST, false otherwise\n"

            "\nResult:\n"
            "{\n"
            "  \"crosstxid\" : \"xxxx\",        (hexstring) cross-transaction id of the notarization that matches, which is one in the arguments\n"
            "  \"txid\" : \"xxxx\",             (hexstring) transaction id of the notarization that was found\n"
            "  \"rawtx\" : \"hexdata\",         (hexstring) entire matching transaction data, serialized\n"
            "  \"newtx\" : \"hexdata\"          (hexstring) the proposed notarization transaction with an opret and opretproof\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getcrossnotarization", "\"systemid\" '[\"notarizationtxid1\", \"notarizationtxid2\", ...]'")
            + HelpExampleRpc("getcrossnotarization", "\"systemid\" '[\"notarizationtxid1\", \"notarizationtxid2\", ...]'")
        );
    }

    uint160 chainID;
    uint32_t ecode;
    UniValue ret(UniValue::VOBJ);

    if (IsVerusActive())
    {
        ecode = EVAL_ACCEPTEDNOTARIZATION;
    }
    else
    {
        ecode = EVAL_EARNEDNOTARIZATION;
    }

    if (params[0].type() == UniValue::VSTR)
    {
        try
        {
            chainID.SetHex(params[0].get_str());
        }
        catch(const std::exception& e)
        {
        }
    }

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currencyid");
    }

    if (params.size() > 2)
    {
        if (!params[2].get_bool())
        {
            ecode = EVAL_EARNEDNOTARIZATION;
        }
    }

    uint32_t crosscode;
    if (ecode == EVAL_ACCEPTEDNOTARIZATION)
    {
        crosscode = EVAL_EARNEDNOTARIZATION;
    }
    else
    {
        crosscode = EVAL_ACCEPTEDNOTARIZATION;
    }

    if (params[1].type() != UniValue::VARR)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid second parameter object type: " + itostr(params[1].type()));
    }

    vector<UniValue> values = params[1].getValues();
    set<uint256> txids;
    for (int32_t i = 0; i < values.size(); i++)
    {
        auto txid = uint256S(values[i].get_str());
        if (txid.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter for notarization ID: " + values[i].get_str());
        }
        txids.insert(txid);
    }

    CChainNotarizationData nData;

    LOCK2(cs_main, mempool.cs);

    CCurrencyDefinition chainDef;
    if (!GetCurrencyDefinition(chainID, chainDef))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain ID: " + EncodeDestination(CIdentityID(chainID)));
    }

    vector<pair<CTransaction, uint256>> nTxes;

    // get notarization data and check all transactions
    if (GetNotarizationData(chainID, ecode, nData, &nTxes))
    {
        CTransaction tx;
        CPBaaSNotarization ourLast;
        uint256 blkHash;
        bool found = false;

        // loop in reverse through list, as most recent is at end
        for (int32_t i = nData.vtx.size() - 1; i >= 0; i--)
        {
            const pair<uint256, CPBaaSNotarization> &nzp = nData.vtx[i];
            tx = nTxes[i].first;
            blkHash = nTxes[i].second;
            auto nit = txids.find(nzp.second.crossNotarization);
            if (i == 0 || !(nit == txids.end()))
            {
                found = true;
                // we have the first matching transaction, return it
                ret.push_back(Pair("crosstxid", nzp.second.crossNotarization.GetHex()));
                ret.push_back(Pair("txid", nzp.first.GetHex()));
                ret.push_back(Pair("rawtx", EncodeHexTx(tx)));
                break;
            }
        }

        // now make the basic notarization for this chain that the other chain daemon can complete
        // after it is returned
        if (found)
        {
            // make sure our MMR matches our tip height, etc.
            LOCK(cs_main);

            CPBaaSNotarization prevNotarization(tx);

            if(!prevNotarization.IsValid())
            {
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Invalid prior notarization");
            }

            int32_t proofheight = chainActive.Height();
            ChainMerkleMountainView mmv(chainActive.GetMMR(), proofheight);
            uint256 mmrRoot = mmv.GetRoot();
            uint256 preHash = mmv.mmr.GetNode(proofheight).hash;

            // prove the last notarization txid with new MMR, which also provides its blockhash and power as part of proof
            CBlock block;
            CBlockIndex *pnindex = mapBlockIndex.find(blkHash)->second;

            if(!pnindex || !ReadBlockFromDisk(block, pnindex, Params().GetConsensus(), 0))
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            int32_t prevHeight = pnindex->GetHeight();

            // which transaction are we in this block?
            std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

            if (!GetAddressIndex(CCrossChainRPCData::GetConditionID(chainID, EVAL_FINALIZE_NOTARIZATION), 1, addressIndex, prevHeight, prevHeight))
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Address index read error - possible corruption in address index");
            }

            uint256 txHash = tx.GetHash();
            unsigned int txIndex;
            for (txIndex = 0; txIndex < addressIndex.size(); txIndex++)
            {
                if (addressIndex[txIndex].first.txhash == txHash)
                {
                    break;
                }
            }

            if (txIndex == addressIndex.size())
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Notarization not found in address index - possible corruption");
            }
            else
            {
                // get index in the block as our transaction index for proofs
                txIndex = addressIndex[txIndex].first.index;
            }

            CMMRProof blockProof;
            chainActive.GetBlockProof(mmv, blockProof, proofheight);

            // create and store the notarization proof of chain
            vector<CBaseChainObject *> chainObjects;
            COpRetProof orp;

            // if bock headers are merge mined, keep header refs, not headers
            CBlockHeaderAndProof bhp(blockProof, chainActive[proofheight]->GetBlockHeader());
            CChainObject<CBlockHeaderAndProof> latestHeaderObj(CHAINOBJ_HEADER, bhp);

            chainObjects.push_back(&latestHeaderObj);
            orp.AddObject(CHAINOBJ_HEADER, bhp.BlockHash());

            // prove the important last notarization components in the tx.
            // we care about the following components:
            //  input 0 - can be used to determine if the tx is a coinbase and is the spending thread for notarization
            //  notarization output - the notarization state being attested to
            //  currency definition output matching notarization output - signifies first notarization
            std::vector<std::pair<int16_t, int16_t>> txComponents({{(int16_t)CTransactionHeader::TX_PREVOUTSEQ, (int16_t)0}});
            for (int i = 0; i < tx.vout.size(); i++)
            {
                COptCCParams p;
                if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
                {
                    if (p.evalCode == ecode)
                    {
                        txComponents.push_back({CTransactionHeader::TX_OUTPUT, i});
                    }
                    else if (p.evalCode == EVAL_CURRENCY_DEFINITION && 
                             p.vData.size())
                    {
                        CCurrencyDefinition definedCurrency(p.vData[0]);
                        if (definedCurrency.IsValid() &&
                            definedCurrency.GetID() == chainID)
                        {
                            txComponents.push_back({CTransactionHeader::TX_OUTPUT, i});
                        }
                    }
                }
            }
            CPartialTransactionProof txProof = block.GetPartialTransactionProof(tx, txIndex, txComponents);

            // add the cross transaction from this chain to return
            CChainObject<CPartialTransactionProof> strippedTxObj(CHAINOBJ_TRANSACTION_PROOF, txProof);

            chainObjects.push_back(&strippedTxObj);
            orp.AddObject(CHAINOBJ_TRANSACTION_PROOF, tx.GetHash());

            // add the MMR block nodes between the last notarization and this one, containing root that combines merkle, block, and compact power hashes
            CPriorBlocksCommitment priorBlocks;
            int numPriorBlocks = proofheight - ourLast.crossHeight;

            if (numPriorBlocks > PBAAS_MAXPRIORBLOCKS || numPriorBlocks > (proofheight - 1))
                numPriorBlocks = PBAAS_MAXPRIORBLOCKS > (proofheight - 1) ? ((proofheight - 1) < 1 ? 0 : (proofheight - 1)) : PBAAS_MAXPRIORBLOCKS;

            // push back the merkle, block hash, and block power commitments for prior blocks to ensure no
            // unintended notary overlap
            for (int i = numPriorBlocks; i >= 0; i--)
            {
                priorBlocks.priorBlocks.push_back(mmv.mmr.GetNode(proofheight - i).hash);
            }

            CChainObject<CPriorBlocksCommitment> priorBlocksObj(CHAINOBJ_PRIORBLOCKS, priorBlocks);
            chainObjects.push_back(&priorBlocksObj);
            orp.AddObject(CHAINOBJ_PRIORBLOCKS, ::GetHash(priorBlocks));

            // get node keys and addresses
            vector<CNodeData> nodes;
            const static int MAX_NODES = 2;

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
                            CIdentityID idID(vNodes[i]->hashPaymentAddress);
                            nodes.push_back(CNodeData(vNodes[i]->addr.ToString(), EncodeDestination(CTxDestination(idID))));
                        }
                    }
                }
            }

            // reduce number to max by removing randomly
            while (nodes.size() > MAX_NODES)
            {
                int toErase = GetRandInt(nodes.size() - 1);
                nodes.erase(nodes.begin() + toErase);
            }

            CTxDestination notaryDest;
            if (!VERUS_DEFAULTID.IsNull())
            {
                notaryDest = VERUS_DEFAULTID;
            }
            else if (USE_EXTERNAL_PUBKEY)
            {
                CPubKey pubKey = CPubKey(ParseHex(NOTARY_PUBKEY));
                if (pubKey.IsFullyValid())
                {
                    notaryDest = pubKey;
                }
            }
            else
            {
                static bool printMsg = true;
                if (printMsg)
                {
                    printf("No notary public key recipient has been set, so this node cannot receive rewards for notarization\n");
                    LogPrintf("No notary public key recipient has been set, so this node cannot receive rewards for notarization\n");
                    printMsg = false;
                }
            }

            CBlockIndex *nzIndex = chainActive[proofheight];
            CCurrencyState currencyState = ConnectedChains.GetCurrencyState(proofheight);

            // get the current block's MMR root and proof height
            CPBaaSNotarization notarization = CPBaaSNotarization(CCurrencyDefinition::NOTARIZATION_AUTO, 
                                                                 ASSETCHAINS_CHAINID,
                                                                 notaryDest,
                                                                 proofheight,
                                                                 mmrRoot,
                                                                 preHash,
                                                                 ArithToUint256(GetCompactPower(nzIndex->nNonce, nzIndex->nBits, nzIndex->nVersion)),
                                                                 currencyState,
                                                                 uint256(), 0,
                                                                 tx.GetHash(), prevNotarization.notarizationHeight,
                                                                 orp,
                                                                 nodes);

            // we now have the chain objects, all associated proofs, and notarization data, make an appropriate transaction template with opret
            // and return it. notarization will need to be completed, so the only thing we really need to construct on this chain is the opret
            CMutableTransaction newNotarization = CreateNewContextualCMutableTransaction(Params().GetConsensus(), proofheight);

            CCcontract_info CC;
            CCcontract_info *cp;

            // make the output for the other chain's notarization
            cp = CCinit(&CC, crosscode);

            std::vector<CTxDestination> dests;
            std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(chainID, crosscode))});
            if (chainDef.notarizationProtocol == chainDef.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CIdentityID(chainDef.GetID())});
            }
            else
            {
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            }
            newNotarization.vout.push_back(CTxOut(CCurrencyDefinition::DEFAULT_OUTPUT_VALUE, 
                                                  MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(crosscode, dests, 1, &notarization), &indexDests)));

            // make the unspent finalization output
            cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
            if (chainDef.notarizationProtocol != chainDef.NOTARIZATION_NOTARY_CHAINID)
            {
                dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
            }
            indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(chainID, EVAL_FINALIZE_NOTARIZATION))});

            CTransactionFinalization nf;
            newNotarization.vout.push_back(CTxOut(DEFAULT_TRANSACTION_FEE, 
                                                  MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &nf), &indexDests)));

            newNotarization.vout.push_back(CTxOut(0, StoreOpRetArray(chainObjects)));

            CTransaction newTx(newNotarization);
            ret.push_back(Pair("newtx", EncodeHexTx(newTx)));
        }
    }
    return ret;
}

UniValue paynotarizationrewards(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 2 && params.size() != 3))
    {
        throw runtime_error(
            "paynotarizationrewards \"currencyid\" \"amount\" \"billingperiod\"\n"
            "\nAdds some amount of funds to a specific billing period of a PBaaS chain, which will be released\n"
            "\nin the form of payments to notaries whose notarizations are confirmed.\n"

            "\nArguments\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("paynotarizationrewards", "\"hextx\"")
            + HelpExampleRpc("paynotarizationrewards", "\"hextx\"")
        );
    }
    CheckPBaaSAPIsValid();

    uint160 chainID;

    if (!pwalletMain)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Paying notarization rewards requires an active wallet");
    }

    chainID = GetChainIDFromParam(params[0]);
    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid PBaaS name or currencyid");
    }

    CAmount amount = AmountFromValue(params[1]);
    uint32_t billingPeriod = 0;

    if (params.size() == 3)
    {
        uint32_t billingPeriod = uni_get_int(params[2]);
    }

    CServiceReward sr = CServiceReward(SERVICE_NOTARIZATION, billingPeriod);
    
    CCcontract_info CC;
    CCcontract_info *cp;
    cp = CCinit(&CC, EVAL_SERVICEREWARD);

    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

    std::vector<CTxDestination> dests({CKeyID(CCrossChainRPCData::GetConditionID(CCrossChainRPCData::GetConditionID(chainID, SERVICE_NOTARIZATION), EVAL_SERVICEREWARD))});

    std::vector<CRecipient> outputs = std::vector<CRecipient>({{MakeCC1of1Vout(EVAL_SERVICEREWARD, amount, pk, dests, sr).scriptPubKey, amount}});
    CWalletTx wtx;

    // create the transaction with native coin as input
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, chainID.GetHex() + ": " + failReason);
    }
    if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return UniValue(wtx.GetHash().GetHex());
}

UniValue listreservetransactions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "listreservetransactions (maxnumber) (minconfirmations)\n"
            "\nLists all reserve coin transactions sent to/from the current wallet.\n"

            "\nArguments\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("listreservetransactions", "100 0")
            + HelpExampleRpc("listreservetransactions", "100 0")
        );
    }
    // lists all transactions in a wallet that are 
    return NullUniValue;
}

// this must be called after all initial contributions are updated in the currency definition.
CCoinbaseCurrencyState GetInitialCurrencyState(const CCurrencyDefinition &chainDef)
{
    bool isFractional = chainDef.IsFractional();
    CCurrencyState cState;

    // calculate contributions and conversions
    const std::vector<CAmount> reserveFees(chainDef.currencies.size());
    std::vector<int64_t> conversions = chainDef.conversions;

    CAmount nativeFees = 0;
    if (isFractional)
    {
        cState = CCurrencyState(chainDef.currencies,
                                chainDef.weights,
                                std::vector<int64_t>(chainDef.currencies.size()), 0, 0, 0, CCurrencyState::FLAG_VALID + CCurrencyState::FLAG_FRACTIONAL);
        CCurrencyState tmpState;
        conversions = cState.ConvertAmounts(chainDef.preconverted, std::vector<int64_t>(chainDef.currencies.size()), tmpState);
        cState = tmpState;
    }
    else
    {
        cState.currencies = chainDef.currencies;
        cState.reserves = conversions;
        CAmount PreconvertedNative = cState.ReserveToNative(CCurrencyValueMap(chainDef.currencies, chainDef.preconverted));
        cState = CCurrencyState(chainDef.currencies, 
                                std::vector<int32_t>(0), 
                                conversions, 
                                0, 
                                PreconvertedNative,
                                PreconvertedNative, 
                                CCurrencyState::FLAG_VALID);
    }

    cState.UpdateWithEmission(chainDef.GetTotalPreallocation());

    CCoinbaseCurrencyState retVal(cState, 
                                  0, 
                                  0, 
                                  chainDef.preconverted, 
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  std::vector<int64_t>(chainDef.currencies.size()), 
                                  conversions,
                                  reserveFees,
                                  reserveFees);

    return retVal;
}

UniValue reserveexchange(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "reserveexchange '[{\"toreserve\": 1, \"recipient\": \"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\", \"amount\": 5.0}]'\n"
            "\nThis sends a Verus output as a JSON object or lists of Verus outputs as a list of objects to an address on the same or another chain.\n"
            "\nFunds are sourced automatically from the current wallet, which must be present, as in sendtoaddress.\n"

            "\nArguments\n"
            "       {\n"
            "           \"toreserve\"      : \"bool\",  (bool,   optional) if present, conversion is to the underlying reserve (Verus), if false, from Verus\n"
            "           \"recipient\"      : \"Rxxx\",  (string, required) recipient of converted funds or funds that failed to convert\n"
            "           \"amount\"         : \"n\",     (int64,  required) amount of source coins that will be converted, depending on the toreserve flag, the rest is change\n"
            "           \"limit\"          : \"n\",     (int64,  optional) price in reserve limit, below which for buys and above which for sells, execution will occur\n"
            "           \"validbefore\"    : \"n\",     (int,    optional) block before which this can execute as a conversion, otherwise, it executes as a send with normal network fee\n"
            "           \"subtractfee\"    : \"bool\",  (bool,   optional) if true, reduce amount to destination by the fee amount, otherwise, add from inputs to cover fee"
            "       }\n"

            "\nResult:\n"
            "       \"txid\" : \"transactionid\" (string) The transaction id.\n"

            "\nExamples:\n"
            + HelpExampleCli("reserveexchange", "'[{\"name\": \"PBAASCHAIN\", \"paymentaddress\": \"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\", \"amount\": 5.0}]'")
            + HelpExampleRpc("reserveexchange", "'[{\"name\": \"PBAASCHAIN\", \"paymentaddress\": \"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\", \"amount\": 5.0}]'")
        );
    }

    CheckPBaaSAPIsValid();
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Not yet implemented. Use sendcurrency in this release.");
}

UniValue sendcurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        throw runtime_error(
            "sendcurrency \"fromaddress\" '[{\"address\":... ,\"amount\":...},...]' (returntx)\n"
            "\nThis sends one or many Verus outputs to one or many addresses on the same or another chain.\n"
            "Funds are sourced automatically from the current wallet, which must be present, as in sendtoaddress.\n"
            "If \"fromaddress\" is specified, all funds will be taken from that address, otherwise funds may come\n"
            "from any source set of UTXOs controlled by the wallet.\n"

            "\nArguments\n"
            "1. \"fromaddress\"             (string, required) The VerusID or address to send the funds from. \"*\" means all addresses\n"
            "2. \"outputs\"                 (array, required) An array of json objects representing currencies, amounts, and destinations to send.\n"
            "    [{\n"
            "      \"currency\": \"name\"   (string, required) Name of the source currency to send in this output, defaults to native of chain\n"
            "      \"amount\":amount        (numeric, required) The numeric amount of currency, denominated in source currency\n"
            "      \"convertto\":\"name\",  (string, optional) Valid currency to convert to, either a reserve of a native source, or fractional of reserve\n"
            "      \"address\":\"dest\"     (string, required) The address and optionally chain/system after the \"@\" as a system specific destination\n"
            "      \"refundto\":\"dest\"    (string, optional) For pre-conversions, this is where refunds will go, defaults to fromaddress\n"
            "      \"memo\":memo            (string, optional) If destination is a zaddr (not supported on testnet), a string message (not hexadecimal) to include.\n"
            "      \"preconvert\":\"false\", (bool,   optional) auto-convert to PBaaS currency at market price, this only works if the order is mined before block start of the chain\n"
            "      \"subtractfee\":\"bool\", (bool,   optional) if true, output must be of native or convertible reserve currency, and output will be reduced by share of fee\n"
            "    }, ... ]\n"
            "3. \"returntx\"                (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed and returned\n"

            "\nResult:\n"
            "   \"txid\" : \"transactionid\" (string) The transaction id if (returntx) is false\n"
            "   \"hextx\" : \"hex\"         (string) The hexadecimal, serialized transaction if (returntx) is true\n"

            "\nExamples:\n"
            + HelpExampleCli("sendcurrency", "\"*\" '[{\"currency\":\"btc\",\"address\":\"RRehdmUV7oEAqoZnzEGBH34XysnWaBatct\" ,\"amount\":500.0},...]'")
            + HelpExampleRpc("sendcurrency", "\"bob@\" '[{\"currency\":\"btc\", \"address\":\"alice@quad\", \"amount\":500.0},...]'")
        );
    }

    std::string sourceAddress = uni_get_str(params[0]);
    CTxDestination sourceDest;

    if (!(sourceAddress == "*" || (sourceDest = DecodeDestination(sourceAddress)).which() != COptCCParams::ADDRTYPE_INVALID))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. First parameter must be source address/identity or \"*\". See help.");
    }

    if (!params[1].isArray() || !params[1].size())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters. Second parameter must be array of outputs. See help.");
    }

    bool returnTx = false;
    if (params.size() > 2)
    {
        returnTx = uni_get_bool(params[2]);
    }

    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    uint160 thisChainID = thisChain.GetID();
    bool toFractional = false;

    std::vector<CRecipient> outputs;

    const UniValue &uniOutputs = params[1];

    uint32_t height = chainActive.Height();

    try
    {
        for (int i = 0; i < uniOutputs.size(); i++)
        {        
            auto currencyStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "currency")));
            CAmount sourceAmount = AmountFromValue(find_value(uniOutputs[i], "amount"));
            auto convertToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "convertto")));
            auto destStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "address")));
            auto refundToStr = TrimSpaces(uni_get_str(find_value(uniOutputs[i], "refundto")));
            auto memoStr = uni_get_str(find_value(uniOutputs[i], "memo"));
            bool preConvert = uni_get_bool(find_value(uniOutputs[i], "preconvert"));
            bool subtractFee = uni_get_bool(find_value(uniOutputs[i], "subtractfee"));
            bool mintNew = uni_get_bool(find_value(uniOutputs[i], "mintnew"));

            if (currencyStr.size() ||
                convertToStr.size() ||
                refundToStr.size() ||
                memoStr.size() ||
                preConvert ||
                mintNew)
            {
                CheckPBaaSAPIsValid();
            }

            LOCK2(cs_main, mempool.cs);

            CCurrencyDefinition sourceCurrencyDef;
            uint160 sourceCurrencyID;
            if (currencyStr != "")
            {
                sourceCurrencyID = ValidateCurrencyName(currencyStr, &sourceCurrencyDef);
                if (sourceCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If source currency is specified, it must be valid.");
                }
            }
            else
            {
                sourceCurrencyDef = thisChain;
                sourceCurrencyID = sourceCurrencyDef.GetID();
                currencyStr = thisChain.name;
            }

            CCurrencyDefinition convertToCurrencyDef;
            uint160 convertToCurrencyID;
            if (convertToStr != "")
            {
                convertToCurrencyID = ValidateCurrencyName(convertToStr, &convertToCurrencyDef);
                if (convertToCurrencyID.IsNull())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If currency conversion is requested, destination currency must be valid.");
                }
            }

            std::string systemDestStr;
            uint160 destSystemID = thisChainID;
            CCurrencyDefinition destSystemDef = thisChain;
            std::vector<std::string> subNames = ParseSubNames(destStr, systemDestStr, true);
            if (systemDestStr != "")
            {
                destSystemID = ValidateCurrencyName(systemDestStr, &destSystemDef);
                if (destSystemID.IsNull() || destSystemDef.IsToken() || destSystemDef.systemID != destSystemDef.GetID())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "If destination system is specified, destination system or chain must be valid.");
                }
            }

            if (mintNew && 
                (!(sourceCurrencyDef.IsToken() &&
                   GetDestinationID(sourceDest) == sourceCurrencyID &&
                   sourceCurrencyDef.proofProtocol == sourceCurrencyDef.PROOF_CHAINID &&
                   destSystemID == thisChainID &&
                   !preConvert &&
                   convertToCurrencyID.IsNull())))
            {
                // attempt to mint currency that isn't under the source ID's control
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Only the ID of a mintable currency can mint such a currency. Minting cannot be combined with conversion.");
            }

            CTxDestination destination = DecodeDestination(destStr);
            CTransferDestination transferDestination;
            if (destination.which() == COptCCParams::ADDRTYPE_INVALID)
            {
                if (destSystemDef.options & destSystemDef.OPTION_GATEWAY)
                {
                    std::vector<unsigned char> rawDestBytes;
                    for (int i = 0; i < subNames.size(); i++)
                    {
                        if (i)
                        {
                            rawDestBytes.push_back('.');
                        }
                        rawDestBytes.insert(rawDestBytes.end(), subNames[i].begin(), subNames[i].end());
                    }
                    transferDestination = CTransferDestination(CTransferDestination::DEST_RAW, rawDestBytes);
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Specified destination must be valid.");
                }
            }
            else if (destination.which() == COptCCParams::ADDRTYPE_ID)
            {
                if (!CIdentity::LookupIdentity(GetDestinationID(destination)).IsValid())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "When sending to an ID, the ID must be valid.");
                }
            }

            CTxDestination refundDestination = DecodeDestination(refundToStr);
            if (refundDestination.which() == COptCCParams::ADDRTYPE_ID &&
                GetDestinationID(refundDestination) != GetDestinationID(destination))
            {
                if (!CIdentity::LookupIdentity(GetDestinationID(refundDestination)).IsValid())
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "When refunding to an ID, the ID must be valid.");
                }
            }
            else if (refundDestination.which() == COptCCParams::ADDRTYPE_INVALID)
            {
                refundDestination = destination;
            }

            if (memoStr.size() > 512)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo, if specified, must be under 512 characters.");
            }

            // make one output
            CRecipient oneOutput;

            // send a reserve transfer preconvert
            uint32_t flags = CReserveTransfer::VALID;
            if (preConvert)
            {
                flags |= CReserveTransfer::PRECONVERT;
            }
            if (!convertToCurrencyID.IsNull())
            {
                flags |= CReserveTransfer::CONVERT;
            }
            if (mintNew)
            {
                flags |= CReserveTransfer::MINT_CURRENCY;
                convertToCurrencyID = sourceCurrencyID;
                convertToCurrencyDef = sourceCurrencyDef;
            }

            // are we a system/chain transfer with or without conversion?
            if (destSystemID != thisChainID)
            {
                CCcontract_info CC;
                CCcontract_info *cp;
                cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                if (preConvert)
                {
                    if (convertToCurrencyID.IsNull())
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot preconvert to unspecified or invalid currency.");
                    }
                    CCurrencyValueMap validConversionCurrencies = CCurrencyValueMap(convertToCurrencyDef.currencies, 
                                                                                    std::vector<CAmount>(convertToCurrencyDef.currencies.size()));
                    if (!validConversionCurrencies.valueMap.count(sourceCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ".");
                    }
                    if (convertToCurrencyDef.startBlock <= (height + 1))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                    }

                    CReserveTransfer rt = CReserveTransfer(flags, 
                                                           sourceCurrencyID, 
                                                           sourceAmount,
                                                           0,
                                                           convertToCurrencyID,
                                                           DestinationToTransferDestination(destination));
                    rt.nFees = rt.CalculateTransferFee();

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID(), refundDestination});
                    std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), CKeyID(destSystemID)});

                    oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + rt.CalculateTransferFee() : 0;
                    oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);
                }
                // only valid conversion for a cross-chain send is to the native currency of the chain
                else if (convertToCurrencyID == destSystemID)
                {
                    flags |= CReserveTransfer::CONVERT;
                    // native currency must be the currency we are converting to, and the source must be a reserve
                    auto reserveMap = convertToCurrencyDef.GetCurrenciesMap();
                    if (!reserveMap.count(sourceCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 3");
                    }
                    // converting from reserve to a fractional of that reserve
                    auto dest = DestinationToTransferDestination(destination);
                    auto fees = CReserveTransfer::CalculateTransferFee(dest);
                    CReserveTransfer rt = CReserveTransfer(flags,
                                                           sourceCurrencyID, 
                                                           sourceAmount, 
                                                           fees, 
                                                           convertToCurrencyID, 
                                                           dest);

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID(), refundDestination});
                    std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), CKeyID(destSystemID)});

                    oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + fees : fees;
                    oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);
                }
                else if (convertToCurrencyID.IsNull())
                {
                    auto dest = DestinationToTransferDestination(destination);
                    auto fees = CReserveTransfer::CalculateTransferFee(dest);
                    CReserveTransfer rt = CReserveTransfer(flags,
                                                           sourceCurrencyID, 
                                                           sourceAmount, 
                                                           fees, 
                                                           sourceCurrencyID, 
                                                           dest);

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID(), refundDestination});
                    std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), CKeyID(destSystemID)});

                    oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + fees : fees;
                    oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);
                }
            }
            // a currency conversion without transfer?
            else if (!convertToCurrencyID.IsNull())
            {
                // if pre-converting to a token, it must be a non-reserve preconvert.
                // if we pre-convert for a new chain launch, which is required for a reserve, it will not be as a token
                if (convertToCurrencyDef.IsToken() && preConvert)
                {
                    if (convertToCurrencyDef.startBlock <= (height + 1))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Too late to convert " + sourceCurrencyDef.name + " to " + convertToStr + ", as pre-launch is over.");
                    }

                    CCurrencyValueMap validConversionCurrencies = CCurrencyValueMap(convertToCurrencyDef.currencies, 
                                                                                    std::vector<CAmount>(convertToCurrencyDef.currencies.size()));
                    if (!validConversionCurrencies.valueMap.count(sourceCurrencyID))
                    {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 1");
                    }

                    CCcontract_info CC;
                    CCcontract_info *cp;
                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID(), refundDestination});
                    std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), 
                                                                                            CKeyID(convertToCurrencyID)});

                    CReserveTransfer rt = CReserveTransfer(flags, 
                                                            sourceCurrencyID, 
                                                            sourceAmount,
                                                            0,
                                                            convertToCurrencyID,
                                                            DestinationToTransferDestination(destination));
                    rt.nFees = rt.CalculateTransferFee();
                    oneOutput.nAmount = (sourceCurrencyID == thisChainID) ? sourceAmount + rt.nFees : 0;
                    oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);
                }
                else if (!preConvert &&
                         (mintNew ||
                          (toFractional = convertToCurrencyDef.IsFractional() && convertToCurrencyDef.GetCurrenciesMap().count(sourceCurrencyID)) ||
                          (sourceCurrencyDef.IsFractional() && sourceCurrencyDef.GetCurrenciesMap().count(convertToCurrencyID))))
                {
                    // the following cases end up here:
                    //   1. we are minting currency
                    //   2. we are converting from a fractional currency to its reserve or back

                    CCcontract_info CC;
                    CCcontract_info *cp;
                    cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                    CPubKey pk = CPubKey(ParseHex(CC.CChexstr));
                    if (mintNew)
                    {
                        // we onnly allow minting of tokens right now
                        // TODO: support centralized minting of native AND fractional currency
                        // minting of fractional currency should emit coins without changing price by
                        // adjusting reserve ratio
                        if (!convertToCurrencyDef.IsToken() || convertToCurrencyDef.IsFractional())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot mint native or fractional currency " + convertToCurrencyDef.name);
                        }
                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});
                        std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), 
                                                                                                CKeyID(sourceCurrencyID)});

                        CReserveTransfer rt = CReserveTransfer(flags, 
                                                               thisChainID, 
                                                               sourceAmount,
                                                               0,
                                                               convertToCurrencyID,
                                                               DestinationToTransferDestination(destination));
                        rt.nFees = rt.CalculateTransferFee();
                        oneOutput.nAmount = rt.CalculateTransferFee();
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);
                    }
                    else
                    {
                        // we are only 
                        flags |= CReserveTransfer::CONVERT;

                        // determine the currency that is the fractional currency, whether that is the source
                        // or destination
                        CCurrencyDefinition *pFractionalCurrency = &sourceCurrencyDef;

                        // determine the reserve currency of the destination that we are relevant to,
                        // again, whether source or destination
                        CCurrencyDefinition *pReserveCurrency = &convertToCurrencyDef;

                        // is our destination currency, the conversion destination?
                        if (toFractional)
                        {
                            pReserveCurrency = pFractionalCurrency;
                            pFractionalCurrency = &convertToCurrencyDef;
                        }

                        if (pFractionalCurrency->startBlock > height)
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + " except through preconvert before the startblock has passed.");
                        }

                        auto reserveMap = pFractionalCurrency->GetCurrenciesMap();
                        auto reserveIndexIt = reserveMap.find(pReserveCurrency->GetID());
                        if (reserveIndexIt == reserveMap.end())
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". Must have reserve<->fractional relationship.");
                        }
                        int reserveIndex = reserveIndexIt->second;

                        // converting from reserve to a fractional of that reserve
                        auto dest = DestinationToTransferDestination(destination);
                        auto fees = CReserveTransfer::CalculateTransferFee(dest);

                        // since this is conversion to a reserve token, which must be fungible with Verus, we will take the fee from
                        // source currency, in an amount we calculate to be equivalent to the expected fee amount in Verus + some buffer,
                        // based on the current price, even if that price must be first converted from reserve to token value, then
                        // back to Verus
                        CChainNotarizationData cnd;
                        if (!GetNotarizationData(pFractionalCurrency->GetID(), EVAL_ACCEPTEDNOTARIZATION, cnd))
                        {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to get reserve currency data for " + pFractionalCurrency->name + ".");
                        }

                        CReserveTransfer rt = CReserveTransfer(flags,
                                                               sourceCurrencyID, 
                                                               sourceAmount, 
                                                               fees, 
                                                               convertToCurrencyID, 
                                                               dest);

                        std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID(), refundDestination});
                        std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(thisChain.GetConditionID(EVAL_RESERVE_TRANSFER)), CKeyID(pFractionalCurrency->GetID())});

                        oneOutput.nAmount = sourceCurrencyID == thisChainID ? sourceAmount + fees : 0;
                        oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests);

                        /*
                        // TODO: must be integrated into the functions above
                        if (sourceCurrencyDef.IsFractional())
                        {
                            // native currency must be the currency we are converting to, and the source must be a fractional with that as a reserve
                            auto reserveMap = sourceCurrencyDef.GetCurrenciesMap();
                            if (!reserveMap.count(convertToCurrencyID))
                            {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 3");
                            }
                            // converting from reserve to a fractional of that reserve

                            CReserveExchange re(flags, convertToCurrencyID, sourceAmount);
                            std::vector<CTxDestination> dests = std::vector<CTxDestination>({destination});
                            oneOutput.nAmount = 0;
                            oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CReserveExchange>(EVAL_RESERVE_EXCHANGE, dests, 1, &re));

                        }
                        */
                    }
                }
                else
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot convert " + sourceCurrencyDef.name + " to " + convertToStr + ". 4");
                }
            }
            // or a normal native or reserve output?
            else
            {
                if (sourceCurrencyID == thisChainID)
                {
                    oneOutput.nAmount = sourceAmount;
                    oneOutput.scriptPubKey = GetScriptForDestination(destination);
                }
                else
                {
                    oneOutput.nAmount = 0;

                    std::vector<CTxDestination> dests = std::vector<CTxDestination>({destination});
                    CTokenOutput to(sourceCurrencyID, sourceAmount);

                    oneOutput.scriptPubKey = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
                }
            }
            if (!oneOutput.scriptPubKey.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Failure to make currency output");
            }
            oneOutput.fSubtractFeeFromAmount = subtractFee;
            outputs.push_back(oneOutput);
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameters.");
    }

    // now figure out if we are pulling from a single address or all addresses
    // make, sign, and send or return the transaction
    CTxDestination *pSourceDest = (sourceDest.which() == COptCCParams::ADDRTYPE_INVALID) ? nullptr : &sourceDest;

    CWalletTx wtx;
    CReserveKey reserveKey(pwalletMain);
    CAmount nFeesRet;
    int nChangePosRet, nChangeOutputs;
    std::string failReason;

    UniValue ret;
    if (pwalletMain->CreateReserveTransaction(outputs, wtx, reserveKey, nFeesRet, nChangePosRet, nChangeOutputs, failReason, NULL, pSourceDest, true))
    {
        // now, we either return or commit the transaction
        if (returnTx)
        {
            // keep the change key
            reserveKey.KeepKey();
            ret = UniValue(EncodeHexTx(wtx));
        }
        else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
        {
            UniValue jsonTx(UniValue::VOBJ);
            TxToUniv(wtx, uint256(), jsonTx);
            LogPrintf("%s\n", jsonTx.write(1,2).c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit reserve transaction " + wtx.GetHash().GetHex());
        }
        else
        {
            ret = UniValue(wtx.GetHash().GetHex());
        }
    }
    else
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, failReason);
    }
    return ret;
}

bool GetLastImportIn(uint160 chainID, CTransaction &lastImportTx)
{
    // look for unspent chain transfer outputs for all chains
    CKeyID keyID = CCrossChainRPCData::GetConditionID(chainID, EVAL_CROSSCHAIN_IMPORT);

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    LOCK(cs_main);

    if (!GetAddressUnspent(keyID, 1, unspentOutputs))
    {
        return false;
    }

    for (auto output : unspentOutputs)
    {
        // find the first one that is either in block 1, part of a chain definition transaction, or spends a prior
        // import output in input 0, which cannot be done unless the output is rooted in a valid import thread. anyone can try to send
        // coins to this address without being part of the chain, but they will be wasted and unspendable.
        COptCCParams p;
        if (output.second.script.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_IMPORT)
        {
            // we actually don't care what is in the transaction here, only that it is a valid cross chain import tx
            // that is either the first in a chain or spends a valid cross chain import output
            CCrossChainImport cci(p.vData[0]);
            CTransaction lastTx;
            uint256 blkHash;
            if (cci.IsValid() && myGetTransaction(output.first.txhash, lastTx, blkHash))
            {
                if (output.second.blockHeight == 1 && lastTx.IsCoinBase())
                {
                    lastImportTx = lastTx;
                    return true;
                }
                else
                {
                    if (IsVerusActive())
                    {
                        // if this is the Verus chain, then we need to either be part of a chain definition transaction
                        // or spend a valid import output
                        std::vector<CCurrencyDefinition> definedChains = CCurrencyDefinition::GetCurrencyDefinitions(lastTx);
                        if (definedChains.size() == 1 && definedChains[0].IsValid())
                        {
                            lastImportTx = lastTx;
                            return true;
                        }
                        // if we get here, we must spend a valid import output
                        CTransaction inputTx;
                        uint256 inputBlkHash;
                        if (lastTx.vin.size() && myGetTransaction(lastTx.vin[0].prevout.hash, inputTx, inputBlkHash) && CCrossChainImport(lastTx).IsValid())
                        {
                            lastImportTx = lastTx;
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

UniValue getlastimportin(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getlastimportin \"fromname\"\n"
            "\nThis returns the last import transaction from the chain specified and a blank transaction template to use when making new\n"
            "\nimport transactions. Since the typical use for this call is to make new import transactions from the other chain that will be then\n"
            "\nbroadcast to this chain, we include the template by default.\n"

            "\nArguments\n"
            "   \"fromname\"                (string, required) name of the chain to get the last import transaction in from\n"

            "\nResult:\n"
            "   {\n"
            "       \"lastimporttransaction\": \"hex\"      Hex encoded serialized import transaction\n"
            "       \"lastconfirmednotarization\" : \"hex\" Hex encoded last confirmed notarization transaction\n"
            "       \"importtxtemplate\": \"hex\"           Hex encoded import template for new import transactions\n"
            "       \"nativeimportavailable\": \"amount\"   Total amount of native import currency available to import as native\n"
            "       \"tokenimportavailable\": \"array\"     ([{\"currencyid\":amount},..], required) tokens available to import, if controlled by this chain\n"
            "   }\n"

            "\nExamples:\n"
            + HelpExampleCli("getlastimportin", "jsondefinition")
            + HelpExampleRpc("getlastimportin", "jsondefinition")
        );
    }
    // starting from that last transaction id, see if we have any newer to export for the indicated chain, and if so, return them as
    // import transactions using the importtxtemplate as a template
    CheckPBaaSAPIsValid();

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    CTransaction lastImportTx, lastConfirmedTx;

    CChainNotarizationData cnd;
    std::vector<std::pair<CTransaction, uint256>> txesOut;

    {
        LOCK2(cs_main, mempool.cs);

        if (!GetNotarizationData(chainID, IsVerusActive() ? EVAL_ACCEPTEDNOTARIZATION : EVAL_EARNEDNOTARIZATION, cnd, &txesOut))
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No chain notarizations for " + uni_get_str(params[0]) + " found");
        }
    }

    UniValue ret(UniValue::VNULL);

    if (cnd.IsConfirmed())
    {
        lastConfirmedTx = txesOut[cnd.lastConfirmed].first;
        if (GetLastImportIn(chainID, lastImportTx))
        {
            ret = UniValue(UniValue::VOBJ);
            CMutableTransaction txTemplate = CreateNewContextualCMutableTransaction(Params().GetConsensus(), chainActive.Height());
            // find the import output
            COptCCParams p;
            int importIdx;
            for (importIdx = 0; importIdx < lastImportTx.vout.size(); importIdx++)
            {
                if (lastImportTx.vout[importIdx].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_IMPORT)
                {
                    break;
                }
            }
            if (importIdx >= lastImportTx.vout.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid lastImport transaction");
            }

            txTemplate.vin.push_back(CTxIn(lastImportTx.GetHash(), importIdx, CScript()));

            // if Verus is active, our template import will gather all RESERVE_DEPOSITS that it can to spend into the
            // import thread
            if (IsVerusActive())
            {
                std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> reserveDeposits;

                LOCK2(cs_main, mempool.cs);

                if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(chainID, EVAL_RESERVE_DEPOSIT)), 1, reserveDeposits))
                {
                    for (auto deposit : reserveDeposits)
                    {
                        COptCCParams p;
                        if (deposit.second.script.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_RESERVE_DEPOSIT)
                        {
                            txTemplate.vin.push_back(CTxIn(deposit.first.txhash, deposit.first.index, CScript()));
                        }
                    }
                }
            }

            CCoinsViewCache view(pcoinsTip);
            int64_t dummyInterest;
            CAmount totalImportAvailable = view.GetValueIn(cnd.vtx[cnd.lastConfirmed].second.notarizationHeight, &dummyInterest, txTemplate);
            CCurrencyValueMap reserveImportAvailable = view.GetReserveValueIn(cnd.vtx[cnd.lastConfirmed].second.notarizationHeight, txTemplate);

            ret.push_back(Pair("lastimporttransaction", EncodeHexTx(lastImportTx)));
            ret.push_back(Pair("lastconfirmednotarization", EncodeHexTx(lastConfirmedTx)));
            ret.push_back(Pair("importtxtemplate", EncodeHexTx(txTemplate)));
            ret.push_back(Pair("nativeimportavailable", totalImportAvailable));
            ret.push_back(Pair("tokenimportavailable", reserveImportAvailable.ToUniValue()));
        }
    }
    return ret;
}

UniValue getlatestimportsout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getlatestimportsout \"name\" \"lastimporttransaction\" \"importtxtemplate\"\n"
            "\nThis creates and returns all new imports for the specified chain that are exported from this blockchain.\n"

            "\nArguments\n"
            "{\n"
            "   \"name\" : \"string\"                   (string, required) name of the chain to get the export transactions for\n"
            "   \"lastimporttransaction\" : \"hex\"     (hex,    required) the last import transaction to follow, return list starts with import that spends this\n"
            "   \"lastconfirmednotarization\" : \"hex\" (hex,    required) the last confirmed notarization transaction\n"
            "   \"importtxtemplate\" : \"hex\"          (hex,    required) template transaction to use, so we create a transaction compatible with the other chain\n"
            "   \"nativeimportavailable\": \"amount\"   (number, required) Total amount of native import currency available to import as native\n"
            "   \"tokenimportavailable\": \"array\"     ([{\"currencyid\":amount},..], required) tokens available to import, if controlled by this chain\n"
            "}\n"

            "\nResult:\n"
            "UniValue array of hex transactions"

            "\nExamples:\n"
            + HelpExampleCli("getlatestimportsout", "jsonargs")
            + HelpExampleRpc("getlatestimportsout", "jsonargs")
        );
    }

    UniValue ret(UniValue::VARR);

    // starting from that last transaction id, see if we have any newer to export for the indicated chain, and if so, return them as
    // import transactions using the importtxtemplate as a template
    CheckPBaaSAPIsValid();

    bool isVerusActive = IsVerusActive();

    uint160 chainID = GetChainIDFromParam(find_value(params[0], "name"));

    if (chainID.IsNull())
    {
        return ret;
    }

    // starting from that last transaction id, see if we have any newer to export for the indicated chain, and if so, return them as
    // import transactions using the importtxtemplate as a template
    CCurrencyDefinition chainDef;

    if (!GetCurrencyDefinition(chainID, chainDef))
    {
        return ret;
    }

    std::string lastImportHex = uni_get_str(find_value(params[0], "lastimporttx"));
    CTransaction lastImportTx;

    std::string templateTxHex = uni_get_str(find_value(params[0], "importtxtemplate"));
    CTransaction templateTx;

    std::string lastConfirmedTxHex = uni_get_str(find_value(params[0], "lastconfirmednotarization"));
    CTransaction lastConfirmedNotarization;

    CAmount nativeImportAvailable = uni_get_int64(find_value(params[0], "nativeimportavailable"));
    CCurrencyValueMap tokenImportAvailable(find_value(params[0], "tokenimportavailable"));

    std::vector<CBaseChainObject *> chainObjs;
    std::vector<CCurrencyDefinition> curDefs = CCurrencyDefinition::GetCurrencyDefinitions(lastImportTx);
    if (!(DecodeHexTx(lastImportTx, lastImportHex) && 
          DecodeHexTx(templateTx, templateTxHex) &&
          DecodeHexTx(lastConfirmedNotarization, lastConfirmedTxHex) &&
          CCrossChainImport(lastImportTx).IsValid() &&
          (curDefs.size() && curDefs[0].IsValid() ||
          (lastImportTx.vout.back().scriptPubKey.IsOpReturn() &&
          (chainObjs = RetrieveOpRetArray(lastImportTx.vout.back().scriptPubKey)).size() == 1 &&
          chainObjs[0]->objectType == CHAINOBJ_CROSSCHAINPROOF))))
    {
        DeleteOpRetObjects(chainObjs);
        return ret;
    }

    //UniValue txUniv(UniValue::VOBJ);
    //TxToUniv(lastImportTx, uint256(), txUniv);
    //printf("lastImportTx%s\n", txUniv.write(1,2).c_str());

    DeleteOpRetObjects(chainObjs);

    std::vector<CTransaction> newImports;
    if (!ConnectedChains.CreateLatestImports(chainDef, lastImportTx, templateTx, lastConfirmedNotarization, tokenImportAvailable, nativeImportAvailable, newImports))
    {
        return ret;
    }

    for (auto import : newImports)
    {
        ret.push_back(EncodeHexTx(import));
    }
    return ret;
}

// refunds a failed launch if it is eligible and not already refunded. if it fails to refund, it returns false
// and a string with the reason for failure
bool RefundFailedLaunch(uint160 currencyID, CTransaction &lastImportTx, std::vector<CTransaction> &newRefunds, std::string &errorReason)
{
    int32_t defHeight = 0;
    CCurrencyDefinition chainDef;
    CTransaction chainDefTx;
    uint160 thisChainID = ConnectedChains.ThisChain().GetID();

    LOCK2(cs_main, mempool.cs);

    if (!GetCurrencyDefinition(currencyID, chainDef, &defHeight) || currencyID == thisChainID)
    {
        errorReason = "currency-not-found-or-ineligible";
        return false;
    }

    if (!GetLastImportIn(chainDef.IsToken() ? chainDef.GetID() : chainDef.systemID, lastImportTx))
    {
        errorReason = "no-import-thread-found";
        return false;
    }

    std::vector<CBaseChainObject *> chainObjs;
    CPartialTransactionProof lastExportTxProof;

    // either a fully valid import with an export or the first import either in block 1 or chain definition
    // on the Verus chain
    std::vector<CCurrencyDefinition> curDefs = CCurrencyDefinition::GetCurrencyDefinitions(lastImportTx);
    if (!(lastImportTx.vout.back().scriptPubKey.IsOpReturn() &&
          (chainObjs = RetrieveOpRetArray(lastImportTx.vout.back().scriptPubKey)).size() >= 1 &&
          chainObjs[0]->objectType == CHAINOBJ_TRANSACTION_PROOF &&
          !(lastExportTxProof = ((CChainObject<CPartialTransactionProof> *)(chainObjs[0]))->object).txProof.proofSequence.size() < 3) &&
          !(chainObjs.size() == 0 && curDefs.size() && curDefs[0].IsValid()))
    {
        DeleteOpRetObjects(chainObjs);
        errorReason = "invalid-import-thread-found";
        return false;
    }

    DeleteOpRetObjects(chainObjs);

    bool isVerusActive = IsVerusActive();

    uint256 lastExportHash;
    CTransaction lastExportTx;

    uint32_t blkHeight = defHeight;
    bool found = false;

    if (lastExportTxProof.txProof.proofSequence.size())
    {
        lastExportHash = lastExportTxProof.TransactionHash();
        CTransaction tx;
        uint256 blkHash;
        BlockMap::iterator blkMapIt;
        if (myGetTransaction(lastExportHash, tx, blkHash) &&
            (blkMapIt = mapBlockIndex.find(blkHash)) != mapBlockIndex.end() && 
            blkMapIt->second)
        {
            found = true;
            blkHeight = blkMapIt->second->GetHeight();
        }
    }
    else
    {
        // if we haven't processed any imports/refunds yet, setup to payout from the first export and continue
        CCrossChainExport ccx(lastImportTx);
        if (ccx.IsValid())
        {
            found = true;
            lastExportTx = lastImportTx;
            lastExportHash = lastImportTx.GetHash();
        }
    }

    if (!found)
    {
        LogPrintf("%s: No export thread found\n", __func__);
        //printf("%s: No export thread found\n", __func__);
        return false;
    }

    // we need to get the last import transaction and handle refunds like exports without conversion or
    // launch fees, so we can make incremental progress if necessary and know when there are none left
    int32_t nHeight = chainActive.Height();

    // make sure the chain is qualified for a refund
    CCurrencyValueMap minPreMap, preConvertedMap;
    CCoinbaseCurrencyState currencyState = GetInitialCurrencyState(chainDef);
    if (!(chainDef.minPreconvert.size() &&
        (minPreMap = CCurrencyValueMap(chainDef.currencies, chainDef.minPreconvert)) > preConvertedMap &&
        chainDef.startBlock < nHeight && 
        (preConvertedMap = CCurrencyValueMap(chainDef.currencies, currencyState.reserveIn)) < minPreMap))
    {
        errorReason = "chain-ineligible";
        return false;
    }
    else
    {
        // convert exports & conversions intended for the failed currency into imports back to this chain that spend from the import thread
        // all reservetransfers are refunded and charged 1/2 of an export fee
        uint160 chainID = chainDef.systemID;

        std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

        // get all exports for the chain
        CKeyID keyID = CCrossChainRPCData::GetConditionID(chainID, EVAL_CROSSCHAIN_EXPORT);

        CBlockIndex *pIndex;

        // get all export transactions that were posted to the chain, since none can be sent
        // TODO:PBAAS - all sends to a failed chain after start block should fail. this may not want to
        // refund all exports, in case we decide to reuse chain names
        if (GetAddressIndex(keyID, 1, addressIndex, defHeight, nHeight))
        {
            // get all exports from first to last, and make sure they spend from the export thread consecutively
            bool found = false;
            uint256 lastHash = lastExportHash;

            // indexed by input hash
            std::map<uint256, std::pair<CAddressIndexKey, CTransaction>> validExports;

            // validate, order, and relate them with their inputs
            for (auto utxo : addressIndex)
            {
                // if current tx spends lastHash, then we have our next valid transaction to create an import with
                CTransaction tx, inputtx;
                uint256 blkHash1, blkHash2;
                BlockMap::iterator blkIt;
                CCrossChainExport ccx;
                COptCCParams p;
                if (!utxo.first.spending &&
                    !(utxo.first.txhash == lastExportHash) &&
                    myGetTransaction(utxo.first.txhash, tx, blkHash1) &&
                    (ccx = CCrossChainExport(tx)).IsValid() &&
                    ccx.numInputs &&
                    (!tx.IsCoinBase() && 
                    tx.vin.size() && 
                    myGetTransaction(tx.vin[0].prevout.hash, inputtx, blkHash2)) &&
                    inputtx.vout[tx.vin[0].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && 
                    p.IsValid() && 
                    p.evalCode == EVAL_CROSSCHAIN_EXPORT)
                {
                    validExports.insert(make_pair(tx.vin[0].prevout.hash, make_pair(utxo.first, tx)));
                }
            }

            CTransaction lastImport(lastImportTx);
            CCrossChainImport lastCCI;

            for (auto aixIt = validExports.find(lastExportHash); 
                aixIt != validExports.end(); 
                aixIt = validExports.find(lastExportHash))
            {
                // One pass - create an import transaction that spends the last import transaction from a confirmed export transaction that spends the last one of those
                // 1. Creates preconvert outputs that spend from the initial supply, which comes from the import transaction thread without fees
                // 2. Creates reserve outputs for unconverted imports
                // 3. Creates reserveExchange transactions requesting conversion at market for convert transfers
                // 4. Creates reserveTransfer outputs for outputs with the SEND_BACK flag set, unless they are under 5x the normal network fee
                // 5. Creates a pass-through EVAL_CROSSCHAIN_IMPORT output with the remainder of the non-preconverted coins
                // then signs the transaction considers it the latest import and the new export the latest export and
                // loops until there are no more confirmed, consecutive, valid export transactions to export

                // aixIt has an input from the export thread of last transaction, an optional deposit to the reserve, and an opret of all outputs + 1 fee
                assert(aixIt->second.second.vout.back().scriptPubKey.IsOpReturn());

                int32_t lastImportPrevoutN = 0, lastExportPrevoutN = 0;
                lastCCI = CCrossChainImport();
                COptCCParams p;

                for (int i = 0; i < lastImport.vout.size(); i++)
                {
                    if (lastImport.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_IMPORT && p.vData.size() && (lastCCI = CCrossChainImport(p.vData[0])).IsValid())
                    {
                        lastImportPrevoutN = i;
                        break;
                    }
                }

                int32_t ccxOutputNum = 0;
                CCrossChainExport ccx(aixIt->second.second, &ccxOutputNum);
                if (!lastCCI.IsValid() || !ccx.IsValid())
                {
                    LogPrintf("%s: POSSIBLE CORRUPTION bad import/export data in transaction %s (import) or %s (export)\n", __func__, lastImport.GetHash().GetHex().c_str(), aixIt->first.GetHex().c_str());
                    printf("%s: POSSIBLE CORRUPTION bad import/export data transaction %s (import) or %s (export)\n", __func__, lastImport.GetHash().GetHex().c_str(), aixIt->first.GetHex().c_str());
                    return false;
                }

                CMutableTransaction newImportTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);
                newImportTx.vin.push_back(CTxIn(lastImport.GetHash(), lastImportPrevoutN));

                // if no prepared input, make one
                newImportTx.vout.clear();
                newImportTx.vout.push_back(CTxOut()); // placeholder for the first output

                // we need to recalculate fees, as there will be no conversions

                CReserveTransactionDescriptor rtxd;

                std::vector<CBaseChainObject *> exportOutputs = RetrieveOpRetArray(aixIt->second.second.vout.back().scriptPubKey);

                // loop through and recalculate every transfer to charge a normal transfer fee and be a normal output
                // recalculate the fee output amount to be based on the new export fee calculation after canceling conversions
                ccx.totalFees = CCurrencyValueMap();

                CCurrencyValueMap feeMap;
                bool inFeeOutputs = false;

                for (auto &objPtr : exportOutputs)
                {
                    if (objPtr->objectType == CHAINOBJ_RESERVETRANSFER)
                    {
                        CReserveTransfer &rt = ((CChainObject<CReserveTransfer> *)objPtr)->object;

                        // convert full ID destinations to normal ID outputs, since it's refund, full ID will be on this chain already
                        if (rt.destination.type == CTransferDestination::DEST_FULLID)
                        {
                            CIdentity(rt.destination.destination);
                            rt.destination = CTransferDestination(CTransferDestination::DEST_ID, rt.destination.destination);
                        }

                        // turn it into a normal transfer, which will create an unconverted output
                        rt.flags &= ~(CReserveTransfer::SEND_BACK | CReserveTransfer::PRECONVERT | CReserveTransfer::CONVERT);

                        if (rt.flags & (CReserveTransfer::PREALLOCATE | CReserveTransfer::MINT_CURRENCY))
                        {
                            rt.flags &= ~(CReserveTransfer::PREALLOCATE | CReserveTransfer::MINT_CURRENCY);
                            rt.nValue = 0;
                        }
                        rt.destCurrencyID = rt.currencyID;

                        // once we get to fees, we should have processed all non-fee outputs and be able to accurately calculate fees
                        if (inFeeOutputs || rt.flags & CReserveTransfer::FEE_OUTPUT)
                        {
                            // will be recalculated
                            if (!inFeeOutputs)
                            {
                                inFeeOutputs = true;
                                ccx.totalFees = feeMap;
                                //printf("total fees:\n%s\n", feeMap.ToUniValue().write(1,2).c_str());
                            }
                            rt.nFees = 0;
                            rt.nValue = ccx.CalculateExportFee().valueMap[rt.currencyID];
                            //printf("one fee out:\n%s\n", rt.ToUniValue().write(1,2).c_str());
                        }
                        else
                        {
                            feeMap.valueMap[rt.currencyID] += rt.nFees;
                        }
                    }
                }

                if (!rtxd.AddReserveTransferImportOutputs(ConnectedChains.ThisChain().GetID(),
                                                          chainDef, 
                                                          currencyState,
                                                          exportOutputs, 
                                                          newImportTx.vout))
                {
                    LogPrintf("%s: POSSIBLE CORRUPTION bad export opret in transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                    printf("%s: POSSIBLE CORRUPTION bad export opret in transaction %s\n", __func__, aixIt->second.second.GetHash().GetHex().c_str());
                    // free the memory
                    DeleteOpRetObjects(exportOutputs);
                    return false;
                }

                // free the memory
                DeleteOpRetObjects(exportOutputs);

                // emit a crosschain import output as summary
                CCcontract_info CC;
                CCcontract_info *cpcp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
                CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(ccx.systemID, EVAL_CROSSCHAIN_IMPORT)))});
                std::vector<CTxDestination> dests;

                if (ConnectedChains.ThisChain().proofProtocol == CCurrencyDefinition::PROOF_PBAASMMR ||
                    ConnectedChains.ThisChain().proofProtocol == CCurrencyDefinition::PROOF_CHAINID)
                {
                    dests = std::vector<CTxDestination>({pk});
                }
                else
                {
                    LogPrintf("%s: ERROR - invalid proof protocol\n", __func__);
                    printf("%s: ERROR - invalid proof protocol\n", __func__);
                    return false;
                }

                CCrossChainImport cci = CCrossChainImport(ccx.systemID, CCurrencyValueMap(), CCurrencyValueMap());

                newImportTx.vout[0] = CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci), &indexDests));

                // now add unspent reserve deposit that came from this export as input to return it back to senders, less transfer fees
                // based on consensus rules, this should provide the necessary funds by definition
                uint256 depositTxId = aixIt->second.second.GetHash();
                for (int i = 0; i < aixIt->second.second.vout.size(); i++)
                {
                    COptCCParams p;
                    if (aixIt->second.second.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_RESERVE_DEPOSIT)
                    {
                        newImportTx.vin.push_back(CTxIn(depositTxId, i, CScript()));
                    }
                }

                // add a proof of the export transaction at the notarization height
                CBlock block;
                if (!ReadBlockFromDisk(block, chainActive[aixIt->second.first.blockHeight], Params().GetConsensus(), false))
                {
                    LogPrintf("%s: POSSIBLE CORRUPTION cannot read block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                    printf("%s: POSSIBLE CORRUPTION cannot read block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                    return false;
                }

                // prove ccx input 0, export output, and opret
                std::vector<std::pair<int16_t, int16_t>> parts({{CTransactionHeader::TX_HEADER, (int16_t)0},
                                                                {CTransactionHeader::TX_PREVOUTSEQ, (int16_t)0},
                                                                {CTransactionHeader::TX_OUTPUT, ccxOutputNum},
                                                                {CTransactionHeader::TX_OUTPUT, (int16_t)(aixIt->second.second.vout.size() - 1)}});

                // prove our transaction up to the MMR root of the last transaction
                CPartialTransactionProof exportProof = block.GetPartialTransactionProof(aixIt->second.second, aixIt->second.first.txindex, parts);
                if (!exportProof.components.size())
                {
                    LogPrintf("%s: could not create partial transaction proof in block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                    printf("%s: could not create partial transaction proof in block %s\n", __func__, chainActive[aixIt->second.first.blockHeight]->GetBlockHash().GetHex().c_str());
                    return false;
                }
                exportProof.txProof << block.MMRProofBridge();

                // TODO: don't include chain MMR proof for exports from the same chain
                ChainMerkleMountainView(chainActive.GetMMR(), nHeight).GetProof(exportProof.txProof, aixIt->second.first.blockHeight);

                CChainObject<CPartialTransactionProof> exportXProof(CHAINOBJ_TRANSACTION_PROOF, exportProof);

                // add the opret with the transaction and proof
                newImportTx.vout.push_back(CTxOut(0, StoreOpRetArray(std::vector<CBaseChainObject *>({&exportXProof}))));

                // we now have an Import transaction for the chainID chain, it is the latest, and the export we used is now the latest as well
                // work our way forward
                newRefunds.push_back(newImportTx);
                lastImport = newImportTx;
                lastExportHash = aixIt->second.first.txhash;
            }
        }
        return true;
    }
}

UniValue refundfailedlaunch(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "refundfailedlaunch \"currencyid\"\n"
            "\nRefunds any funds sent to the chain if they are eligible for refund.\n"
            "This attempts to refund all transactions for all contributors.\n"

            "\nArguments\n"
            "\"currencyid\"         (iaddress or full chain name, required)   the chain to refund contributions to\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("refundfailedlaunch", "\"currencyid\"")
            + HelpExampleRpc("refundfailedlaunch", "\"currencyid\"")
        );
    }
    CheckPBaaSAPIsValid();

    uint160 chainID;

    chainID = GetChainIDFromParam(params[0]);
    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid PBaaS name or currencyid");
    }

    if (chainID == ConnectedChains.ThisChain().GetID() || chainID == ConnectedChains.NotaryChain().chainDefinition.GetID())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot refund the specified chain");
    }

    CTransaction lastImportTx;
    std::vector<CTransaction> refundTxes;
    std::string failReason;

    if (!RefundFailedLaunch(chainID, lastImportTx, refundTxes, failReason))
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, failReason);
    }

    uint32_t consensusBranchId = CurrentEpochBranchId(chainActive.LastTip()->GetHeight(), Params().GetConsensus());

    UniValue ret(UniValue::VARR);

    CCoinsViewCache view(pcoinsTip);

    // sign and commit the transactions
    for (auto tx : refundTxes)
    {
        LOCK2(cs_main, mempool.cs);

        CMutableTransaction newTx(tx);

        // sign the transaction and submit
        bool signSuccess;
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
                CCoinsViewCache view(pcoinsTip);
                CCoins coins;
                if (!view.GetCoins(tx.vin[i].prevout.hash, coins))
                {
                    fprintf(stderr,"refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    LogPrintf("refundfailedlaunch: cannot get input coins from tx: %s, output: %d\n", tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
                    break;
                }
                value = coins.vout[tx.vin[i].prevout.n].nValue;
                outputScript = coins.vout[tx.vin[i].prevout.n].scriptPubKey;
            }

            signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &tx, i, value, SIGHASH_ALL), outputScript, sigdata, consensusBranchId);

            if (!signSuccess)
            {
                fprintf(stderr,"refundfailedlaunch: failure to sign refund transaction\n");
                LogPrintf("refundfailedlaunch: failure to sign refund transaction\n");
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
            if (!AcceptToMemoryPool(mempool, state, signedTx, false, &fMissingInputs)) {
                if (state.IsInvalid()) {
                    fprintf(stderr,"refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                    LogPrintf("refundfailedlaunch: rejected by memory pool for %s\n", state.GetRejectReason().c_str());
                } else {
                    if (fMissingInputs) {
                        fprintf(stderr,"refundfailedlaunch: missing inputs\n");
                        LogPrintf("refundfailedlaunch: missing inputs\n");
                    }
                    else
                    {
                        fprintf(stderr,"refundfailedlaunch: rejected by memory pool for\n");
                        LogPrintf("refundfailedlaunch: rejected by memory pool for\n");
                    }
                }
                break;
            }
            else
            {
                RelayTransaction(signedTx);
                ret.push_back(signedTx.GetHash().GetHex());
            }
        }
    }
    return ret;
}

UniValue getinitialcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getinitialcurrencystate \"name\"\n"
            "\nReturns the total amount of preconversions that have been confirmed on the blockchain for the specified PBaaS chain.\n"
            "This should be used to get information about chains that are not this chain, but are being launched by it.\n"

            "\nArguments\n"
            "   \"name\"                    (string, required) name or chain ID of the chain to get the export transactions for\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"flags\" : n,\n"
            "           \"initialratio\" : n,\n"
            "           \"initialsupply\" : n,\n"
            "           \"emitted\" : n,\n"
            "           \"supply\" : n,\n"
            "           \"reserve\" : n,\n"
            "           \"currentratio\" : n,\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getinitialcurrencystate", "name")
            + HelpExampleRpc("getinitialcurrencystate", "name")
        );
    }
    CheckPBaaSAPIsValid();

    uint160 chainID = GetChainIDFromParam(params[0]);

    if (chainID.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid chain name or chain ID");
    }

    LOCK(cs_main);

    CCurrencyDefinition chainDef;
    int32_t definitionHeight;
    if (!GetCurrencyDefinition(chainID, chainDef, &definitionHeight))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Chain " + params[0].get_str() + " not found");
    }

    // get accurate preconversions
    CCurrencyValueMap fees;
    chainDef.preconverted = CalculatePreconversions(chainDef, definitionHeight, fees).AsCurrencyVector(chainDef.currencies);
    return GetInitialCurrencyState(chainDef).ToUniValue();
}

UniValue getcurrencystate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "getcurrencystate \"n\"\n"
            "\nReturns the total amount of preconversions that have been confirmed on the blockchain for the specified chain.\n"

            "\nArguments\n"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the currency state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"

            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"height\": n,\n"
            "           \"blocktime\": n,\n"
            "           \"currencystate\": {\n"
            "               \"flags\" : n,\n"
            "               \"initialratio\" : n,\n"
            "               \"initialsupply\" : n,\n"
            "               \"emitted\" : n,\n"
            "               \"supply\" : n,\n"
            "               \"reserve\" : n,\n"
            "               \"currentratio\" : n,\n"
            "           \"}\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getcurrencystate", "name")
            + HelpExampleRpc("getcurrencystate", "name")
        );
    }
    CheckPBaaSAPIsValid();

    uint64_t lStart;
    uint64_t startEnd[3] = {0};

    lStart = startEnd[1] = startEnd[0] = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 1;

    if (params.size() == 1)
    {
        if (uni_get_int(params[0], -1) == -1 && params[0].isStr())
        {
            Split(params[0].get_str(), startEnd, startEnd[0], 3);
        }
    }

    if (startEnd[0] > startEnd[1])
    {
        startEnd[0] = startEnd[1];
    }

    if (startEnd[1] > lStart)
    {
        startEnd[1] = lStart;
    }

    if (startEnd[1] < startEnd[0])
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
    }

    if (startEnd[2] == 0)
    {
        startEnd[2] = 1;
    }

    if (startEnd[2] > INT_MAX)
    {
        startEnd[2] = INT_MAX;
    }

    uint32_t start = startEnd[0], end = startEnd[1], step = startEnd[2];

    UniValue ret(UniValue::VARR);

    for (int i = start; i <= end; i += step)
    {
        CCoinbaseCurrencyState currencyState = ConnectedChains.GetCurrencyState(i);
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("height", i));
        entry.push_back(Pair("blocktime", (uint64_t)chainActive.LastTip()->nTime));
        CAmount price;
        entry.push_back(Pair("currencystate", currencyState.ToUniValue()));
        ret.push_back(entry);
    }
    return ret;
}

UniValue getsaplingtree(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
            "getsaplingtree \"n\"\n"
            "\nReturns the entries for a light wallet Sapling tree state.\n"

            "\nArguments\n"
            "   \"n\" or \"m,n\" or \"m,n,o\"         (int or string, optional) height or inclusive range with optional step at which to get the Sapling tree state\n"
            "                                                                   If not specified, the latest currency state and height is returned\n"
            "\nResult:\n"
            "   [\n"
            "       {\n"
            "           \"network\": \"VRSC\",\n"
            "           \"height\": n,\n"
            "           \"hash\": \"hex\"\n"
            "           \"time\": n,\n"
            "           \"tree\": \"hex\"\n"
            "       },\n"
            "   ]\n"

            "\nExamples:\n"
            + HelpExampleCli("getsaplingtree", "name")
            + HelpExampleRpc("getsaplingtree", "name")
        );
    }

    uint64_t lStart;
    uint64_t startEnd[3] = {0};

    lStart = startEnd[1] = startEnd[0] = chainActive.LastTip() ? chainActive.LastTip()->GetHeight() : 1;

    if (params.size() == 1)
    {
        if (uni_get_int(params[0], -1) == -1 && params[0].isStr())
        {
            Split(params[0].get_str(), startEnd, startEnd[0], 3);
        }
    }

    if (startEnd[0] > startEnd[1])
    {
        startEnd[0] = startEnd[1];
    }

    if (startEnd[1] > lStart)
    {
        startEnd[1] = lStart;
    }

    if (startEnd[1] < startEnd[0])
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range for currency state");
    }

    if (startEnd[2] == 0)
    {
        startEnd[2] = 1;
    }

    if (startEnd[2] > INT_MAX)
    {
        startEnd[2] = INT_MAX;
    }

    uint32_t start = startEnd[0], end = startEnd[1], step = startEnd[2];

    UniValue ret(UniValue::VARR);

    LOCK(cs_main);
    CCoinsViewCache view(pcoinsTip);
    SaplingMerkleTree tree;

    for (int i = start; i <= end; i += step)
    {
        CBlockIndex &blkIndex = *(chainActive[i]);
        if (view.GetSaplingAnchorAt(blkIndex.hashFinalSaplingRoot, tree))
        {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("network", ConnectedChains.ThisChain().name));
            entry.push_back(Pair("height", blkIndex.GetHeight()));
            entry.push_back(Pair("hash", blkIndex.GetBlockHash().GetHex()));
            entry.push_back(Pair("time", (uint64_t)chainActive.LastTip()->nTime));
            std::vector<unsigned char> treeBytes = ::AsVector(tree);
            entry.push_back(Pair("tree", HexBytes(treeBytes.data(), treeBytes.size())));
            ret.push_back(entry);
        }
    }
    return ret;
}

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);

UniValue definecurrency(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "definecurrency '{\"name\": \"BAAS\", ..., \"nodes\":[{\"networkaddress\":\"identity\"},..]}'\n"
            "\nThis defines a blockchain currency, either as an independent blockchain, or as a token on this blockchain. It also spends\n"
            "the identity after which this currency is named and sets a bit indicating that it has a currently active blockchain in its name.\n"
            "\nTo create a currency of any kind, the identity it is named after must be minted on the blockchain on which the currency is created.\n"
            "Once a currency is activated for an identity name, the same symbol may not be reused for another currency or blockchain, even\n"
            "if the identity is transferred, revoked or recovered, unless there is an endblock specified and the currency or blockchain has\n"
            "deactivated as of that end block.\n"
            "\nAll funds to start the currency and for initial conversion amounts must be available to spend from the identity with the same\n"
            "name and ID as the currency being defined.\n"
            "\nArguments\n"
            "      {\n"
            "         \"options\" : \"n\",             (int,    optional) bits:\n"
            "                                                             1 = FRACTIONAL, 2 = IDRESTRICTED, 4 = IDSTAKING, 8 = IDREFERRALS\n"
            "                                                             0x10 = IDREFERRALSREQUIRED, 0x20 = TOKEN, 0x40 = CANBERESERVE\n"
            "         \"name\" : \"xxxx\",             (string, required) name of existing identity with no active or pending blockchain\n"
            "         \"idregistrationprice\" : \"xx.xx\", (value, required) price of an identity in native currency\n"
            "         \"idreferrallevels\" : \"n\",    (int, required) how many levels ID referrals go back in reward\n"

            "         \"notaries\" : \"[identity,..]\", (list, optional) list of identities that are assigned as chain notaries\n"
            "         \"minnotariesconfirm\" : \"n\",  (int, optional) unique notary signatures required to confirm an auto-notarization\n"
            "         \"notarizationreward\" : \"xx.xx\", (value,  required) default VRSC notarization reward total for first billing period\n"
            "         \"billingperiod\" : \"n\",       (int,    optional) number of blocks in each billing period\n"
            "         \"proofprotocol\" : \"n\",       (int,    optional) if 2, currency can be minted by whoever controls the ID\n"

            "         \"startblock\"   : \"n\",        (int,    optional) VRSC block must be notarized into block 1 of PBaaS chain, default curheight + 100\n"
            "         \"endblock\"     : \"n\",        (int,    optional) chain is considered inactive after this block height, and a new one may be started\n"

            "         \"reserveratio\" : \"n\",        (value, optional) total reserve ratio, divided among currencies\n"
            "         \"currencies\" : \"[\"VRSC\",..]\", (list, optional) reserve currencies backing this chain in equal amounts\n"
            "         \"conversions\" : \"[\"xx.xx\",..]\", (list, optional) if present, must be same size as currencies. pre-launch conversion ratio overrides\n"
            "         \"minpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) must be same size as currencies. minimum in each currency to launch\n"
            "         \"maxpreconversion\" : \"[\"xx.xx\",..]\", (list, optional) maximum in each currency allowed\n"

            "         \"preallocationratio\" : \"xx.xx\", (value, optional) if non-0, pre-allocation is a percentage after initial supply is determined\n"
            "         \"preallocation\" : \"[{\"identity\":xx.xx}..]\", (list, optional) amount or % of from pre-allocation, depending on preallocationratio\n"
            "         \"initialcontribution\" : \"[\"xx.xx\",..]\", (list, optional) initial contribution in each currency\n"
    
            "         \"eras\"         : \"objarray\", (array, optional) data specific to each era, maximum 3\n"
            "         {\n"
            "            \"reward\"    : \"n\",       (int64,  optional) native initial block rewards in each period\n"
            "            \"decay\" : \"n\",           (int64,  optional) reward decay for each era\n"
            "            \"halving\"   : \"n\",       (int,    optional) halving period for each era\n"
            "            \"eraend\"    : \"n\",       (int,    optional) ending block of each era\n"
            "         }\n"
            "         \"nodes\"      : \"[obj, ..]\", (objectarray, optional) up to 2 nodes that can be used to connect to the blockchain"
            "         [{\n"
            "            \"networkaddress\" : \"txid\", (string,  optional) internet, TOR, or other supported address for node\n"
            "            \"nodeidentity\" : \"name@\",  (string, optional) rewards payment and identity\n"
            "          }, .. ]\n"
            "      }\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"transactionid\", (string) The transaction id\n"
            "  \"tx\"   : \"json\",          (json)   The transaction decoded as a transaction\n"
            "  \"hex\"  : \"data\"           (string) Raw data for signed transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("definecurrency", "jsondefinition")
            + HelpExampleRpc("definecurrency", "jsondefinition")
        );
    }

    CheckPBaaSAPIsValid();
    bool isVerusActive = IsVerusActive();

    uint160 thisChainID = ConnectedChains.ThisChain().GetID();

    if (!params[0].isObject())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "JSON object required. see help.");
    }
    if (!pwalletMain)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "must have active wallet to define PBaaS chain");
    }

    UniValue valStr(UniValue::VSTR);
    if (!valStr.read(params[0].write()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid characters in blockchain definition");
    }

    CCurrencyDefinition newChain(params[0]);

    if (!newChain.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid currency definition. see help.");
    }

    CCurrencyDefinition checkDef;
    if (GetCurrencyDefinition(newChain.name, checkDef))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, newChain.name + " chain already defined. see help.");
    }

    // a new blockchain can only be defined with the current chain as parent
    if (newChain.parent.IsNull())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, params[0].write() + " invalid chain name.");
    }

    if (newChain.parent != thisChainID)
    {
        // parent chain must be current chain
        throw JSONRPCError(RPC_INVALID_PARAMETER, "attempting to define a chain relative to a parent that is not the current chain.");
    }

    for (auto &oneID : newChain.preAllocation)
    {
        if (!CIdentity::LookupIdentity(CIdentityID(oneID.first)).IsValid())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "attempting to pre-allocate currency to a non-existent ID.");
        }
    }

    uint160 newChainID = newChain.GetID();

    std::vector<CNodeData> vNodes;
    UniValue nodeArr = find_value(params[0], "nodes");
    if (nodeArr.isArray() && nodeArr.size())
    {
        for (int i = 0; i < nodeArr.size(); i++)
        {
            CNodeData nd(nodeArr[i]);
            if (nd.IsValid())
            {
                vNodes.push_back(nd);
                if (vNodes.size() == 2)
                {
                    break;
                }
            }
        }
    }

    // a new currency definition must spend an ID that currently has no active currency, which sets a semaphore that "blocks"
    // that ID from having more than one at once. Before submitting the transaction, it must be properly signed by the primary authority. 
    // This also has the effect of piggybacking on the ID protocol's deconfliction between mined blocks to avoid name conflicts, 
    // as the ID can only have its bit set or unset by one transaction at any time and only as part of a transaction that changes the
    // the state of a potentially active currency.
    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (newChain.IsToken())
    {
        if (newChain.rewards.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "currency cannot be both a token and also specify a mining and staking rewards schedule.");
        }
        // if this is a token definition, the systemID is this chain
        newChain.systemID = ConnectedChains.ThisChain().GetID();
    }
    else
    {
        // it is a PBaaS chain, and it is its own system, responsible for its own communication and currency control
        newChain.systemID = newChainID;
    }

    CIdentity launchIdentity;
    uint32_t height = chainActive.Height();
    uint32_t idHeight = 0;
    CTxIn idTxIn;
    bool canSign = false, canSpend = false;

    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
    if (pwalletMain->GetIdentity(newChainID, keyAndIdentity))
    {
        canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
        canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
        launchIdentity = static_cast<CIdentity>(keyAndIdentity.second);
    }

    if (!(launchIdentity = CIdentity::LookupIdentity(newChainID, 0, &idHeight, &idTxIn)).IsValidUnrevoked() || launchIdentity.HasActiveCurrency())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID " + newChain.name + " not found, is revoked, or already has an active currency defined");
    }

    if (launchIdentity.parent != thisChainID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency can only be defined using an ID issued by " + VERUS_CHAINNAME);
    }

    // refunding a currency after its launch is aborted, or shutting it down after the endblock has passed must be completed
    // to fully decommission a blockchain and clear the active blockchain bit from an ID

    //if (!newChain.startBlock || newChain.startBlock < (chainActive.Height() + PBAAS_MINSTARTBLOCKDELTA))
    //{
    //    newChain.startBlock = chainActive.Height() + (PBAAS_MINSTARTBLOCKDELTA + 5);    // give a little time to send the tx
    //}
    if (!newChain.startBlock || newChain.startBlock < (chainActive.Height() + 10))
    {
        newChain.startBlock = chainActive.Height() + 15;    // give a little time to send the tx
    }

    if (newChain.endBlock && newChain.endBlock < (newChain.startBlock + CCurrencyDefinition::MIN_CURRENCY_LIFE))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "If endblock (" + to_string(newChain.endBlock) + 
                                               ") is specified, it must be at least " + to_string(CCurrencyDefinition::MIN_CURRENCY_LIFE) + 
                                               " blocks after startblock (" + to_string(newChain.startBlock) + ")\n");
    }

    if (!newChain.IsToken())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Current testnet does not support launch of independent PBaaS blockchains. Please use token currencies for now.\n");

        if (newChain.billingPeriod < CCurrencyDefinition::MIN_BILLING_PERIOD || (newChain.notarizationReward / newChain.billingPeriod) < CCurrencyDefinition::MIN_PER_BLOCK_NOTARIZATION)
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Billing period of at least " + 
                                                to_string(CCurrencyDefinition::MIN_BILLING_PERIOD) + 
                                                " blocks and per-block notary rewards of >= " + to_string(CCurrencyDefinition::MIN_PER_BLOCK_NOTARIZATION) + 
                                                " are required to define an active currency\n");
        }

        // TODO: check to see if rewards obviously lead to an unstable currency
        //for (int i = 0; i < newChain.rewards.size(); i++)
        //{
        //}

        // if we have no emission parameters, this is not a PBaaS blockchain, it is a controlled or bridged token.
        // controlled tokens can be centrally or algorithmically controlled.
        if (newChain.rewards.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "A currency must either be based on a token protocol or must specify blockchain rewards, even if 0\n");
        }
    }

    if (newChain.currencies.empty() && newChain.IsFractional())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Fractional reserve currencies must specify at least one reserve currency\n");
    }

    // if this is a fractional reserve currency, ensure that all reserves are currently active 
    // with at least as long of a life as this currency and that at least one of the currencies
    // is VRSC or VRSCTEST.
    std::vector<CCurrencyDefinition> reserveCurrencies;
    bool hasCoreReserve = false;
    if (newChain.IsFractional())
    {
        if (newChain.contributions.size() != newChain.currencies.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserves must have non-zero initial contributions for each reserve for fractional currency " + newChain.name);
        }
        for (int i = 0; i < newChain.contributions.size(); i++)
        {
            if (newChain.contributions[i] <= 0)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserves must have non-zero initial contributions " + EncodeDestination(CKeyID(newChain.currencies[i])));
            }
        }
        newChain.preconverted = newChain.contributions;
        for (auto &currency : newChain.currencies)
        {
            reserveCurrencies.emplace_back();
            if (!GetCurrencyDefinition(currency, reserveCurrencies.back()) ||
                reserveCurrencies.back().startBlock >= height)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "All reserve currencies of a fractional currency must be valid and past the start block " + EncodeDestination(CKeyID(currency)));
            }

            if (reserveCurrencies.back().endBlock && (!newChain.endBlock || reserveCurrencies.back().endBlock < newChain.endBlock))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Reserve currency " + EncodeDestination(CKeyID(currency)) + " ends its life before the fractional currency's endblock");
            }

            if (!reserveCurrencies.back().CanBeReserve())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Currency " + EncodeDestination(CKeyID(currency)) + " may not be used as a reserve");
            }

            if (currency == VERUS_CHAINID)
            {
                hasCoreReserve = true;
            }
        }
        if (!hasCoreReserve)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Fractional currency requires a reserve of " + VERUS_CHAINNAME + " in addition to any other reserves");
        }
    }

    // now, create the outputs:
    // 1. Updated identity with active currency
    // 2. Currency definition
    // 3. Notarization thread
    // 4. Import thread
    // 5. Export thread
    // 6. Initial contribution exports
    // 7. Critical identity exports (chain identity, notaries, pre-allocation recipients)
    //
    // ensure that the appropriate identity is an input to the transaction,
    // and fund the transaction
    std::vector<CRecipient> vOutputs;

    // first, we need the identity output with currency activated
    launchIdentity.ActivateCurrency();
    vOutputs.push_back({launchIdentity.IdentityUpdateOutputScript(), 0, false});

    // now, create the currency definition output
    CCcontract_info CC;
    CCcontract_info *cp;
    cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
    CPubKey pk(ParseHex(CC.CChexstr));

    std::vector<CTxDestination> indexDests({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_CURRENCY_DEFINITION)),
                                            CKeyID(newChain.GetConditionID(EVAL_CURRENCY_DEFINITION))});
    std::vector<CTxDestination> dests({pk});

    vOutputs.push_back({MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &newChain), &indexDests), 
                                         CCurrencyDefinition::DEFAULT_OUTPUT_VALUE, 
                                         false});

    // get initial currency state
    CCoinbaseCurrencyState newCurrencyState = GetInitialCurrencyState(newChain);

    // we need to make a notarization, notarize this information and block 0, which is the same as out block 0
    // our authorization will be that we are the chain definition
    uint256 mmvRoot, nodePreHash;

    auto mmr = chainActive.GetMMR();
    auto mmv = ChainMerkleMountainView(mmr);
    mmv.resize(1);
    mmvRoot = mmv.GetRoot();
    nodePreHash = mmr.GetNode(0).hash;

    CTxDestination notaryDest;
    extern int32_t USE_EXTERNAL_PUBKEY; extern std::string NOTARY_PUBKEY;
    // use default ID as notary ID if there is one
    if (!VERUS_DEFAULTID.IsNull())
    {
        notaryDest = VERUS_DEFAULTID;
    }
    // use pub key if there is one
    else if (USE_EXTERNAL_PUBKEY)
    {
        CPubKey pubKey = CPubKey(ParseHex(NOTARY_PUBKEY));
        if (pubKey.IsFullyValid())
        {
            notaryDest = pubKey.GetID();
        }
    }

    CPBaaSNotarization pbn = CPBaaSNotarization(newChain.notarizationProtocol, 
                                                newChainID, 
                                                notaryDest, 
                                                0, 
                                                mmvRoot, 
                                                nodePreHash, 
                                                mmr.GetNode(0).power,
                                                static_cast<CCurrencyState>(newCurrencyState),
                                                uint256(),
                                                0,
                                                uint256(),
                                                0,
                                                COpRetProof(),
                                                vNodes);

    // make the first chain notarization output
    cp = CCinit(&CC, EVAL_ACCEPTEDNOTARIZATION);
    CTxDestination notarizationDest;

    if (newChain.notarizationProtocol == newChain.NOTARIZATION_AUTO || newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CONFIRM)
    {
        notarizationDest = CPubKey(ParseHex(CC.CChexstr));
    }
    else if (newChain.notarizationProtocol == newChain.NOTARIZATION_NOTARY_CHAINID)
    {
        notarizationDest = CIdentityID(newChainID);
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "None or notarization protocol specified");
    }

    indexDests = std::vector<CTxDestination>({CKeyID(newChain.GetConditionID(EVAL_ACCEPTEDNOTARIZATION))});
    dests = std::vector<CTxDestination>({notarizationDest});

    vOutputs.push_back({MakeMofNCCScript(CConditionObj<CPBaaSNotarization>(EVAL_ACCEPTEDNOTARIZATION, dests, 1, &pbn), &indexDests), 
                                         newChain.notarizationReward, 
                                         false});

    // make the finalization output
    cp = CCinit(&CC, EVAL_FINALIZE_NOTARIZATION);
    pk = CPubKey(ParseHex(CC.CChexstr));

    indexDests = std::vector<CTxDestination>({CKeyID(newChain.GetConditionID(EVAL_FINALIZE_NOTARIZATION))});
    dests = std::vector<CTxDestination>({pk});

    CTransactionFinalization nf;

    vOutputs.push_back({MakeMofNCCScript(CConditionObj<CTransactionFinalization>(EVAL_FINALIZE_NOTARIZATION, dests, 1, &nf), &indexDests), 
                                         CTransactionFinalization::DEFAULT_OUTPUT_VALUE, 
                                         false});

    std::set<CIdentityID> idExportSet;

    if (!newChain.IsToken())
    {
        idExportSet = std::set<CIdentityID>({newChainID});

        // create chain transfer exports for launch identity, notaries, and preallocation recipients
        for (auto &notary : newChain.notaries)
        {
            idExportSet.insert(notary);
        }
        for (auto &oneAlloc : newChain.preAllocation)
        {
            idExportSet.insert(oneAlloc.first);
        }

        // now, look them all up and create exports for zero value to move the IDs
        for (auto &oneID : idExportSet)
        {
            CIdentity oneIdentity = (oneID == newChainID) ? launchIdentity : CIdentity::LookupIdentity(oneID);
            if (!oneIdentity.IsValid())
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid specified identity: " + EncodeDestination(CIdentityID(oneID)));
            }

            // emit a reserve transfer output
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
            CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

            // send a zero output to this ID and pass the full ID to do so
            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});
            indexDests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER)),
                                                      CKeyID(newChain.systemID)});

            CTransferDestination transferDest = IdentityToTransferDestination(oneIdentity);
            CReserveTransfer rt = CReserveTransfer(CReserveExchange::VALID, 
                                                   ASSETCHAINS_CHAINID, 
                                                   0, 
                                                   CReserveTransfer::CalculateTransferFee(transferDest), 
                                                   newChain.GetID(),
                                                   transferDest);

            vOutputs.push_back({MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests), 
                                                 rt.nFees, 
                                                 false});
        }
    }
    else
    {
        // output preallocation
        for (auto &oneAlloc : newChain.preAllocation)
        {
            // emit a reserve transfer output, which will be imported on successful launch
            cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
            CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});
            indexDests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER)),
                                                      CKeyID(newChainID)});

            CTransferDestination transferDest = DestinationToTransferDestination(CIdentityID(oneAlloc.first));
            CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PREALLOCATE, 
                                                   newChain.systemID, 
                                                   oneAlloc.second,
                                                   CReserveTransfer::CalculateTransferFee(transferDest), 
                                                   newChainID,
                                                   transferDest);

            vOutputs.push_back({MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests), 
                                CReserveTransfer::CalculateTransferFee(transferDest), false});
        }
    }

    // create import and export outputs
    cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
    pk = CPubKey(ParseHex(CC.CChexstr));

    CTxDestination proofDest;

    if (newChain.proofProtocol == newChain.PROOF_PBAASMMR || newChain.proofProtocol == newChain.PROOF_CHAINID)
    {
        proofDest = CPubKey(ParseHex(CC.CChexstr));
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "None or notarization protocol specified");
    }

    // import thread is specific to the chain importing from
    dests = std::vector<CTxDestination>({proofDest});
    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(newChainID, EVAL_CROSSCHAIN_IMPORT))});
    // if this is a token on this chain, the transfer that is output here is burned through the export 
    // and merges with the import thread. we multiply new input times 2, to cover both the import thread output 
    // and the reserve transfer outputs.
    CCrossChainImport cci(newChainID, CCurrencyValueMap(), CCurrencyValueMap());
    vOutputs.push_back({MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci), &indexDests), 0, false});

    // export thread
    cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
    dests = std::vector<CTxDestination>({CPubKey(ParseHex(CC.CChexstr))});
    indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(newChainID, EVAL_CROSSCHAIN_EXPORT))});
    if (newChainID != newChain.systemID)
    {
        indexDests.push_back(CKeyID(CCrossChainRPCData::GetConditionID(newChain.systemID, EVAL_CROSSCHAIN_EXPORT)));
    }
    CCrossChainExport ccx = CCrossChainExport(newChainID, 0, CCurrencyValueMap(), CCurrencyValueMap());
    vOutputs.push_back({MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx), &indexDests), 0, false});

    // make the outputs for initial contributions
    if (newChain.contributions.size() && newChain.contributions.size() == newChain.currencies.size())
    {
        for (int i = 0; i < newChain.currencies.size(); i++)
        {
            if (newChain.contributions[i] > 0)
            {
                CAmount fee = CReserveTransactionDescriptor::CalculateAdditionalConversionFee(newChain.contributions[i]);
                CAmount contribution = (newChain.contributions[i] + fee) - 
                                        CReserveTransactionDescriptor::CalculateConversionFee(newChain.contributions[i] + fee);
                fee += CReserveTransfer::DEFAULT_PER_STEP_FEE << 1;

                CReserveTransfer rt = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::PRECONVERT,
                                                       newChain.currencies[i],
                                                       contribution,
                                                       fee,
                                                       newChainID,
                                                       DestinationToTransferDestination(CIdentityID(newChainID)));

                cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                CPubKey pk(ParseHex(CC.CChexstr));

                indexDests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_RESERVE_TRANSFER)),
                                                          CKeyID(newChain.systemID)});
                dests = std::vector<CTxDestination>({pk});

                vOutputs.push_back({MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &rt), &indexDests), 
                                                     newChain.currencies[i] == thisChainID ? newChain.contributions[i] + fee : 0, 
                                                     false});
                
                // TODO: send export and conversion fees to reserve deposit, as appropriate, to enable payment
            }
        }
    }

    // create the transaction
    CWalletTx wtx;
    CMutableTransaction mtx(wtx);
    mtx.vin.push_back(idTxIn);
    *static_cast<CTransaction*>(&wtx) = mtx;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        CReserveKey reserveKey(pwalletMain);
        CAmount fee;
        int nChangePos;
        int nChangeOutput;
        string failReason;

        CTxDestination chainDefSource = CIdentityID(newChainID);

        if (!pwalletMain->CreateReserveTransaction(vOutputs, 
                                                   wtx, 
                                                   reserveKey, 
                                                   fee, 
                                                   nChangePos, 
                                                   nChangeOutput, 
                                                   failReason, 
                                                   NULL, 
                                                   &chainDefSource))
        {
            throw JSONRPCError(RPC_TRANSACTION_ERROR, newChain.name + ": " + failReason);
        }
    }

    UniValue uvret(UniValue::VOBJ);
    std::vector<CCurrencyDefinition> curDefs = CCurrencyDefinition::GetCurrencyDefinitions(wtx);
    uvret.push_back(Pair("currencydefinition", (curDefs.size() ? curDefs[0] : CCurrencyDefinition()).ToUniValue()));

    uvret.push_back(Pair("basenotarization", CPBaaSNotarization(wtx).ToUniValue()));

    uvret.push_back(Pair("txid", wtx.GetHash().GetHex()));

    UniValue txJSon(UniValue::VOBJ);
    TxToJSON(wtx, uint256(), txJSon);
    uvret.push_back(Pair("tx",  txJSon));

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx));
    uvret.push_back(Pair("hex", strHex));

    return uvret;
}

UniValue registernamecommitment(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() < 2 && params.size() > 3))
    {
        throw runtime_error(
            "registernamecommitment \"name\" \"controladdress\" (\"referralidentity\")\n"
            "\nRegisters a name commitment, which is required as a source for the name to be used when registering an identity. The name commitment hides the name itself\n"
            "while ensuring that the miner who mines in the registration cannot front-run the name unless they have also registered a name commitment for the same name or\n"
            "are willing to forfeit the offer of payment for the chance that a commitment made now will allow them to register the name in the future.\n"

            "\nArguments\n"
            "\"name\"                           (string, required)  the unique name to commit to. creating a name commitment is not a registration, and if one is\n"
            "                                                       created for a name that exists, it may succeed, but will never be able to be used.\n"
            "\"controladdress\"                 (address, required) address that will control this commitment\n"
            "\"referralidentity\"               (identity, optional)friendly name or identity address that is provided as a referral mechanism and to lower network cost of the ID\n"

            "\nResult: obj\n"
            "{\n"
            "    \"txid\" : \"hexid\"\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\"    : \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\"    : \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referral\": \"identityaddress\", (base58) address of the referring identity if there is one\n"
            "        \"parent\"  : \"namestr\",   (string) name of the parent if not Verus or Verus test\n"
            "        \"nameid\"  : \"address\",   (base58) identity address for this identity if it is created\n"
            "    }\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("registernamecommitment", "\"name\"")
            + HelpExampleRpc("registernamecommitment", "\"name\"")
        );
    }

    CheckIdentityAPIsValid();

    uint160 parent;
    std::string name = CleanName(uni_get_str(params[0]), parent, true);

    // if either we have an invalid name or an implied parent, that is not valid
    if (name == "" || !(parent == ASSETCHAINS_CHAINID) || name != uni_get_str(params[0]))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid name for commitment. Names must not have leading or trailing spaces and must not include any of the following characters between parentheses (\\/:*?\"<>|@)");
    }

    parent = ConnectedChains.ThisChain().GetID();

    CTxDestination dest = DecodeDestination(uni_get_str(params[1]));
    if (dest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid control address for commitment");
    }

    // create the transaction with native coin as input
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CIdentityID referrer;
    if (params.size() > 2)
    {
        CTxDestination referDest = DecodeDestination(uni_get_str(params[2]));
        if (referDest.which() != COptCCParams::ADDRTYPE_ID)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid referral identity for commitment, must be a currently registered friendly name or i-address");
        }
        referrer = CIdentityID(GetDestinationID(referDest));
        if (!CIdentity::LookupIdentity(referrer).IsValidUnrevoked())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Referral identity for commitment must be a currently valid, unrevoked friendly name or i-address");
        }
    }

    CNameReservation nameRes(name, referrer, GetRandHash());
    CCommitmentHash commitment(nameRes.GetCommitment());
    
    CConditionObj<CCommitmentHash> condObj(EVAL_IDENTITY_COMMITMENT, std::vector<CTxDestination>({dest}), 1, &commitment);
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{MakeMofNCCScript(condObj, &dest), CCommitmentHash::DEFAULT_OUTPUT_AMOUNT, false}});
    CWalletTx wtx;

    if (CIdentity::LookupIdentity(CIdentity::GetID(name, parent)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity already exists.");
    }

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to create commitment transaction: " + failReason);
    }
    if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    ret.push_back(Pair("namereservation", nameRes.ToUniValue()));
    return ret;
}

UniValue registeridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "registeridentity \"jsonidregistration\" feeoffer\n"
            "\n\n"

            "\nArguments\n"
            "{\n"
            "    \"txid\" : \"hexid\",          (hex)    the transaction ID of the name committment for this ID name\n"
            "    \"namereservation\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name in this commitment\n"
            "        \"salt\": \"hexstr\",      (hex)    salt used to hide the commitment\n"
            "        \"referrer\": \"identityID\", (name@ or address) must be a valid ID to use as a referrer to receive a discount\n"
            "    },\n"
            "    \"identity\" :\n"
            "    {\n"
            "        \"name\": \"namestr\",     (string) the unique name for this identity\n"
            "        ...\n"
            "    }\n"
            "}\n"
            "feeoffer                           (amount, optional) amount to offer miner/staker for the registration fee, if missing, uses standard price\n\n"

            "\nResult:\n"
            "   transactionid                   (hexstr)\n"

            "\nExamples:\n"
            + HelpExampleCli("registeridentity", "jsonidregistration")
            + HelpExampleRpc("registeridentity", "jsonidregistration")
        );
    }

    CheckIdentityAPIsValid();

    // all names have a parent of the current chain
    uint160 parent = ConnectedChains.ThisChain().GetID();

    uint256 txid = uint256S(uni_get_str(find_value(params[0], "txid")));
    CNameReservation reservation(find_value(params[0], "namereservation"));

    CIdentity newID(find_value(params[0], "identity"));
    if (!newID.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity");
    }

    CAmount feeOffer;
    CAmount minFeeOffer = reservation.referral.IsNull() ? 
                          ConnectedChains.ThisChain().IDFullRegistrationAmount() : 
                          ConnectedChains.ThisChain().IDReferredRegistrationAmount();

    if (params.size() > 1)
    {
        feeOffer = AmountFromValue(params[1]);
    }
    else
    {
        feeOffer = minFeeOffer;
    }

    if (feeOffer < minFeeOffer)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee offer must be at least " + ValueFromAmount(minFeeOffer).write());
    }

    uint160 impliedParent, resParent;
    if (txid.IsNull() || 
        CleanName(reservation.name, resParent) != CleanName(newID.name, impliedParent) || 
        resParent != impliedParent ||
        impliedParent != ASSETCHAINS_CHAINID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid identity description or mismatched reservation.");
    }

    // lookup commitment to be sure that we can register this identity
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hashBlk;
    uint32_t commitmentHeight;
    CTransaction txOut;
    CCommitmentHash ch;
    int commitmentOutput;

    // must be present and in a mined block
    {
        LOCK(mempool.cs);
        if (!myGetTransaction(txid, txOut, hashBlk) || hashBlk.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment transaction id");
        }

        auto indexIt = mapBlockIndex.find(hashBlk);
        if (indexIt == mapBlockIndex.end() || indexIt->second->GetHeight() > chainActive.Height() || chainActive[indexIt->second->GetHeight()]->GetBlockHash() != indexIt->second->GetBlockHash())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or unconfirmed commitment");
        }

        commitmentHeight = indexIt->second->GetHeight();

        for (int i = 0; i < txOut.vout.size(); i++)
        {
            COptCCParams p;
            if (txOut.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
            {
                commitmentOutput = i;
                ::FromVector(p.vData[0], ch);
                break;
            }
        }
        if (ch.hash.IsNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment hash");
        }
    }

    if (ch.hash != reservation.GetCommitment().hash)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid commitment salt or referral ID");
    }

    // when creating an ID, the parent is always the current chains, and it is invalid to specify a parent
    if (newID.parent != parent)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid to specify alternate parent when creating an identity. Parent is determined by the current blockchain.");
    }

    newID.parent = parent;

    CIdentity dupID = newID.LookupIdentity(newID.GetID());
    if (dupID.IsValid())
    {
        throw JSONRPCError(RPC_VERIFY_ALREADY_IN_CHAIN, "Identity already exists.");
    }

    // make sure we have a revocation and recovery authority defined
    CIdentity revocationAuth = (newID.revocationAuthority.IsNull() || newID.revocationAuthority == newID.GetID()) ? newID : newID.LookupIdentity(newID.revocationAuthority);
    CIdentity recoveryAuth = (newID.recoveryAuthority.IsNull() || newID.recoveryAuthority == newID.GetID()) ? newID : newID.LookupIdentity(newID.recoveryAuthority);

    if (!recoveryAuth.IsValidUnrevoked() || !revocationAuth.IsValidUnrevoked())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked recovery, or revocation identity.");
    }

    // now we have a new and valid primary, revocation, and recovery identity, as well as a valid reservation
    newID.revocationAuthority = revocationAuth.GetID();
    newID.recoveryAuthority = recoveryAuth.GetID();

    // create the identity definition transaction & reservation key output
    CConditionObj<CNameReservation> condObj(EVAL_IDENTITY_RESERVATION, std::vector<CTxDestination>({CIdentityID(newID.GetID())}), 1, &reservation);
    CTxDestination resIndexDest = CKeyID(CCrossChainRPCData::GetConditionID(newID.GetID(), EVAL_IDENTITY_RESERVATION));
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(), 0, false}});

    // add referrals, Verus supports referrals
    if ((ConnectedChains.ThisChain().IDReferrals() || IsVerusActive()) && !reservation.referral.IsNull())
    {
        uint32_t referralHeight;
        CTxIn referralTxIn;
        CTransaction referralIdTx;
        auto referralIdentity =  newID.LookupIdentity(reservation.referral, commitmentHeight - 1);
        if (referralIdentity.IsValidUnrevoked())
        {
            if (!newID.LookupFirstIdentity(reservation.referral, &referralHeight, &referralTxIn, &referralIdTx).IsValid())
            {
                throw JSONRPCError(RPC_DATABASE_ERROR, "Database or blockchain data error, \"" + referralIdentity.name + "\" seems valid, but first instance is not found in index");
            }

            // create outputs for this referral and up to n identities back in the referral chain
            outputs.push_back({referralIdentity.TransparentOutput(referralIdentity.GetID()), ConnectedChains.ThisChain().IDReferralAmount(), false});
            feeOffer -= ConnectedChains.ThisChain().IDReferralAmount();
            int afterId = referralTxIn.prevout.n + 1;
            for (int i = afterId; i < referralIdTx.vout.size() && (i - afterId) < (ConnectedChains.ThisChain().idReferralLevels - 1); i++)
            {
                CTxDestination nextID;
                COptCCParams p, master;

                if (referralIdTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && 
                    p.IsValid() && 
                    p.evalCode == EVAL_NONE && 
                    p.vKeys.size() == 1 && 
                    (p.vData.size() == 1 ||
                    (p.vData.size() == 2 && 
                    p.vKeys[0].which() == COptCCParams::ADDRTYPE_ID &&
                    (master = COptCCParams(p.vData[1])).IsValid() &&
                    master.evalCode == EVAL_NONE)))
                {
                    outputs.push_back({newID.TransparentOutput(CIdentityID(GetDestinationID(p.vKeys[0]))), ConnectedChains.ThisChain().IDReferralAmount(), false});
                    feeOffer -= ConnectedChains.ThisChain().IDReferralAmount();
                }
                else
                {
                    break;
                }
            }
        }
        else
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid or revoked referral identity at time of commitment");
        }
    }

    CScript reservationOutScript = MakeMofNCCScript(condObj, &resIndexDest);
    outputs.push_back({reservationOutScript, CNameReservation::DEFAULT_OUTPUT_AMOUNT, false});

    // make one dummy output, which CreateTransaction will leave as last, and we will remove to add its output to the fee
    // this serves to keep the change output after our real reservation output
    outputs.push_back({reservationOutScript, feeOffer, false});

    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to create identity transaction: " + failReason);
    }

    // add commitment output
    CMutableTransaction mtx(wtx);
    mtx.vin.push_back(CTxIn(txid, commitmentOutput));

    // remove the fee offer output
    mtx.vout.pop_back();

    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess)
        {
            LogPrintf("%s: failure to sign identity registration tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity registration tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }

    // including definitions and claims thread
    return UniValue(wtx.GetHash().GetHex());
}

UniValue updateidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "updateidentity \"jsonidentity\" (returntx)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("updateidentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("updateidentity", "\'{\"name\" : \"myname\"}\'")
        );
    }

    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    CIdentity newID(params[0]);

    if (!newID.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!(oldID = CIdentity::LookupIdentity(newID.GetID(), 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + newID.ToUniValue().write());
    }

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }

    CMutableTransaction mtx(wtx);
    mtx.vin.push_back(idTxIn);
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess)
        {
            LogPrintf("%s: failure to sign identity update tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity update tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue revokeidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "revokeidentity \"nameorID\" (returntx)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("revokeidentity", "\"nameorID\"")
            + HelpExampleRpc("revokeidentity", "\"nameorID\"")
        );
    }

    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    CTxDestination idDest = DecodeDestination(uni_get_str(params[0]));

    if (idDest.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    CIdentityID idID(GetDestinationID(idDest));

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!(oldID = CIdentity::LookupIdentity(idID, 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + EncodeDestination(idID));
    }

    CIdentity newID(oldID);
    newID.Revoke();

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }
    CMutableTransaction mtx(wtx);

    // add the spend of the last ID transaction output
    mtx.vin.push_back(idTxIn);

    // all of the reservation output is actually the fee offer, so zero the output
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess)
        {
            LogPrintf("%s: failure to sign identity revocation tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity revocation tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue recoveridentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "recoveridentity \"jsonidentity\" (returntx)\n"
            "\n\n"

            "\nArguments\n"
            "       \"returntx\"                        (bool,   optional) defaults to false and transaction is sent, if true, transaction is signed by this wallet and returned\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("recoveridentity", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("recoveridentity", "\'{\"name\" : \"myname\"}\'")
        );
    }
    CheckIdentityAPIsValid();

    // get identity
    bool returnTx = false;
    CIdentity newID(params[0]);

    if (!newID.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid JSON ID parameter");
    }

    if (params.size() > 1)
    {
        returnTx = uni_get_bool(params[1], false);
    }

    CTxIn idTxIn;
    CIdentity oldID;
    uint32_t idHeight;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!(oldID = CIdentity::LookupIdentity(newID.GetID(), 0, &idHeight, &idTxIn)).IsValid())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found " + newID.ToUniValue().write());
    }

    if (!oldID.IsRevoked())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity must be revoked in order to recover : " + newID.name);
    }

    newID.flags &= ~CIdentity::FLAG_REVOKED;

    // create the identity definition transaction
    std::vector<CRecipient> outputs = std::vector<CRecipient>({{newID.IdentityUpdateOutputScript(), 0, false}});
    CWalletTx wtx;

    CReserveKey reserveKey(pwalletMain);
    CAmount fee;
    int nChangePos;
    string failReason;

    if (!pwalletMain->CreateTransaction(outputs, wtx, reserveKey, fee, nChangePos, failReason, nullptr, false))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Unable to create update transaction: " + failReason);
    }
    CMutableTransaction mtx(wtx);

    // add the spend of the last ID transaction output
    mtx.vin.push_back(idTxIn);

    // all of the reservation output is actually the fee offer, so zero the output
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    // now sign
    CCoinsViewCache view(pcoinsTip);
    for (int i = 0; i < wtx.vin.size(); i++)
    {
        bool signSuccess;
        SignatureData sigdata;

        CCoins coins;
        if (!(view.GetCoins(wtx.vin[i].prevout.hash, coins) && coins.IsAvailable(wtx.vin[i].prevout.n)))
        {
            break;
        }

        CAmount value = coins.vout[wtx.vin[i].prevout.n].nValue;

        signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &wtx, i, value, coins.vout[wtx.vin[i].prevout.n].scriptPubKey), coins.vout[wtx.vin[i].prevout.n].scriptPubKey, sigdata, CurrentEpochBranchId(chainActive.Height(), Params().GetConsensus()));

        if (!signSuccess)
        {
            LogPrintf("%s: failure to sign identity recovery tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            printf("%s: failure to sign identity recovery tx for input %d from output %d of %s\n", __func__, i, wtx.vin[i].prevout.n, wtx.vin[i].prevout.hash.GetHex().c_str());
            throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to sign transaction");
        } else {
            UpdateTransaction(mtx, i, sigdata);
        }
    }
    *static_cast<CTransaction*>(&wtx) = CTransaction(mtx);

    if (returnTx)
    {
        return EncodeHexTx(wtx);
    }
    else if (!pwalletMain->CommitTransaction(wtx, reserveKey))
    {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Could not commit transaction " + wtx.GetHash().GetHex());
    }
    return wtx.GetHash().GetHex();
}

UniValue getidentity(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error(
            "getidentity \"name\"\n"
            "\n\n"

            "\nArguments\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("getidentity", "\"name@\"")
            + HelpExampleRpc("getidentity", "\"name@\"")
        );
    }

    CheckIdentityAPIsValid();

    CTxDestination idID = DecodeDestination(uni_get_str(params[0]));
    if (idID.which() != COptCCParams::ADDRTYPE_ID)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Identity parameter must be valid friendly name or identity address: \"" + uni_get_str(params[0]) + "\"");
    }

    CTxIn idTxIn;
    uint32_t height;

    CIdentity identity;
    bool canSign = false, canSpend = false;

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        uint256 txID;
        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
        if (pwalletMain->GetIdentity(GetDestinationID(idID), keyAndIdentity))
        {
            canSign = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SIGN;
            canSpend = keyAndIdentity.first.flags & keyAndIdentity.first.CAN_SPEND;
            identity = static_cast<CIdentity>(keyAndIdentity.second);
        }
    }

    LOCK(cs_main);

    uint160 identityID = GetDestinationID(idID);
    identity = CIdentity::LookupIdentity(CIdentityID(identityID), 0, &height, &idTxIn);

    if (!identity.IsValid() && identityID == VERUS_CHAINID)
    {
        std::vector<CTxDestination> primary({CTxDestination(CKeyID(uint160()))});
        std::vector<std::pair<uint160, uint256>> contentmap;
        identity = CIdentity(CIdentity::VERSION_PBAAS, 
                             CIdentity::FLAG_ACTIVECURRENCY,
                             primary, 
                             1, 
                             ConnectedChains.ThisChain().parent,
                             VERUS_CHAINNAME,
                             contentmap,
                             ConnectedChains.ThisChain().GetID(),
                             ConnectedChains.ThisChain().GetID(),
                             std::vector<libzcash::SaplingPaymentAddress>());
    }

    UniValue ret(UniValue::VOBJ);

    uint160 parent;
    if (identity.IsValid() && identity.name == CleanName(identity.name, parent, true))
    {
        ret.push_back(Pair("identity", identity.ToUniValue()));
        ret.push_back(Pair("status", identity.IsRevoked() ? "revoked" : "active"));
        ret.push_back(Pair("canspendfor", canSpend));
        ret.push_back(Pair("cansignfor", canSign));
        ret.push_back(Pair("blockheight", (int64_t)height));
        ret.push_back(Pair("txid", idTxIn.prevout.hash.GetHex()));
        ret.push_back(Pair("vout", (int32_t)idTxIn.prevout.n));
        return ret;
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Identity not found");
    }
}

UniValue IdentityPairToUni(const std::pair<CIdentityMapKey, CIdentityMapValue> &identity)
{
    UniValue oneID(UniValue::VOBJ);

    if (identity.first.IsValid() && identity.second.IsValid())
    {
        oneID.push_back(Pair("identity", identity.second.ToUniValue()));
        oneID.push_back(Pair("blockheight", (int64_t)identity.first.blockHeight));
        oneID.push_back(Pair("txid", identity.second.txid.GetHex()));
        if (identity.second.IsRevoked())
        {
            oneID.push_back(Pair("status", "revoked"));
            oneID.push_back(Pair("canspendfor", bool(0)));
            oneID.push_back(Pair("cansignfor", bool(0)));
        }
        else
        {
            oneID.push_back(Pair("status", "active"));
            oneID.push_back(Pair("canspendfor", bool(identity.first.flags & identity.first.CAN_SPEND)));
            oneID.push_back(Pair("cansignfor", bool(identity.first.flags & identity.first.CAN_SIGN)));
        }
    }
    return oneID;
}

UniValue listidentities(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
    {
        throw runtime_error(
            "listidentities (includecansign) (includewatchonly)\n"
            "\n\n"

            "\nArguments\n"
            "    \"includecanspend\"    (bool, optional, default=true)    Include identities for which we can spend/authorize\n"
            "    \"includecansign\"     (bool, optional, default=true)    Include identities that we can only sign for but not spend\n"
            "    \"includewatchonly\"   (bool, optional, default=false)   Include identities that we can neither sign nor spend, but are either watched or are co-signers with us\n"

            "\nResult:\n"

            "\nExamples:\n"
            + HelpExampleCli("listidentities", "\'{\"name\" : \"myname\"}\'")
            + HelpExampleRpc("listidentities", "\'{\"name\" : \"myname\"}\'")
        );
    }

    CheckIdentityAPIsValid();

    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> mine, imsigner, notmine;

    bool includeCanSpend = params.size() > 0 ? uni_get_bool(params[0], true) : true;
    bool includeCanSign = params.size() > 1 ? uni_get_bool(params[1], true) : true;
    bool includeWatchOnly = params.size() > 2 ? uni_get_bool(params[2], false) : false;

    if (pwalletMain->GetIdentities(mine, imsigner, notmine))
    {
        UniValue ret(UniValue::VARR);
        if (includeCanSpend)
        {
            for (auto identity : mine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeCanSign)
        {
            for (auto identity : imsigner)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        if (includeWatchOnly)
        {
            for (auto identity : notmine)
            {
                uint160 parent;
                if (identity.second.IsValid() && identity.second.name == CleanName(identity.second.name, parent, true))
                {
                    ret.push_back(IdentityPairToUni(identity));
                }
            }
        }
        return ret;
    }
    else
    {
        return NullUniValue;
    }
}

UniValue addmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
    {
        throw runtime_error(
            "addmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAdds a fully prepared block and its header to the current merge mining queue of this daemon.\n"
            "Parameters determine the action to take if adding this block would exceed the available merge mining slots.\n"
            "Default action to take if adding would exceed available space is to replace the choice with the least ROI if this block provides more.\n"

            "\nArguments\n"
            "1. \"hexdata\"                     (string, required) the hex-encoded, complete, unsolved block data to add. nTime, and nSolution are replaced.\n"
            "2. \"name\"                        (string, required) chain name symbol\n"
            "3. \"rpchost\"                     (string, required) host address for RPC connection\n"
            "4. \"rpcport\"                     (int,    required) port address for RPC connection\n"
            "5. \"userpass\"                    (string, required) credentials for login to RPC\n"

            "\nResult:\n"
            "\"deserialize-invalid\" - block could not be deserialized and was rejected as invalid\n"
            "\"blocksfull\"          - block did not exceed others in estimated ROI, and there was no room for an additional merge mined block\n"

            "\nExamples:\n"
            + HelpExampleCli("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum}\'")
            + HelpExampleRpc("addmergedblock", "\"hexdata\" \'{\"currencyid\" : \"hexstring\", \"rpchost\" : \"127.0.0.1\", \"rpcport\" : portnum, \"estimatedroi\" : (verusreward/hashrate)}\'")
        );
    }

    CheckPBaaSAPIsValid();

    // check to see if we should replace any existing block or add a new one. if so, add this to the merge mine vector
    string name = params[1].get_str();
    if (name == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide chain name to merge mine");
    }

    string rpchost = params[2].get_str();
    int32_t rpcport = params[3].get_int();
    string rpcuserpass = params[4].get_str();

    if (rpchost == "" || rpcport == 0 || rpcuserpass == "")
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "must provide valid RPC connection parameters to merge mine");
    }

    uint160 chainID = CCrossChainRPCData::GetID(name);

    // confirm data from blockchain
    CRPCChainData chainData;
    CCurrencyDefinition chainDef;
    if (ConnectedChains.GetChainInfo(chainID, chainData))
    {
        chainDef = chainData.chainDefinition;
    }

    if (!chainDef.IsValid() && !GetCurrencyDefinition(name, chainDef))
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain not found");
    }

    CBlock blk;

    if (!DecodeHexBlk(blk, params[0].get_str()))
        return "deserialize-invalid";

    CPBaaSMergeMinedChainData blkData = CPBaaSMergeMinedChainData(chainDef, rpchost, rpcport, rpcuserpass, blk);

    return ConnectedChains.AddMergedBlock(blkData) ? NullUniValue : "blocksfull";
}

UniValue submitmergedblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitmergedblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit one more more new blocks to one or more networks.\n"
            "Each merged block submission may be valid for Verus and/or up to 8 merge mined chains.\n"
            "The submitted block consists of a valid block for this chain, along with embedded headers of up to 8 other chains.\n"
            "If the hash for this header meets targets of other chains that have been added with 'addmergedblock', this API will\n"
            "submit those blocks to the specified URL endpoints with an RPC 'submitblock' request."
            "\nAttempts to submit one more more new blocks to one or more networks.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"    (string, required) the hex-encoded block data to submit\n"
            "2. \"jsonparametersobject\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\"duplicate\" - node already has valid copy of block\n"
            "\"duplicate-invalid\" - node already has block, but it is invalid\n"
            "\"duplicate-inconclusive\" - node already has block but has not validated it\n"
            "\"inconclusive\" - node has not validated the block, it may not be on the node's current best chain\n"
            "\"rejected\" - block was rejected as invalid\n"
            "For more information on submitblock parameters and results, see: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki#block-submission\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    CheckPBaaSAPIsValid();

    CBlock block;
    //LogPrintStr("Hex block submission: " + params[0].get_str());
    if (!DecodeHexBlk(block, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex)
            {
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                // Otherwise, we might only have the header - process the block before returning
                fBlockPresent = true;
            }
        }
    }

    CValidationState state;
    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    //printf("submitblock, height=%d, coinbase sequence: %d, scriptSig: %s\n", chainActive.LastTip()->GetHeight()+1, block.vtx[0].vin[0].nSequence, block.vtx[0].vin[0].scriptSig.ToString().c_str());
    bool fAccepted = ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, &block, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted)
    {
        if (!sc.found)
            return "inconclusive";
        state = sc.state;
    }
    return BIP22ValidationResult(state);
}

UniValue getmergedblocktemplate(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate ( \"jsonrequestobject\" )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments:\n"
            "1. \"jsonrequestobject\"       (string, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
            "       \"capabilities\":[       (array, optional) A list of strings\n"
            "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "         ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                     (numeric) The block version\n"
            "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
            "  \"finalsaplingroothash\" : \"xxxx\", (string) The hash of the final sapling root\n"
            "  \"transactions\" : [                 (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"hash\" : \"xxxx\",          (string) hash/id encoded in little-endian hexadecimal\n"
            "         \"depends\" : [              (array) array of numbers \n"
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any\n"
            "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
//            "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
//            "      \"flags\" : \"flags\"            (string) \n"
//            "  },\n"
//            "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",               (string) The hash target\n"
            "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
            "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    CheckPBaaSAPIsValid();

    LOCK(cs_main);

    // Wallet or miner address is required because we support coinbasetxn
    if (GetArg("-mineraddress", "").empty()) {
#ifdef ENABLE_WALLET
        if (!pwalletMain) {
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Wallet disabled and -mineraddress not set");
        }
#else
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "verusd compiled without wallet and -mineraddress not set");
#endif
    }

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    // TODO: Re-enable coinbasevalue once a specification has been written
    bool coinbasetxn = true;
    if (params.size() > 0)
    {
        const UniValue& oparam = params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex)
                {
                    if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                        return "duplicate";
                    if (pindex->nStatus & BLOCK_FAILED_MASK)
                        return "duplicate-invalid";
                }
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.LastTip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    bool fvNodesEmpty;
    {
        LOCK(cs_vNodes);
        fvNodesEmpty = vNodes.empty();
    }
    if (Params().MiningRequiresPeers() && (IsNotInSync() || fvNodesEmpty))
    {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Cannot get a block template while no peers are connected or chain not in sync!");
    }

    //if (IsInitialBlockDownload())
     //   throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Zcash is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.LastTip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1);

            boost::unique_lock<boost::mutex> lock(csBestBlock);
            while (chainActive.LastTip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                if (!cvBlockChange.timed_wait(lock, checktxtime))
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != chainActive.LastTip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlockWithKey, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.LastTip();
        nStart = GetTime();

        // Create new block
        if(pblocktemplate)
        {
            delete pblocktemplate;
            pblocktemplate = NULL;
        }
#ifdef ENABLE_WALLET
        CReserveKey reservekey(pwalletMain);
        pblocktemplate = CreateNewBlockWithKey(reservekey,chainActive.LastTip()->GetHeight()+1,KOMODO_MAXGPUCOUNT);
#else
        pblocktemplate = CreateNewBlockWithKey();
#endif
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory or no available utxo for staking");

        // Need to update only after we know CreateNewBlockWithKey succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    pblock->nNonce = uint256();

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue txCoinbase = NullUniValue;
    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    BOOST_FOREACH (const CTransaction& tx, pblock->vtx) {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() && !coinbasetxn)
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx)));

        entry.push_back(Pair("hash", txHash.GetHex()));

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CTxIn &in, tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        entry.push_back(Pair("sigops", pblocktemplate->vTxSigOps[index_in_template]));

        if (tx.IsCoinBase()) {
            // Show founders' reward if it is required
            //if (pblock->vtx[0].vout.size() > 1) {
                // Correct this if GetBlockTemplate changes the order
            //    entry.push_back(Pair("foundersreward", (int64_t)tx.vout[1].nValue));
            //}
            CAmount nReward = GetBlockSubsidy(chainActive.LastTip()->GetHeight()+1, Params().GetConsensus());
            entry.push_back(Pair("coinbasevalue", nReward));
            entry.push_back(Pair("required", true));
            txCoinbase = entry;
        } else
            transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    static UniValue aMutable(UniValue::VARR);
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("finalsaplingroothash", pblock->hashFinalSaplingRoot.GetHex()));
    result.push_back(Pair("transactions", transactions));
    if (coinbasetxn) {
        assert(txCoinbase.isObject());
        result.push_back(Pair("coinbasetxn", txCoinbase));
    } else {
        result.push_back(Pair("coinbaseaux", aux));
        result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    }
    result.push_back(Pair("longpollid", chainActive.LastTip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    if ( ASSETCHAINS_STAKED != 0 )
    {
        arith_uint256 POWtarget; int32_t PoSperc;
        POWtarget = komodo_PoWtarget(&PoSperc,hashTarget,(int32_t)(pindexPrev->GetHeight()+1),ASSETCHAINS_STAKED);
        result.push_back(Pair("target", POWtarget.GetHex()));
        result.push_back(Pair("PoSperc", (int64_t)PoSperc));
        result.push_back(Pair("ac_staked", (int64_t)ASSETCHAINS_STAKED));
        result.push_back(Pair("origtarget", hashTarget.GetHex()));
    } else result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", pblock->GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->GetHeight()+1)));

    //fprintf(stderr,"return complete template\n");
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "identity",     "registernamecommitment",       &registernamecommitment, true  },
    { "identity",     "registeridentity",             &registeridentity,       true  },
    { "identity",     "updateidentity",               &updateidentity,         true  },
    { "identity",     "revokeidentity",               &revokeidentity,         true  },
    { "identity",     "recoveridentity",              &recoveridentity,        true  },
    { "identity",     "getidentity",                  &getidentity,            true  },
    { "identity",     "listidentities",               &listidentities,         true  },
    { "multichain",   "definecurrency",               &definecurrency,         true  },
    { "multichain",   "listcurrencies",               &listcurrencies,         true  },
    { "multichain",   "getcurrency",                  &getcurrency,            true  },
    { "multichain",   "getnotarizationdata",          &getnotarizationdata,    true  },
    { "multichain",   "getcrossnotarization",         &getcrossnotarization,   true  },
    { "multichain",   "submitacceptednotarization",   &submitacceptednotarization, true },
    { "multichain",   "paynotarizationrewards",       &paynotarizationrewards, true  },
    { "multichain",   "getinitialcurrencystate",      &getinitialcurrencystate, true  },
    { "multichain",   "getcurrencystate",             &getcurrencystate,       true  },
    { "multichain",   "getsaplingtree",               &getsaplingtree,         true  },
    { "multichain",   "sendcurrency",                 &sendcurrency,           true  },
    { "multichain",   "getpendingtransfers",          &getpendingtransfers,    true  },
    { "multichain",   "getexports",                   &getexports,             true  },
    { "multichain",   "getimports",                   &getimports,             true  },
    { "multichain",   "reserveexchange",              &reserveexchange,        true  },
    { "multichain",   "getlatestimportsout",          &getlatestimportsout,    true  },
    { "multichain",   "getlastimportin",              &getlastimportin,        true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "refundfailedlaunch",           &refundfailedlaunch,     true  },
    { "multichain",   "getmergedblocktemplate",       &getmergedblocktemplate, true  },
    { "multichain",   "addmergedblock",               &addmergedblock,         true  }
};

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
