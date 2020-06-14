// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "miner.h"
#ifdef ENABLE_MINING
#include "pow/tromp/equi_miner.h"
#endif

#include "amount.h"
#include "chainparams.h"
#include "cc/StakeGuard.h"
#include "importcoin.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#include "crypto/verus_hash.h"
#endif
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "metrics.h"
#include "net.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "random.h"
#include "timedata.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include "zcash/Address.hpp"
#include "transaction_builder.h"

#include "sodium.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#ifdef ENABLE_MINING
#include <functional>
#endif
#include <mutex>

#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "pbaas/identity.h"
#include "rpc/pbaasrpc.h"
#include "transaction_builder.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;
    
    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
    
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (consensusParams.nPowAllowMinDifficultyBlocksAfterHeight != boost::none) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
}

#include "komodo_defs.h"

extern CCriticalSection cs_metrics;
extern int32_t KOMODO_MININGTHREADS,KOMODO_LONGESTCHAIN,ASSETCHAINS_SEED,IS_KOMODO_NOTARY,USE_EXTERNAL_PUBKEY,KOMODO_CHOSEN_ONE,ASSETCHAIN_INIT,KOMODO_INITDONE,KOMODO_ON_DEMAND,KOMODO_INITDONE,KOMODO_PASSPORT_INITDONE;
extern uint64_t ASSETCHAINS_COMMISSION, ASSETCHAINS_STAKED;
extern bool VERUS_MINTBLOCKS;
extern uint64_t ASSETCHAINS_REWARD[ASSETCHAINS_MAX_ERAS], ASSETCHAINS_TIMELOCKGTE, ASSETCHAINS_NONCEMASK[];
extern const char *ASSETCHAINS_ALGORITHMS[];
extern int32_t VERUS_MIN_STAKEAGE, ASSETCHAINS_EQUIHASH, ASSETCHAINS_VERUSHASH, ASSETCHAINS_LASTERA, ASSETCHAINS_LWMAPOS, ASSETCHAINS_NONCESHIFT[], ASSETCHAINS_HASHESPERROUND[];
extern uint32_t ASSETCHAINS_ALGO;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint160 ASSETCHAINS_CHAINID;
extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;
extern int32_t PBAAS_STARTBLOCK, PBAAS_ENDBLOCK;
extern string PBAAS_HOST, PBAAS_USERPASS, ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;;
extern int32_t PBAAS_PORT;
extern uint16_t ASSETCHAINS_RPCPORT;
extern std::string NOTARY_PUBKEY,ASSETCHAINS_OVERRIDE_PUBKEY;
void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len);

extern uint8_t NOTARY_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEY33[33];
uint32_t Mining_start, Mining_height;
int32_t My_notaryid = -1;
int32_t komodo_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t komodo_pax_opreturn(int32_t height,uint8_t *opret,int32_t maxsize);
int32_t komodo_baseid(char *origbase);
int32_t komodo_validate_interest(const CTransaction &tx,int32_t txheight,uint32_t nTime,int32_t dispflag);
int64_t komodo_block_unlocktime(uint32_t nHeight);
uint64_t komodo_commission(const CBlock *block);
int32_t komodo_staked(CMutableTransaction &txNew,uint32_t nBits,uint32_t *blocktimep,uint32_t *txtimep,uint256 *utxotxidp,int32_t *utxovoutp,uint64_t *utxovaluep,uint8_t *utxosig);
int32_t verus_staked(CBlock *pBlock, CMutableTransaction &txNew, uint32_t &nBits, arith_uint256 &hashResult, std::vector<unsigned char> &utxosig, CPubKey &pk);
int32_t komodo_notaryvin(CMutableTransaction &txNew,uint8_t *notarypub33);

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int &nExtraNonce, bool buildMerkle, uint32_t *pSaveBits)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;

    if (pSaveBits)
    {
        *pSaveBits = pblock->nBits;
    }

    int32_t nHeight = pindexPrev->GetHeight() + 1;

    if (CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight) >= CConstVerusSolutionVector::activationHeight.ACTIVATE_PBAAS)
    {
        // coinbase should already be finalized in the new version
        if (buildMerkle)
        {
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
            pblock->SetPrevMMRRoot(ChainMerkleMountainView(chainActive.GetMMR(), pindexPrev->GetHeight()).GetRoot());
            BlockMMRange mmRange(pblock->BuildBlockMMRTree());
            BlockMMView mmView(mmRange);
            pblock->SetBlockMMRRoot(mmView.GetRoot());
            pblock->AddUpdatePBaaSHeader();
        }

        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);

        uint256 mmvRoot;
        {
            LOCK(cs_main);
            // set the PBaaS header
            ChainMerkleMountainView mmv = chainActive.GetMMV();
            mmvRoot = mmv.GetRoot();
        }

        pblock->AddUpdatePBaaSHeader();

        // POS blocks have already had their solution space filled, and there is no actual extra nonce, extradata is used
        // for POS proof, so don't modify it
        if (!pblock->IsVerusPOSBlock())
        {
            uint8_t dummy;
            // clear extra data to allow adding more PBaaS headers
            pblock->SetExtraData(&dummy, 0);

            // combine blocks and set compact difficulty if necessary
            uint32_t savebits;
            if ((savebits = ConnectedChains.CombineBlocks(*pblock)) && pSaveBits)
            {
                arith_uint256 ours, merged;
                ours.SetCompact(pblock->nBits);
                merged.SetCompact(savebits);
                if (merged > ours)
                {
                    *pSaveBits = savebits;
                }
            }

            // extra nonce is kept in the header, not in the coinbase any longer
            // this allows instant spend transactions to use coinbase funds for
            // inputs by ensuring that once final, the coinbase transaction hash
            // will not continue to change
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << nExtraNonce;
            std::vector<unsigned char> vENonce(s.begin(), s.end());

            assert(pblock->ExtraDataLen() >= vENonce.size());
            pblock->SetExtraData(vENonce.data(), vENonce.size());
        }
    }
    else
    {
        // finalize input of coinbase
        CMutableTransaction txcb(pblock->vtx[0]);
        txcb.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
        assert(txcb.vin[0].scriptSig.size() <= 100);
        pblock->vtx[0] = txcb;
        if (buildMerkle)
        {
            pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        }

        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    }
}

extern CWallet *pwalletMain;

CPubKey GetSolutionPubKey(const std::vector<std::vector<unsigned char>> &vSolutions, txnouttype txType)
{
    CPubKey pk;

    if (txType == TX_PUBKEY)
    {
        pk = CPubKey(vSolutions[0]);
    }
    else if(txType == TX_PUBKEYHASH)
    {
        // we need to have this in our wallet to get the public key
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
    }
    else if (txType == TX_CRYPTOCONDITION)
    {
        if (vSolutions[0].size() == 33)
        {
            pk = CPubKey(vSolutions[0]);
        }
        else if (vSolutions[0].size() == 34 && vSolutions[0][0] == COptCCParams::ADDRTYPE_PK)
        {
            pk = CPubKey(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()));
        }
        else if (vSolutions[0].size() == 20)
        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->GetPubKey(CKeyID(uint160(vSolutions[0])), pk);
        }
        else if (vSolutions[0].size() == 21 && vSolutions[0][0] == COptCCParams::ADDRTYPE_ID)
        {
            // destination is an identity, see if we can get its first public key
            std::pair<CIdentityMapKey, CIdentityMapValue> identity;

            if (pwalletMain->GetIdentity(CIdentityID(uint160(std::vector<unsigned char>(vSolutions[0].begin() + 1, vSolutions[0].end()))), identity) && 
                identity.second.IsValidUnrevoked() && 
                identity.second.primaryAddresses.size())
            {
                CPubKey pkTmp = boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), identity.second.primaryAddresses[0]);
                if (pkTmp.IsValid())
                {
                    pk = pkTmp;
                }
                else
                {
                    LOCK(pwalletMain->cs_wallet);
                    pwalletMain->GetPubKey(CKeyID(GetDestinationID(identity.second.primaryAddresses[0])), pk);
                }
            }
        }
    }
    return pk;
}

CPubKey GetScriptPublicKey(const CScript &scriptPubKey)
{
    txnouttype typeRet;
    std::vector<std::vector<unsigned char>> vSolutions;
    if (Solver(scriptPubKey, typeRet, vSolutions))
    {
        return GetSolutionPubKey(vSolutions, typeRet);
    }
    return CPubKey();
}

void ProcessNewImports(const uint160 &sourceChainID, const CTransaction &lastConfirmed, int32_t nHeight)
{
    if (CConstVerusSolutionVector::GetVersionByHeight(nHeight) < CActivationHeight::ACTIVATE_PBAAS || 
        CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight))
    {
        return;
    }
    uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, Params().GetConsensus());

    // get any pending imports from the source chain. if the source chain is this chain, we don't need notarization
    CCurrencyDefinition thisChain = ConnectedChains.ThisChain();

    CTransaction lastImportTx;

    // we need to find the last unspent import transaction
    std::vector<CAddressUnspentDbEntry> unspentOutputs;

    bool found = false;

    if (GetAddressUnspent(CKeyID(CCrossChainRPCData::GetConditionID(sourceChainID, EVAL_CROSSCHAIN_IMPORT)), 1, unspentOutputs))
    {
        // if one spends the prior one, get the one that is not spent
        for (auto txidx : unspentOutputs)
        {
            uint256 blkHash;
            CTransaction itx;
            if (myGetTransaction(txidx.first.txhash, lastImportTx, blkHash) &&
                CCrossChainImport(lastImportTx).IsValid() &&
                (lastImportTx.IsCoinBase() ||
                (myGetTransaction(lastImportTx.vin[0].prevout.hash, itx, blkHash) &&
                CCrossChainImport(itx).IsValid())))
            {
                found = true;
                break;
            }
        }
    }

    if (found && pwalletMain)
    {
        UniValue params(UniValue::VARR);
        UniValue param(UniValue::VOBJ);

        CMutableTransaction txTemplate = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);
        int i;
        for (i = 0; i < lastImportTx.vout.size(); i++)
        {
            COptCCParams p;
            if (lastImportTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CROSSCHAIN_IMPORT)
            {
                txTemplate.vin.push_back(CTxIn(lastImportTx.GetHash(), (uint32_t)i));
                break;
            }
        }

        UniValue result = NullUniValue;
        if (i < lastImportTx.vout.size())
        {
            param.push_back(Pair("name", EncodeDestination(CIdentityID(thisChain.GetID()))));
            param.push_back(Pair("lastimporttx", EncodeHexTx(lastImportTx)));
            param.push_back(Pair("lastconfirmednotarization", EncodeHexTx(lastConfirmed)));
            param.push_back(Pair("importtxtemplate", EncodeHexTx(txTemplate)));
            param.push_back(Pair("totalimportavailable", lastImportTx.vout[txTemplate.vin[0].prevout.n].nValue));
            params.push_back(param);

            try
            {
                if (sourceChainID == thisChain.GetID())
                {
                    UniValue getlatestimportsout(const UniValue& params, bool fHelp);
                    result = getlatestimportsout(params, false);
                }
                else
                {
                    result = find_value(RPCCallRoot("getlatestimportsout", params), "result");
                }
            } catch (exception e)
            {
                printf("Could not get latest imports from notary chain\n");
            }
        }

        if (result.isArray() && result.size())
        {
            LOCK(pwalletMain->cs_wallet);

            uint256 lastImportHash = lastImportTx.GetHash();
            for (int i = 0; i < result.size(); i++)
            {
                CTransaction itx;
                if (result[i].isStr() && DecodeHexTx(itx, result[i].get_str()) && itx.vin.size() && itx.vin[0].prevout.hash == lastImportHash)
                {
                    // sign the transaction spending the last import and add to mempool
                    CMutableTransaction mtx(itx);
                    CCrossChainImport cci(lastImportTx);

                    bool signSuccess;
                    SignatureData sigdata;
                    CAmount value;
                    const CScript *pScriptPubKey;

                    signSuccess = ProduceSignature(
                        TransactionSignatureCreator(pwalletMain, &itx, 0, lastImportTx.vout[itx.vin[0].prevout.n].nValue, SIGHASH_ALL), lastImportTx.vout[itx.vin[0].prevout.n].scriptPubKey, sigdata, consensusBranchId);

                    if (!signSuccess)
                    {
                        break;
                    }

                    UpdateTransaction(mtx, 0, sigdata);
                    itx = CTransaction(mtx);

                    // commit to mempool and remove any conflicts
                    std::list<CTransaction> removed;
                    mempool.removeConflicts(itx, removed);
                    CValidationState state;
                    if (!myAddtomempool(itx, &state))
                    {
                        LogPrintf("Failed to add import transactions to the mempool due to: %s\n", state.GetRejectReason().c_str());
                        printf("Failed to add import transactions to the mempool due to: %s\n", state.GetRejectReason().c_str());
                        break;  // if we failed to add one, the others will fail to spend it
                    }

                    lastImportTx = itx;
                    lastImportHash = itx.GetHash();
                }
            }
        }
    }
}

CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& _scriptPubKeyIn, int32_t gpucount, bool isStake)
{
    CScript scriptPubKeyIn(_scriptPubKeyIn);

    // instead of one scriptPubKeyIn, we take a vector of them along with relative weight. each is assigned a percentage of the block subsidy and
    // mining reward based on its weight relative to the total
    std::vector<pair<int, CScript>> minerOutputs = scriptPubKeyIn.size() ? std::vector<pair<int, CScript>>({make_pair((int)1, scriptPubKeyIn)}) : std::vector<pair<int, CScript>>();

    CTxDestination firstDestination;
    if (!(scriptPubKeyIn.size() && ConnectedChains.SetLatestMiningOutputs(minerOutputs, firstDestination) || isStake))
    {
        fprintf(stderr,"%s: Must have valid miner outputs, including script with valid PK, PKH, or Verus ID destination.\n", __func__);
        return NULL;
    }

    CPubKey pk;

    if (minerOutputs.size())
    {
        int64_t shareCheck = 0;
        for (auto output : minerOutputs)
        {
            shareCheck += output.first;
            if (shareCheck < 0 || shareCheck > INT_MAX)
            {
                fprintf(stderr,"Invalid miner outputs share specifications\n");
                return NULL;
            }
        }
        pk = GetScriptPublicKey(minerOutputs[0].second);
    }

    uint64_t deposits; int32_t isrealtime,kmdheight; uint32_t blocktime;
    //fprintf(stderr,"create new block\n");
    // Create new block
    if ( gpucount < 0 )
        gpucount = KOMODO_MAXGPUCOUNT;
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
    {
        fprintf(stderr,"pblocktemplate.get() failure\n");
        return NULL;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // set version according to the current tip height, add solution if it is
    // VerusHash
    if (ASSETCHAINS_ALGO == ASSETCHAINS_VERUSHASH)
    {
        pblock->nSolution.resize(Eh200_9.SolutionWidth);
    }
    else
    {
        pblock->nSolution.clear();
    }
    pblock->SetVersionByHeight(chainActive.LastTip()->GetHeight() + 1);

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);
    
    // Add dummy coinbase tx placeholder as first transaction
    pblock->vtx.push_back(CTransaction());

    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end
    
    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    unsigned int nMaxIDSize = nBlockMaxSize / 2;
    unsigned int nCurrentIDSize = 0;
    
    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);
    
    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
    
    // Collect memory pool transactions into the block
    CAmount nFees = 0;

    // if this is a reserve currency, update the currency state from the coinbase of the last block
    bool isVerusActive = IsVerusActive();
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
    CAmount prealloc = 0;
    for (auto &onePair : thisChain.preAllocation)
    {
        prealloc += onePair.second;
    }
    CCoinbaseCurrencyState currencyState = CCoinbaseCurrencyState(CCurrencyState(thisChain.currencies,
                                                                                    thisChain.weights,
                                                                                    thisChain.contributions,
                                                                                    prealloc, 0, 0));

    std::vector<CAmount> exchangeRate(thisChain.currencies.size());

    // we will attempt to spend any cheats we see
    CTransaction cheatTx;
    boost::optional<CTransaction> cheatSpend;
    uint256 cbHash;

    CBlockIndex* pindexPrev = 0;
    {
        LOCK2(cs_main, mempool.cs);
        pindexPrev = chainActive.LastTip();
        const int nHeight = pindexPrev->GetHeight() + 1;
        const Consensus::Params &consensusParams = chainparams.GetConsensus();
        uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);
        bool sapling = consensusParams.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_SAPLING);

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        uint32_t proposedTime = GetAdjustedTime();
        if (proposedTime == nMedianTimePast)
        {
            // too fast or stuck, this addresses the too fast issue, while moving
            // forward as quickly as possible
            for (int i; i < 100; i++)
            {
                proposedTime = GetAdjustedTime();
                if (proposedTime == nMedianTimePast)
                    MilliSleep(10);
            }
        }
        pblock->nTime = GetAdjustedTime();

        CCoinsViewCache view(pcoinsTip);
        uint32_t expired; uint64_t commission;
        
        SaplingMerkleTree sapling_tree;
        assert(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree));

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);
        
        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size() + 1);

        // check if we should add cheat transaction
        CBlockIndex *ppast;
        CTransaction cb;
        int cheatHeight = nHeight - COINBASE_MATURITY < 1 ? 1 : nHeight - COINBASE_MATURITY;
        if (defaultSaplingDest &&
            sapling && chainActive.Height() > 100 && 
            (ppast = chainActive[cheatHeight]) && 
            ppast->IsVerusPOSBlock() && 
            cheatList.IsHeightOrGreaterInList(cheatHeight))
        {
            // get the block and see if there is a cheat candidate for the stake tx
            CBlock b;
            if (!(fHavePruned && !(ppast->nStatus & BLOCK_HAVE_DATA) && ppast->nTx > 0) && ReadBlockFromDisk(b, ppast, chainparams.GetConsensus(), 1))
            {
                CTransaction &stakeTx = b.vtx[b.vtx.size() - 1];

                if (cheatList.IsCheatInList(stakeTx, &cheatTx))
                {
                    // make and sign the cheat transaction to spend the coinbase to our address
                    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);

                    uint32_t voutNum;
                    // get the first vout with value
                    for (voutNum = 0; voutNum < b.vtx[0].vout.size(); voutNum++)
                    {
                        if (b.vtx[0].vout[voutNum].nValue > 0)
                            break;
                    }

                    // send to the same pub key as the destination of this block reward
                    if (MakeCheatEvidence(mtx, b.vtx[0], voutNum, cheatTx))
                    {
                        LOCK(pwalletMain->cs_wallet);
                        TransactionBuilder tb = TransactionBuilder(consensusParams, nHeight);
                        cb = b.vtx[0];
                        cbHash = cb.GetHash();

                        bool hasInput = false;
                        for (uint32_t i = 0; i < cb.vout.size(); i++)
                        {
                            // add the spends with the cheat
                            if (cb.vout[i].nValue > 0)
                            {
                                tb.AddTransparentInput(COutPoint(cbHash,i), cb.vout[0].scriptPubKey, cb.vout[0].nValue);
                                hasInput = true;
                            }
                        }

                        if (hasInput)
                        {
                            // this is a send from a t-address to a sapling address, which we don't have an ovk for.
                            // Instead, generate a common one from the HD seed. This ensures the data is
                            // recoverable, at least for us, while keeping it logically separate from the ZIP 32
                            // Sapling key hierarchy, which the user might not be using.
                            uint256 ovk;
                            HDSeed seed;
                            if (pwalletMain->GetHDSeed(seed)) {
                                ovk = ovkForShieldingFromTaddr(seed);

                                // send everything to Sapling address
                                tb.SendChangeTo(defaultSaplingDest.value(), ovk);

                                tb.AddOpRet(mtx.vout[mtx.vout.size() - 1].scriptPubKey);

                                TransactionBuilderResult buildResult(tb.Build());
                                if (!buildResult.IsError() && buildResult.IsTx())
                                {
                                    cheatSpend = buildResult.GetTxOrThrow();
                                }
                                else
                                {
                                    LogPrintf("Error building cheat catcher transaction: %s\n", buildResult.GetError().c_str());
                                }
                            }
                        }
                    }
                }
            }
        }

        if (cheatSpend)
        {
            cheatTx = cheatSpend.value();
            std::list<CTransaction> removed;
            mempool.removeConflicts(cheatTx, removed);
            printf("Found cheating stake! Adding cheat spend for %.8f at block #%d, coinbase tx\n%s\n",
                (double)cb.GetValueOut() / (double)COIN, nHeight, cheatSpend.value().vin[0].prevout.hash.GetHex().c_str());

            // add to mem pool and relay
            if (myAddtomempool(cheatTx))
            {
                RelayTransaction(cheatTx);
            }
        }

        //
        // Now start solving the block
        //

        uint64_t nBlockSize = 1000;             // initial size
        uint64_t nBlockTx = 1;                  // number of transactions - always have a coinbase
        uint32_t autoTxSize = 0;                // extra transaction overhead that we will add while creating the block
        int nBlockSigOps = 100;

        // VerusPoP staking transaction data
        CMutableTransaction txStaked;           // if this is a stake operation, the staking transaction that goes at the end
        uint32_t nStakeTxSize = 0;              // serialized size of the stake transaction

        // if this is not for mining, first determine if we have a right to bother
        if (isStake)
        {
            uint64_t txfees, utxovalue;
            uint32_t txtime;
            uint256 utxotxid;
            int32_t i, siglen, numsigs, utxovout;
            std::vector<unsigned char> utxosig;

            txStaked = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);

            //if ( blocktime > pindexPrev->GetMedianTimePast()+60 )
            //    blocktime = pindexPrev->GetMedianTimePast() + 60;
            if (ASSETCHAINS_LWMAPOS != 0)
            {
                uint32_t nBitsPOS;
                arith_uint256 posHash;

                siglen = verus_staked(pblock, txStaked, nBitsPOS, posHash, utxosig, pk);
                blocktime = GetAdjustedTime();

                // change the default scriptPubKeyIn to the same output script exactly as the staking transaction
                // TODO: improve this and just implement stake guard here rather than keeping this legacy
                if (siglen > 0)
                    scriptPubKeyIn = CScript(txStaked.vout[0].scriptPubKey);
            }

            if (siglen <= 0)
            {
                return NULL;
            }

            pblock->nTime = blocktime;
            nStakeTxSize = GetSerializeSize(txStaked, SER_NETWORK, PROTOCOL_VERSION);
            nBlockSize += nStakeTxSize;

            pk = GetScriptPublicKey(txStaked.vout[0].scriptPubKey);
            ExtractDestination(txStaked.vout[0].scriptPubKey, firstDestination);
        }

        ConnectedChains.AggregateChainTransfers(firstDestination, nHeight);

        // Now the coinbase -
        // A PBaaS coinbase must have some additional outputs to enable certain chain state and functions to be properly
        // validated. All but currency state and the first chain definition are either optional or not valid on non-fractional reserve PBaaS blockchains
        // All of these are instant spend outputs that have no maturity wait time and may be spent in the same block.
        //
        // 1. (required) currency state - current state of currency supply and optionally reserve, premine, etc. This is primarily a data output to provide
        //    cross check for coin minting and burning operations, making it efficient to determine up-to-date supply, reserves, and conversions. To provide
        //    an extra level of supply cross-checking and fast data retrieval, this is part of all PBaaS chains' protocol, not just reserves.
        //    This output also includes reserve and native amounts for total conversions, less fees, of any conversions between Verus reserve and the
        //    native currency.
        //
        // 2. (block 1 required) chain definition - in order to confirm the amount of coins converted and issued within the possible range, before chain start,
        //    new PBaaS chains have a zero-amount, unspendable chain definition output.
        //
        // 3. (block 1 optional) initial import utxo - for any chain with conversion or pre-conversion, the first coinbase must include an initial import utxo. 
        //    Pre-conversions are handled on the launch chain before the PBaaS chain starts, so they are an additional output, which begins
        //    as a fixed amount and is spent with as many outputs as necessary to the recipients of the pre-conversion transactions when those pre-conversions
        //    are imported. All pre-converted outputs get their source currency from a thread that starts with this output in block 1.
        //
        // 4. (block 1 optional) initial export utxo - reserve chains, or any chain that will use exports to another chain must have an initial export utxo, any chain
        //    may have one, but currently, they can only be spent with valid exports, which only occur on reserve chains
        //
        // 5. (optional) notarization output - in order to ensure that notarization can occur independent of the availability of fungible
        //    coins on the network, and also that the notarization can provide a spendable finalization output and possible reward
        //
        // In addition, each PBaaS block can be mined with optional, fee-generating transactions. Inporting transactions from the reserve chain or sending
        // exported transactions to the reserve chain are optional fee-generating steps that would be easy to do when running multiple daemons.
        // The types of transactions miners/stakers may facilitate or create for fees are as follows:
        //
        // 1. Earned notarization of Verus chain - spends the notarization instant out. must be present and spend the notarization output if there is a notarization output
        //
        // 2. Imported transactions from the export thread for this PBaaS chain on the Verus blockchain - imported transactions must spend the import utxo
        //    thread, represent the export from the alternate chain which spends the export output from the prior import transaction, carry a notary proof, and
        //    include outputs that map to each of its inputs on the source chain. Outputs can include unconverted reserve outputs only on fractional
        //    reserve chains, pre-converted outputs for any chain with launch conversion, and post launch outputs to be converted on fractional reserve
        //    chains. Each are handled in the following way:
        //      a. Unconverted outputs are left as outputs to the intended destination of Verus reserve token and do not pass through the coinbase
        //      b. Pre-converted outputs require that the import transaction spend the last pre-conversion output starting at block 1 as the source for
        //         pre-converted currency.
        //
        // 3. Zero or more aggregated exports that combine individual cross-chain transactions and reserve transfer outputs for export to the Verus chain. 
        //
        // 4. Conversion distribution transactions for all native and reserve currency conversions, including reserve transfer outputs without conversion as
        //    a second step for reserve transfers that have conversion included. Any remaining pre-converted reserve must always remain in a change output
        //    until it is exhausted
        CTxOut premineOut, chainDefinitionOut, importThreadOut, exportThreadOut, currencyStateOut, notarizationOut;
        CMutableTransaction newNotarizationTx, newConversionOutputTx;
        int currencyStateOutNum = 0, notarizationOutNum = 0;

        // size of conversion tx
        std::vector<CInputDescriptor> conversionInputs;

        // if we are a PBaaS chain, first make sure we don't start prematurely, and if
        // we should make an earned notarization, make it and set index to non-zero value
        int32_t notarizationTxIndex = 0;                            // index of notarization if it is added
        int32_t conversionTxIndex = 0;                              // index of conversion transaction if it is added

        // export transactions can be created here by aggregating all pending transfer requests and either getting 10 or more together, or
        // waiting n (10) blocks since the last one. each export must spend the output of the one before it
        std::vector<CMutableTransaction> exportTransactions;

        // all transaction outputs requesting conversion to another currency (PBaaS fractional reserve only)
        // these will be used to calculate conversion price, fees, and generate coinbase conversion output as well as the
        // conversion output transaction
        std::vector<CTxOut> reserveConversionTo;
        std::vector<CTxOut> reserveConversionFrom;

        int64_t pbaasTransparentIn = 0;
        int64_t pbaasTransparentOut = 0;
        //extern int64_t ASSETCHAINS_SUPPLY;
        //printf("%lu premine\n", ASSETCHAINS_SUPPLY);
        int64_t blockSubsidy = GetBlockSubsidy(nHeight, consensusParams);

        uint160 thisChainID = ConnectedChains.ThisChain().GetID();

        uint256 mmrRoot;
        vector<CInputDescriptor> notarizationInputs;

        // used as scratch for making CCs, should be reinitialized each time
        CCcontract_info CC;
        CCcontract_info *cp;
        vector<CTxDestination> vKeys;
        CPubKey pkCC;

        // Create coinbase tx and set up the null input with height
        CMutableTransaction coinbaseTx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        coinbaseTx.vin.push_back(CTxIn(uint256(), (uint32_t)-1, CScript() << nHeight << OP_0));

        // we will update amounts and fees later, but convert the guarded output now for validity checking and size estimate
        if (isStake)
        {
            // if there is a specific destination, use it
            CTransaction stakeTx(txStaked);
            CStakeParams p;
            if (ValidateStakeTransaction(stakeTx, p, false))
            {
                if (p.Version() < p.VERSION_EXTENDED_STAKE && !p.pk.IsValid())
                {
                    LogPrintf("CreateNewBlock: invalid public key\n");
                    fprintf(stderr,"CreateNewBlock: invalid public key\n");
                    return NULL;
                }
                CTxDestination guardedOutputDest = (p.Version() < p.VERSION_EXTENDED_STAKE) ? p.pk : p.delegate;
                coinbaseTx.vout.push_back(CTxOut(1, CScript()));
                if (!MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back()))
                {
                    LogPrintf("CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                    fprintf(stderr,"CreateNewBlock: failed to make GuardedOutput on staking coinbase\n");
                    return NULL;
                }
                COptCCParams optP;
                if (!coinbaseTx.vout.back().scriptPubKey.IsPayToCryptoCondition(optP) || !optP.IsValid())
                {
                    MakeGuardedOutput(1, guardedOutputDest, stakeTx, coinbaseTx.vout.back());
                    LogPrintf("%s: created invalid staking coinbase\n", __func__);
                    fprintf(stderr,"%s: created invalid staking coinbase\n", __func__);
                    return NULL;
                }
            }
            else
            {
                LogPrintf("CreateNewBlock: invalid stake transaction\n");
                fprintf(stderr,"CreateNewBlock: invalid stake transaction\n");
                return NULL;
            }
        }
        else
        {
            // default outputs for mining and before stake guard or fee calculation
            // store the relative weight in the amount output to convert later to a relative portion
            // of the reward + fees
            for (auto &spk : minerOutputs)
            {
                coinbaseTx.vout.push_back(CTxOut(spk.first, spk.second));
            }
        }

        CAmount totalEmission = blockSubsidy;

        // make earned notarization only if this is not the Verus chain and we have enough subsidy
        if (!isVerusActive)
        {
            // if we don't have a connected root PBaaS chain, we can't properly check
            // and notarize the start block, so we have to pass the notarization and cross chain steps
            bool notaryConnected = ConnectedChains.IsVerusPBaaSAvailable() && ConnectedChains.notaryChainHeight >= PBAAS_STARTBLOCK;

            // get current currency state differently, depending on height
            if (nHeight == 1)
            {
                if (!notaryConnected || !ConnectedChains.readyToStart)
                {
                    // cannot make block 1 unless we can properly notarize that the launch chain is past the start block
                    return NULL;
                }

                // if some amount of pre-conversion was allowed, we need to check with all eligible currency
                // chains or systems to determine how much in each currency is available for preconversion
                // TODO: support querying multiple systems... initial support for VRSC and VRSCTEST-homed currencies
                if (thisChain.maxPreconvert.size() && thisChain.maxPreconvert.size() == thisChain.currencies.size())
                {
                    // get the total amount pre-converted
                    UniValue params(UniValue::VARR);
                    params.push_back(EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)));

                    UniValue result;
                    try
                    {
                        result = find_value(RPCCallRoot("getinitialcurrencystate", params), "result");
                    } catch (exception e)
                    {
                        result = NullUniValue;
                    }

                    if (!result.isNull())
                    {
                        currencyState = CCoinbaseCurrencyState(result);
                    }

                    if (result.isNull() || !currencyState.IsValid())
                    {
                        // no matter what happens, we should be able to get a valid currency state of some sort, if not, fail
                        LogPrintf("Unable to get initial currency state to create block.\n");
                        printf("Failure to get initial currency state. Cannot create block.\n");
                        return NULL;
                    }

                    CCurrencyValueMap preConverted = CCurrencyValueMap(ConnectedChains.ThisChain().currencies, currencyState.reserveIn);
                    CCurrencyValueMap minPreconvert = CCurrencyValueMap(ConnectedChains.ThisChain().currencies, ConnectedChains.ThisChain().minPreconvert);

                    if (preConverted < minPreconvert)
                    {
                        // we must reach minimums in all currencies to launch
                        LogPrintf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
                        printf("This chain did not receive the minimum currency contributions and cannot launch. Pre-launch contributions to this chain can be refunded.\n");
                        return NULL;
                    }

                    thisChain.preconverted = preConverted.AsCurrencyVector(thisChain.currencies);
                    thisChain.conversions = currencyState.conversionPrice;
                }

                CAmount blockOnePremine = thisChain.GetTotalPreallocation();
                SetBlockOnePremine(blockOnePremine);
                totalEmission = GetBlockSubsidy(nHeight, consensusParams);
                blockSubsidy = totalEmission - blockOnePremine;

                // add needed block one coinbase outputs for preallocation
                if (blockOnePremine)
                {
                    std::vector<CTxOut> tmpOut;
                    for (auto &onePremine : ConnectedChains.ThisChain().GetPreAllocationAmounts())
                    {
                        premineOut = CTxOut(onePremine.second, GetScriptForDestination(CTxDestination(CIdentityID(onePremine.first))));
                        tmpOut.push_back(premineOut);
                    }
                    if (tmpOut.size())
                    {
                        coinbaseTx.vout.insert(coinbaseTx.vout.end(), tmpOut.begin(), tmpOut.end());
                    }
                }

                // now, we have pre-mine outputs calculated and created for either absolute or percentage-based
                // pre-allocation

                // following that, we have either 1 stake guarded output to the staker or delegate,
                // or some number of miner outputs

                // now, start adding additional outputs, including chain-definition output for Notary chain and all currencies in ConnectedChains
                ConnectedChains.LoadReserveCurrencies();

                // create a currency definition output for this currency, the notary currency, and all reserves
                CCcontract_info CC;
                CCcontract_info *cp;
                cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
                pkCC = CPubKey(ParseHex(CC.CChexstr));

                std::vector<CTxDestination> indexDests({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_CURRENCY_DEFINITION))});
                std::vector<CTxDestination> dests({pkCC});

                coinbaseTx.vout.push_back(CTxOut(0,
                                            MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, 
                                                             &ConnectedChains.ThisChain()),
                                            &indexDests)));

                for (auto &oneCur : ConnectedChains.reserveCurrencies)
                {
                    indexDests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_CURRENCY_DEFINITION)),
                                                            CKeyID(oneCur.second.GetConditionID(EVAL_CURRENCY_DEFINITION))});
                    coinbaseTx.vout.push_back(CTxOut(0,
                                              MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, &oneCur.second),
                                              &indexDests)));
                }

                if (!ConnectedChains.reserveCurrencies.count(ConnectedChains.NotaryChain().GetID()))
                {
                    indexDests = std::vector<CTxDestination>({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_CURRENCY_DEFINITION)),
                                                            CKeyID(ConnectedChains.NotaryChain().chainDefinition.GetConditionID(EVAL_CURRENCY_DEFINITION))});
                    coinbaseTx.vout.push_back(CTxOut(0,
                                              MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, 
                                                               &ConnectedChains.NotaryChain().chainDefinition),
                                              &indexDests)));
                }

                // create the import thread output
                cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
                pkCC = CPubKey(ParseHex(CC.CChexstr));

                // import thread from PBaaS parent
                indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.notaryChain.GetID(), EVAL_CROSSCHAIN_IMPORT))});
                dests = std::vector<CTxDestination>({pkCC});

                CCrossChainImport cci = CCrossChainImport(ConnectedChains.notaryChain.GetID(), CCurrencyValueMap());
                coinbaseTx.vout.push_back(CTxOut(currencyState.ReserveToNativeRaw(CCurrencyValueMap(thisChain.currencies, thisChain.preconverted), thisChain.conversions),
                                                 MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci), &indexDests)));

                // export thread to PBaaS parent
                cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
                pkCC = CPubKey(ParseHex(CC.CChexstr));
                indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.notaryChain.GetID(), EVAL_CROSSCHAIN_EXPORT))});
                dests = std::vector<CTxDestination>({pkCC});

                CCrossChainExport ccx(ConnectedChains.NotaryChain().GetID(), 0, CCurrencyValueMap(), CCurrencyValueMap());
                coinbaseTx.vout.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx), &indexDests)));
            }
            else
            {
                CBlock block;
                assert(nHeight > 1);
                currencyState = ConnectedChains.GetCurrencyState(nHeight - 1);
                currencyState.ClearForNextBlock();

                if (!currencyState.IsValid())
                {
                    // we should be able to get a valid currency state, if not, fail
                    LogPrintf("Unable to get initial currency state to create block #%d.\n", nHeight);
                    printf("Failure to get initial currency state. Cannot create block #%d.\n", nHeight);
                    return NULL;
                }
            }

            // update the currency state to include emissions before calculating conversions
            // premine is an emission that is factored in before this
            currencyState.UpdateWithEmission(totalEmission);

            // add currency state output to coinbase
            vKeys.clear();
            cp = CCinit(&CC, EVAL_CURRENCYSTATE);

            CPubKey currencyOutPK(ParseHex(cp->CChexstr));
            std::vector<CTxDestination> indexDests({CKeyID(CCrossChainRPCData::GetConditionID(thisChainID, EVAL_CURRENCYSTATE))});
            std::vector<CTxDestination> dests({currencyOutPK});

            // pre-conversions go to the import thread
            // conversions for this block, if any, will be processed
            // below
            coinbaseTx.vout.push_back(CTxOut(currencyState.ReserveToNativeRaw(CCurrencyValueMap(thisChain.currencies, thisChain.preconverted), thisChain.conversions),
                                                MakeMofNCCScript(CConditionObj<CCoinbaseCurrencyState>(EVAL_CURRENCYSTATE, dests, 1, &currencyState), &indexDests)));

            currencyStateOutNum = coinbaseTx.vout.size() - 1;

            if (notaryConnected)
            {
                // if we have access to our notary daemon
                // create a notarization if we would qualify to do so. add it to the mempool and next block
                CTransaction prevTx, crossTx, lastConfirmed, lastImportTx;
                ChainMerkleMountainView mmv = chainActive.GetMMV();
                mmrRoot = mmv.GetRoot();
                int32_t confirmedInput = -1;
                CTxDestination confirmedDest;
                if (CreateEarnedNotarization(newNotarizationTx, notarizationInputs, prevTx, crossTx, lastConfirmed, nHeight, &confirmedInput, &confirmedDest))
                {
                    // we have a valid, earned notarization transaction. we still need to complete it as follows:
                    // 1. Add an instant-spend input from the coinbase transaction to fund the finalization output
                    //
                    // 2. if we are spending finalization outputs, create an output of the same amount as a finalization output 
                    //    plus and any excess from the other, orphaned finalizations to the creator of the confirmed notarization
                    //
                    // 3. make sure the currency state is correct

                    // input should either be 0 or PBAAS_MINNOTARIZATIONOUTPUT + all finalized outputs
                    // we will add PBAAS_MINNOTARIZATIONOUTPUT from a coinbase instant spend in all cases and double that when it is 0 for block 1
                    for (const CTxIn& txin : newNotarizationTx.vin)
                    {
                        const uint256& prevHash = txin.prevout.hash;
                        const CCoins *pcoins = view.AccessCoins(prevHash);
                        pbaasTransparentIn += pcoins && (pcoins->vout.size() > txin.prevout.n) ? pcoins->vout[txin.prevout.n].nValue : 0;
                    }

                    // calculate the amount that will be sent to the confirmed notary address
                    // this will only be non-zero if we have finalized inputs
                    if (pbaasTransparentIn > 0)
                    {
                        pbaasTransparentOut = pbaasTransparentIn - PBAAS_MINNOTARIZATIONOUTPUT;
                    }

                    if (pbaasTransparentOut)
                    {
                        // if we are on a non-fungible chain, reward out must be unspendable
                        // make a normal output to the confirmed notary with the excess right behind the op_return
                        // TODO: make this a cc out to only allow spending on a fungible chain
                        CTxOut rewardOut = CTxOut(pbaasTransparentOut, GetScriptForDestination(confirmedDest));
                        newNotarizationTx.vout.insert(newNotarizationTx.vout.begin() + newNotarizationTx.vout.size() - 1, rewardOut);
                    }

                    // make the earned notarization coinbase output
                    vKeys.clear();
                    cp = CCinit(&CC, EVAL_EARNEDNOTARIZATION);

                    // send this to EVAL_EARNEDNOTARIZATION address as a destination, locked by the default pubkey
                    pkCC = CPubKey(ParseHex(cp->CChexstr));
                    vKeys.push_back(CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(VERUS_CHAINID, EVAL_EARNEDNOTARIZATION))));

                    int64_t needed = nHeight == 1 ? PBAAS_MINNOTARIZATIONOUTPUT << 1 : PBAAS_MINNOTARIZATIONOUTPUT;

                    // output duplicate notarization as coinbase output for instant spend to notarization
                    // the output amount is considered part of the total value of this coinbase
                    CPBaaSNotarization pbn(newNotarizationTx);
                    notarizationOut = MakeCC1of1Vout(EVAL_EARNEDNOTARIZATION, needed, pkCC, vKeys, pbn);
                    coinbaseTx.vout.push_back(notarizationOut);
                    notarizationOutNum = coinbaseTx.vout.size() - 1;

                    // place the notarization
                    pblock->vtx.push_back(CTransaction(newNotarizationTx));
                    pblocktemplate->vTxFees.push_back(0);
                    pblocktemplate->vTxSigOps.push_back(-1); // updated at end
                    nBlockSize += GetSerializeSize(newNotarizationTx, SER_NETWORK, PROTOCOL_VERSION);
                    notarizationTxIndex = pblock->vtx.size() - 1;
                    nBlockTx++;
                }
                else if (nHeight == 1)
                {
                    // failed to notarize at block 1
                    return NULL;
                }

                // if we have a last confirmed notarization, then check for new imports from the notary chain
                if (lastConfirmed.vout.size())
                {
                    ProcessNewImports(ConnectedChains.NotaryChain().GetID(), lastConfirmed, nHeight);
                }
            }
        }
        else
        {
            if (nHeight == 1)
            {
                SetBlockOnePremine(thisChain.GetTotalPreallocation());
            }
            totalEmission = GetBlockSubsidy(nHeight, consensusParams);
            blockSubsidy = totalEmission;
            currencyState.UpdateWithEmission(totalEmission);

            if (CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight))
            {
                // at activation height for PBaaS on VRSC or VRSCTEST, add currency definition, import, and export outputs to the coinbase
                // create a currency definition output for this currency, the notary currency, and all reserves
                CCcontract_info CC;
                CCcontract_info *cp;
                cp = CCinit(&CC, EVAL_CURRENCY_DEFINITION);
                pkCC = CPubKey(ParseHex(CC.CChexstr));

                std::vector<CTxDestination> indexDests({CKeyID(ConnectedChains.ThisChain().GetConditionID(EVAL_CURRENCY_DEFINITION))});
                std::vector<CTxDestination> dests({pkCC});

                coinbaseTx.vout.push_back(CTxOut(0,
                                            MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, dests, 1, 
                                                             &ConnectedChains.ThisChain()),
                                            &indexDests)));
            }
        }

        // on all chains, we add an export and import to ourselves at PBaaS activation height (1 for PBaaS chains)
        if (CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight))
        {
            // create the import thread output
            cp = CCinit(&CC, EVAL_CROSSCHAIN_IMPORT);
            pkCC = CPubKey(ParseHex(CC.CChexstr));

            // import thread from self
            std::vector<CTxDestination> indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.ThisChain().GetID(), EVAL_CROSSCHAIN_IMPORT))});
            std::vector<CTxDestination> dests = std::vector<CTxDestination>({pkCC});

            CCrossChainImport cci = CCrossChainImport(ConnectedChains.ThisChain().GetID(), CCurrencyValueMap());
            coinbaseTx.vout.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainImport>(EVAL_CROSSCHAIN_IMPORT, dests, 1, &cci), &indexDests)));

            // export thread to self
            cp = CCinit(&CC, EVAL_CROSSCHAIN_EXPORT);
            pkCC = CPubKey(ParseHex(CC.CChexstr));
            indexDests = std::vector<CTxDestination>({CKeyID(CCrossChainRPCData::GetConditionID(ConnectedChains.ThisChain().GetID(), EVAL_CROSSCHAIN_EXPORT))});
            dests = std::vector<CTxDestination>({pkCC});

            CCrossChainExport ccx(ConnectedChains.ThisChain().GetID(), 0, CCurrencyValueMap(), CCurrencyValueMap());
            coinbaseTx.vout.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CCrossChainExport>(EVAL_CROSSCHAIN_EXPORT, dests, 1, &ccx), &indexDests)));
        }

        // process any imports from the current chain to itself, to suport token launches, etc.
        // TODO: should also add refund checking here
        ProcessNewImports(ConnectedChains.ThisChain().GetID(), CTransaction(), nHeight);

        // coinbase should have all necessary outputs (TODO: timelock is not supported yet)
        uint32_t nCoinbaseSize = GetSerializeSize(coinbaseTx, SER_NETWORK, PROTOCOL_VERSION);
        nBlockSize += nCoinbaseSize;

        // now create the priority array, including market order reserve transactions, since they can always execute, leave limits for later
        bool haveReserveTransactions = false;
        uint32_t reserveExchangeLimitSize = 0;
        std::vector<CReserveTransactionDescriptor> limitOrders;

        // now add transactions from the mem pool to the priority heap
        for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->GetTx();
            uint256 hash = tx.GetHash();
            
            int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
            ? nMedianTimePast
            : pblock->GetBlockTime();

            if (tx.IsCoinBase() || !IsFinalTx(tx, nHeight, nLockTimeCutoff) || IsExpiredTx(tx, nHeight))
            {
                //fprintf(stderr,"coinbase.%d finaltx.%d expired.%d\n",tx.IsCoinBase(),IsFinalTx(tx, nHeight, nLockTimeCutoff),IsExpiredTx(tx, nHeight));
                continue;
            }

            if ( ASSETCHAINS_SYMBOL[0] == 0 && komodo_validate_interest(tx,nHeight,(uint32_t)pblock->nTime,0) < 0 )
            {
                //fprintf(stderr,"CreateNewBlock: komodo_validate_interest failure nHeight.%d nTime.%u vs locktime.%u\n",nHeight,(uint32_t)pblock->nTime,(uint32_t)tx.nLockTime);
                continue;
            }

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            CCurrencyValueMap totalReserveIn;
            bool fMissingInputs = false;
            CReserveTransactionDescriptor rtxd;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, rtxd);

            if (tx.IsCoinImport())
            {
                CAmount nValueIn = GetCoinImportValue(tx);
                nTotalIn += nValueIn;
                dPriority += (double)nValueIn * 1000;  // flat multiplier
            } else {
                // separate limit orders to be added later, we add them at the end, failed fill or kills are normal transactions, consider them reserve txs
                if (isReserve && rtxd.IsReserveExchange() && rtxd.IsLimit())
                {
                    // if we might expire, refresh and check again
                    if (rtxd.IsFillOrKill())
                    {
                        rtxd = CReserveTransactionDescriptor(tx, view, nHeight);
                        mempool.PrioritiseReserveTransaction(rtxd, currencyState);
                    }

                    // if is is a failed conversion, drop through
                    if (!rtxd.IsFillOrKillFail())
                    {
                        limitOrders.push_back(rtxd);
                        reserveExchangeLimitSize += GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                        continue;
                    }
                }
                if (isReserve)
                {
                    nTotalIn += rtxd.nativeIn;
                    totalReserveIn += rtxd.ReserveInputMap();
                    if (rtxd.IsIdentity() && CNameReservation(tx).IsValid())
                    {
                        nCurrentIDSize += GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                        if (nCurrentIDSize > nMaxIDSize)
                        {
                            continue;
                        }
                    }
                }
                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {
                    CAmount nValueIn = 0;
                    CCurrencyValueMap reserveValueIn;

                    // Read prev transaction
                    if (!view.HaveCoins(txin.prevout.hash))
                    {
                        // This should never happen; all transactions in the memory
                        // pool should connect to either transactions in the chain
                        // or other transactions in the memory pool.
                        if (!mempool.mapTx.count(txin.prevout.hash))
                        {
                            LogPrintf("ERROR: mempool transaction missing input\n");
                            if (fDebug) assert("mempool transaction missing input" == 0);
                            fMissingInputs = true;
                            if (porphan)
                                vOrphan.pop_back();
                            break;
                        }

                        // Has to wait for dependencies
                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);

                        const CTransaction &otx = mempool.mapTx.find(txin.prevout.hash)->GetTx();
                        // consider reserve outputs and set priority according to their value here as well
                        if (isReserve)
                        {
                            totalReserveIn += otx.vout[txin.prevout.n].ReserveOutValue();
                        }
                        nTotalIn += otx.vout[txin.prevout.n].nValue;
                        continue;
                    }
                    const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                    assert(coins);

                    if (isReserve)
                    {
                        reserveValueIn = coins->vout[txin.prevout.n].ReserveOutValue();
                    }

                    nValueIn = coins->vout[txin.prevout.n].nValue;
                    int nConf = nHeight - coins->nHeight;

                    dPriority += ((double)((reserveValueIn.valueMap.size() ? currencyState.ReserveToNative(reserveValueIn) : 0) + nValueIn)) * nConf;

                    if (!isReserve)
                    {
                        nTotalIn += nValueIn;
                        totalReserveIn += reserveValueIn;
                    }
                }
                nTotalIn += tx.GetShieldedValueIn();
            }

            if (fMissingInputs) continue;
            
            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);
            
            CAmount nDeltaValueIn = nTotalIn + (totalReserveIn.valueMap.size() ? currencyState.ReserveToNative(totalReserveIn) : 0);
            CAmount nFeeValueIn = nDeltaValueIn;
            mempool.ApplyDeltas(hash, dPriority, nDeltaValueIn);

            CAmount nativeEquivalentOut = 0;

            // if there is reserve in, or this is a reserveexchange transaction, calculate fee properly
            if (isReserve && rtxd.ReserveOutputMap().valueMap.size())
            {
                // if this has reserve currency out, convert it to native currency for fee calculation
                nativeEquivalentOut = currencyState.ReserveToNative(rtxd.ReserveOutputMap());
            }

            CFeeRate feeRate(isReserve ? rtxd.AllFeesAsNative(currencyState) + currencyState.ReserveToNative(rtxd.ReserveConversionFeesMap()) + rtxd.nativeConversionFees : 
                                         nFeeValueIn - (tx.GetValueOut() + nativeEquivalentOut), nTxSize);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, feeRate, &(mi->GetTx())));
        }

        //
        // NOW -- REALLY START TO FILL THE BLOCK
        //
        // estimate number of conversions, staking transaction size, and additional coinbase outputs that will be required

        int32_t maxPreLimitOrderBlockSize = nBlockMaxSize - std::min(nBlockMaxSize >> 2, reserveExchangeLimitSize);

        int64_t interest;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        std::vector<int> reservePositions;

        // now loop and fill the block, leaving space for reserve exchange limit transactions
        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());
            
            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();
            
            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= maxPreLimitOrderBlockSize - autoTxSize) // room for extra autotx
            {
                //fprintf(stderr,"nBlockSize %d + %d nTxSize >= %d maxPreLimitOrderBlockSize\n",(int32_t)nBlockSize,(int32_t)nTxSize,(int32_t)maxPreLimitOrderBlockSize);
                continue;
            }
            
            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"A nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }
            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                //fprintf(stderr,"fee rate skip\n");
                continue;
            }

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }
            
            if (!view.HaveInputs(tx))
            {
                //fprintf(stderr,"dont have inputs\n");
                continue;
            }
            CAmount nTxFees;
            CReserveTransactionDescriptor txDesc;
            bool isReserve = mempool.IsKnownReserveTransaction(hash, txDesc);

            nTxFees = view.GetValueIn(chainActive.LastTip()->GetHeight(),&interest,tx,chainActive.LastTip()->nTime)-tx.GetValueOut();
            
            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"B nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            PrecomputedTransactionData txdata(tx);
            if (!ContextualCheckInputs(tx, state, view, nHeight, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), consensusBranchId))
            {
                //fprintf(stderr,"context failure\n");
                continue;
            }

            UpdateCoins(tx, view, nHeight);

            if (isReserve)
            {
                nTxFees = 0;            // we will adjust all reserve transaction fees when we get an accurate conversion rate
                reservePositions.push_back(nBlockTx);
                haveReserveTransactions = true;
            }

            BOOST_FOREACH(const OutputDescription &outDescription, tx.vShieldedOutput) {
                sapling_tree.append(outDescription.cm);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;
            
            if (fPrintPriority)
            {
                LogPrintf("priority %.1f fee %s txid %s\n",dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }
            
            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        // if we have reserve transactions or limit transactions to add:
        // 1. collect all the reserve transactions from the block and add them to the reserveFills vector
        // 2. add all limit transactions to the orders vector
        // 3. match orders to include all limit transactions that qualify and will fit
        CAmount conversionFees = 0;

        if (haveReserveTransactions)
        {
            std::vector<CReserveTransactionDescriptor> reserveFills;
            std::vector<CReserveTransactionDescriptor> noFills;
            std::vector<const CReserveTransactionDescriptor *> expiredFillOrKills;
            std::vector<const CReserveTransactionDescriptor *> rejects;

            // identify all reserve transactions in the block to calculate fees
            for (int i = 0; i < reservePositions.size(); i++)
            {
                CReserveTransactionDescriptor txDesc;
                if (mempool.IsKnownReserveTransaction(pblock->vtx[reservePositions[i]].GetHash(), txDesc))
                {
                    reserveFills.push_back(txDesc);
                }
            }

            // now, we need to have room for the transaction which will spend the coinbase
            // and output all conversions mined/staked
            newConversionOutputTx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nHeight);
            newConversionOutputTx.vin.resize(1); // placeholder for size calculation

            int64_t newBlockSize = nBlockSize;

            // TODO:PBAAS - NEED TO ADD SIGOPS LIMIT TO THIS FOR HARDENING
            CCoinbaseCurrencyState newState = currencyState.MatchOrders(limitOrders,
                                                                        reserveFills,
                                                                        noFills,
                                                                        expiredFillOrKills,
                                                                        rejects,
                                                                        exchangeRate, 
                                                                        nHeight, 
                                                                        conversionInputs,
                                                                        nBlockMaxSize - autoTxSize, 
                                                                        &newBlockSize, 
                                                                        &newConversionOutputTx);

            // TODO:PBAAS - account for the edge case where we have too large expected fills and have no room
            // for transactions that we would otherwise take
            assert(reserveFills.size() >= reservePositions.size());

            // create the conversion transaction and all outputs indicated by every single mined transaction
            if (reserveFills.size())
            {
                currencyState = newState;
            }

            int oldRPSize = reservePositions.size();

            // add the rest of the reserve fills that have not yet been added to the block,
            for (int i = oldRPSize; i < reserveFills.size(); i++)
            {
                // add these transactions to the block
                reservePositions.push_back(nBlockTx);
                pblock->vtx.push_back(*reserveFills[i].ptx);
                const CTransaction &tx = pblock->vtx.back();

                UpdateCoins(tx, view, nHeight);

                BOOST_FOREACH(const OutputDescription &outDescription, tx.vShieldedOutput) {
                    sapling_tree.append(outDescription.cm);
                }

                CAmount nTxFees = reserveFills[i].AllFeesAsNative(currencyState, exchangeRate);
                uint32_t nTxSigOps = GetLegacySigOpCount(tx);

                // size was already updated
                pblocktemplate->vTxFees.push_back(nTxFees);
                pblocktemplate->vTxSigOps.push_back(nTxSigOps);
                ++nBlockTx;
                nBlockSigOps += nTxSigOps;
                nFees += nTxFees;
            }

            // update block size with the calculation from the function called, which includes all additional transactions, 
            // but does not include the conversion transaction, since its final size is still unknown
            nBlockSize = newBlockSize;

            // fixup the transaction block template fees that were added before we knew the correct exchange rate and
            // add them to the block fee total
            for (int i = 0; i < oldRPSize; i++)
            {
                assert(pblocktemplate->vTxFees.size() > reservePositions[i]);
                CAmount nTxFees = reserveFills[i].AllFeesAsNative(currencyState, exchangeRate);
                pblocktemplate->vTxFees[reservePositions[i]] = nTxFees;
                nFees += nTxFees;
            }

            // remake the newConversionOutputTx, right now, it has dummy inputs and placeholder outputs, just remake it correctly
            newConversionOutputTx.vin.resize(1);
            newConversionOutputTx.vout.clear();
            conversionInputs.clear();

            // keep one placeholder for txCoinbase output as input and remake with the correct exchange rate
            for (auto fill : reserveFills)
            {
                fill.AddConversionInOuts(newConversionOutputTx, conversionInputs, CCurrencyValueMap(currencyState.currencies, exchangeRate), &currencyState);
            }
        }

        // first calculate and distribute block rewards, including fees in the minerOutputs vector
        CAmount rewardTotalShareAmount = 0;
        CAmount rewardTotal = blockSubsidy + 
                              currencyState.nativeConversionFees + 
                              currencyState.ReserveToNativeRaw(CCurrencyValueMap(currencyState.currencies, currencyState.conversionFees), exchangeRate) + 
                              currencyState.ReserveToNativeRaw(CCurrencyValueMap(currencyState.currencies, currencyState.fees), exchangeRate) + 
                              nFees;

        CAmount rewardLeft = notarizationTxIndex ? rewardTotal - notarizationOut.nValue : rewardTotal;

        // now that we have the total reward, update the coinbase outputs
        if (isStake)
        {
            coinbaseTx.vout[0].nValue = rewardLeft;
        }
        else
        {
            for (auto &outputShare : minerOutputs)
            {
                rewardTotalShareAmount += outputShare.first;
            }

            int cbOutIdx;
            for (cbOutIdx = 0; cbOutIdx < minerOutputs.size(); cbOutIdx++)
            {
                CAmount amount = (arith_uint256(rewardTotal) * arith_uint256(minerOutputs[cbOutIdx].first) / arith_uint256(rewardTotalShareAmount)).GetLow64();
                if (rewardLeft <= amount || (cbOutIdx + 1) == minerOutputs.size())
                {
                    amount = rewardLeft;
                }
                rewardLeft -= amount;
                coinbaseTx.vout[cbOutIdx].nValue = amount;
                // the only valid CC output we currently support on coinbases is stake guard, which does not need to be modified for this
            }
        }

        // currencyStateOut - update currency state, output is present whether or not there is a conversion transaction
        // the transaction itself pays no fees, but all conversion fees are included for each conversion transaction between its input and this output
        if (currencyStateOut.scriptPubKey.size())
        {
            COptCCParams p;
            currencyStateOut.scriptPubKey.IsPayToCryptoCondition(p);
            p.vData[0] = currencyState.AsVector();
            currencyStateOut.scriptPubKey.ReplaceCCParams(p);

            if (conversionInputs.size())
            {
                CTransaction convertTx(newConversionOutputTx);
                currencyStateOut.nValue = convertTx.GetValueOut();

                auto reserveOutMap = convertTx.GetReserveValueOut();
                for (int i = 0; i < currencyState.currencies.size(); i++)
                {
                    auto it = reserveOutMap.valueMap.find(currencyState.currencies[i]);
                    currencyState.reserveOut[i] = (it != reserveOutMap.valueMap.end()) ? it->second : 0;
                }

                // the coinbase is not finished, store index placeholder here now and fixup hash later
                newConversionOutputTx.vin[0] = CTxIn(uint256(), currencyStateOutNum);
            }
            else
            {
                newConversionOutputTx.vin.clear();
                newConversionOutputTx.vout.clear();
            }

            coinbaseTx.vout[currencyStateOutNum] = currencyStateOut;
        }

        // notarizationOut - update currencyState in notarization
        if (notarizationTxIndex)
        {
            COptCCParams p;
            int i;
            for (i = 0; i < newNotarizationTx.vout.size(); i++)
            {
                if (newNotarizationTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_EARNEDNOTARIZATION)
                {
                    break;
                }
            }
            if (i >= newNotarizationTx.vout.size())
            {
                LogPrintf("CreateNewBlock: bad notarization\n");
                fprintf(stderr,"CreateNewBlock: bad notarization\n");
                return NULL;
            }
            CPBaaSNotarization nz(p.vData[0]);
            nz.currencyState = currencyState;
            p.vData[0] = nz.AsVector();
            newNotarizationTx.vout[i].scriptPubKey.ReplaceCCParams(p);

            notarizationOut.scriptPubKey.IsPayToCryptoCondition(p);
            p.vData[0] = nz.AsVector();
            notarizationOut.scriptPubKey.ReplaceCCParams(p);

            coinbaseTx.vout[notarizationOutNum] = notarizationOut;

            // now that the coinbase is finished, finish and place conversion transaction before the stake transaction
            newNotarizationTx.vin.push_back(CTxIn(uint256(), notarizationOutNum));

            pblock->vtx[notarizationTxIndex] = newNotarizationTx;
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        blocktime = std::max(pindexPrev->GetMedianTimePast(), GetAdjustedTime());

        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());

        coinbaseTx.nExpiryHeight = 0;
        coinbaseTx.nLockTime = blocktime;

        if ( ASSETCHAINS_SYMBOL[0] == 0 && IS_KOMODO_NOTARY != 0 && My_notaryid >= 0 )
            coinbaseTx.vout[0].nValue += 5000;

        /*
        // check if coinbase transactions must be time locked at current subsidy and prepend the time lock
        // to transaction if so, cast for GTE operator
        CAmount cbValueOut = 0;
        for (auto txout : coinbaseTx.vout)
        {
            cbValueOut += txout.nValue;
        }
        if (cbValueOut >= ASSETCHAINS_TIMELOCKGTE)
        {
            int32_t opretlen, p2shlen, scriptlen;
            CScriptExt opretScript = CScriptExt();

            coinbaseTx.vout.push_back(CTxOut());

            // prepend time lock to original script unless original script is P2SH, in which case, we will leave the coins
            // protected only by the time lock rather than 100% inaccessible
            opretScript.AddCheckLockTimeVerify(komodo_block_unlocktime(nHeight));
            if (scriptPubKeyIn.IsPayToScriptHash() || scriptPubKeyIn.IsPayToCryptoCondition())
            {
                LogPrintf("CreateNewBlock: attempt to add timelock to pay2sh or pay2cc\n");
                fprintf(stderr,"CreateNewBlock: attempt to add timelock to pay2sh or pay2cc\n");
                return 0;
            }
            
            opretScript += scriptPubKeyIn;

            coinbaseTx.vout[0].scriptPubKey = CScriptExt().PayToScriptHash(CScriptID(opretScript));
            coinbaseTx.vout.back().scriptPubKey = CScriptExt().OpReturnScript(opretScript, OPRETTYPE_TIMELOCK);
            coinbaseTx.vout.back().nValue = 0;
        } // timelocks and commissions are currently incompatible due to validation complexity of the combination
        else if ( nHeight > 1 && ASSETCHAINS_SYMBOL[0] != 0 && ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 && ASSETCHAINS_COMMISSION != 0 && (commission= komodo_commission((CBlock*)&pblocktemplate->block)) != 0 )
        {
            int32_t i; uint8_t *ptr;
            coinbaseTx.vout.resize(2);
            coinbaseTx.vout[1].nValue = commission;
            coinbaseTx.vout[1].scriptPubKey.resize(35);
            ptr = (uint8_t *)&coinbaseTx.vout[1].scriptPubKey[0];
            ptr[0] = 33;
            for (i=0; i<33; i++)
                ptr[i+1] = ASSETCHAINS_OVERRIDE_PUBKEY33[i];
            ptr[34] = OP_CHECKSIG;
            //printf("autocreate commision vout\n");
        }
        */

        // finalize input of coinbase
        coinbaseTx.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(0)) + COINBASE_FLAGS;
        assert(coinbaseTx.vin[0].scriptSig.size() <= 100);

        // coinbase is done
        pblock->vtx[0] = coinbaseTx;
        uint256 cbHash = coinbaseTx.GetHash();

        // if there is a conversion, update the correct coinbase hash and add it to the block
        // we also need to sign the conversion transaction
        if (newConversionOutputTx.vin.size() > 1)
        {
            // put the coinbase into the updated coins, since we will spend from it
            UpdateCoins(pblock->vtx[0], view, nHeight);

            newConversionOutputTx.vin[0].prevout.hash = cbHash;

            CTransaction ncoTx(newConversionOutputTx);

            // sign transaction for cb output and conversions
            for (int i = 0; i < ncoTx.vin.size(); i++)
            {
                bool signSuccess;
                SignatureData sigdata;
                CAmount value;
                const CScript *pScriptPubKey;

                // if this is our coinbase input, different signing
                if (i)
                {
                    pScriptPubKey = &conversionInputs[i - 1].scriptPubKey;
                    value = conversionInputs[i - 1].nValue;
                }
                else
                {
                    pScriptPubKey = &coinbaseTx.vout[ncoTx.vin[i].prevout.n].scriptPubKey;
                    value = coinbaseTx.vout[ncoTx.vin[i].prevout.n].nValue;
                }

                signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &ncoTx, i, value, SIGHASH_ALL), *pScriptPubKey, sigdata, consensusBranchId);

                if (!signSuccess)
                {
                    if (ncoTx.vin[i].prevout.hash == coinbaseTx.GetHash())
                    {
                        LogPrintf("Coinbase conversion source tx id: %s\n", coinbaseTx.GetHash().GetHex().c_str());
                        printf("Coinbase conversion source tx - amount: %lu, n: %d, id: %s\n", coinbaseTx.vout[ncoTx.vin[i].prevout.n].nValue, ncoTx.vin[i].prevout.n, coinbaseTx.GetHash().GetHex().c_str());
                    }
                    LogPrintf("CreateNewBlock: failure to sign conversion tx for input %d from output %d of %s\n", i, ncoTx.vin[i].prevout.n, ncoTx.vin[i].prevout.hash.GetHex().c_str());
                    printf("CreateNewBlock: failure to sign conversion tx for input %d from output %d of %s\n", i, ncoTx.vin[i].prevout.n, ncoTx.vin[i].prevout.hash.GetHex().c_str());
                    return NULL;
                } else {
                    UpdateTransaction(newConversionOutputTx, i, sigdata);
                }
            }

            UpdateCoins(newConversionOutputTx, view, nHeight);
            pblock->vtx.push_back(newConversionOutputTx);
            pblocktemplate->vTxFees.push_back(0);
            int txSigOps = GetLegacySigOpCount(newConversionOutputTx);
            pblocktemplate->vTxSigOps.push_back(txSigOps);
            nBlockSize += GetSerializeSize(newConversionOutputTx, SER_NETWORK, PROTOCOL_VERSION);
            ++nBlockTx;
            nBlockSigOps += txSigOps;
        }

        // if there is a stake transaction, add it to the very end
        if (isStake)
        {
            UpdateCoins(txStaked, view, nHeight);
            pblock->vtx.push_back(txStaked);
            pblocktemplate->vTxFees.push_back(0);
            int txSigOps = GetLegacySigOpCount(txStaked);
            pblocktemplate->vTxSigOps.push_back(txSigOps);
            // already added to the block size above
            ++nBlockTx;
            nBlockSigOps += txSigOps;
        }

        extern CWallet *pwalletMain;

        // add final notarization and instant spend coinbase output hash fixup
        if (notarizationTxIndex)
        {
            LOCK(pwalletMain->cs_wallet);

            newNotarizationTx.vin.back().prevout.hash = cbHash;

            CTransaction ntx(newNotarizationTx);

            for (int i = 0; i < ntx.vin.size(); i++)
            {
                bool signSuccess;
                SignatureData sigdata;
                CAmount value;
                const CScript *pScriptPubKey;

                // if this is our coinbase input, we won't find it elsewhere
                if (i < notarizationInputs.size())
                {
                    pScriptPubKey = &notarizationInputs[i].scriptPubKey;
                    value = notarizationInputs[i].nValue;
                }
                else
                {
                    pScriptPubKey = &coinbaseTx.vout[ntx.vin[i].prevout.n].scriptPubKey;
                    value = coinbaseTx.vout[ntx.vin[i].prevout.n].nValue;
                }

                signSuccess = ProduceSignature(TransactionSignatureCreator(pwalletMain, &ntx, i, value, SIGHASH_ALL), *pScriptPubKey, sigdata, consensusBranchId);

                if (!signSuccess)
                {
                    if (ntx.vin[i].prevout.hash == coinbaseTx.GetHash())
                    {
                        LogPrintf("Coinbase source tx id: %s\n", coinbaseTx.GetHash().GetHex().c_str());
                        printf("Coinbase source tx - amount: %lu, n: %d, id: %s\n", coinbaseTx.vout[ntx.vin[i].prevout.n].nValue, ntx.vin[i].prevout.n, coinbaseTx.GetHash().GetHex().c_str());
                    }
                    LogPrintf("CreateNewBlock: failure to sign earned notarization for input %d from output %d of %s\n", i, ntx.vin[i].prevout.n, ntx.vin[i].prevout.hash.GetHex().c_str());
                    printf("CreateNewBlock: failure to sign earned notarization for input %d from output %d of %s\n", i, ntx.vin[i].prevout.n, ntx.vin[i].prevout.hash.GetHex().c_str());
                    return NULL;
                } else {
                    UpdateTransaction(newNotarizationTx, i, sigdata);
                }
            }
            pblocktemplate->vTxSigOps[notarizationTxIndex] = GetLegacySigOpCount(newNotarizationTx);

            // put now signed notarization back in the block
            pblock->vtx[notarizationTxIndex] = newNotarizationTx;

            LogPrintf("Coinbase source tx id: %s\n", coinbaseTx.GetHash().GetHex().c_str());
            //printf("Coinbase source tx id: %s\n", coinbaseTx.GetHash().GetHex().c_str());
            LogPrintf("adding notarization tx at height %d, index %d, id: %s\n", nHeight, notarizationTxIndex, newNotarizationTx.GetHash().GetHex().c_str());
            //printf("adding notarization tx at height %d, index %d, id: %s\n", nHeight, notarizationTxIndex, mntx.GetHash().GetHex().c_str());
            {
                LOCK(cs_main);
                for (auto input : newNotarizationTx.vin)
                {
                    LogPrintf("Earned notarization input n: %d, hash: %s, HaveCoins: %s\n", input.prevout.n, input.prevout.hash.GetHex().c_str(), pcoinsTip->HaveCoins(input.prevout.hash) ? "true" : "false");
                    //printf("Earned notarization input n: %d, hash: %s, HaveCoins: %s\n", input.prevout.n, input.prevout.hash.GetHex().c_str(), pcoinsTip->HaveCoins(input.prevout.hash) ? "true" : "false");
                }
            }
        }

        pblock->vtx[0] = coinbaseTx;
        pblocktemplate->vTxFees[0] = -nFees;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        // if not Verus stake, setup nonce, otherwise, leave it alone
        if (!isStake || ASSETCHAINS_LWMAPOS == 0)
        {
            // Randomize nonce
            arith_uint256 nonce = UintToArith256(GetRandHash());

            // Clear the top 16 and bottom 16 or 24 bits (for local use as thread flags and counters)
            nonce <<= ASSETCHAINS_NONCESHIFT[ASSETCHAINS_ALGO];
            nonce >>= 16;
            pblock->nNonce = ArithToUint256(nonce);
        }
        
        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->hashFinalSaplingRoot   = sapling_tree.root();

        // all Verus PoS chains need this data in the block at all times
        if ( ASSETCHAINS_LWMAPOS || ASSETCHAINS_SYMBOL[0] == 0 || ASSETCHAINS_STAKED == 0 || KOMODO_MININGTHREADS > 0 )
        {
            UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
        }

        if ( ASSETCHAINS_SYMBOL[0] == 0 && IS_KOMODO_NOTARY != 0 && My_notaryid >= 0 )
        {
            uint32_t r;
            CMutableTransaction txNotary = CreateNewContextualCMutableTransaction(Params().GetConsensus(), chainActive.Height() + 1);
            if ( pblock->nTime < pindexPrev->nTime+60 )
                pblock->nTime = pindexPrev->nTime + 60;
            if ( gpucount < 33 )
            {
                uint8_t tmpbuffer[40]; uint32_t r; int32_t n=0; uint256 randvals;
                memcpy(&tmpbuffer[n],&My_notaryid,sizeof(My_notaryid)), n += sizeof(My_notaryid);
                memcpy(&tmpbuffer[n],&Mining_height,sizeof(Mining_height)), n += sizeof(Mining_height);
                memcpy(&tmpbuffer[n],&pblock->hashPrevBlock,sizeof(pblock->hashPrevBlock)), n += sizeof(pblock->hashPrevBlock);
                vcalc_sha256(0,(uint8_t *)&randvals,tmpbuffer,n);
                memcpy(&r,&randvals,sizeof(r));
                pblock->nTime += (r % (33 - gpucount)*(33 - gpucount));
            }
            if ( komodo_notaryvin(txNotary,NOTARY_PUBKEY33) > 0 )
            {
                CAmount txfees = 5000;
                pblock->vtx.push_back(txNotary);
                pblocktemplate->vTxFees.push_back(txfees);
                pblocktemplate->vTxSigOps.push_back(GetLegacySigOpCount(txNotary));
                nFees += txfees;
                pblocktemplate->vTxFees[0] = -nFees;
                //*(uint64_t *)(&pblock->vtx[0].vout[0].nValue) += txfees;
                //fprintf(stderr,"added notaryvin\n");
            }
            else
            {
                fprintf(stderr,"error adding notaryvin, need to create 0.0001 utxos\n");
                return(0);
            }
        }
        else if ( ASSETCHAINS_CC == 0 && pindexPrev != 0 && ASSETCHAINS_STAKED == 0 && (ASSETCHAINS_SYMBOL[0] != 0 || IS_KOMODO_NOTARY == 0 || My_notaryid < 0) )
        {
            CValidationState state;
            //fprintf(stderr,"check validity\n");
            if ( !TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) // invokes CC checks
            {
                throw std::runtime_error("CreateNewBlock(): TestBlockValidity failed");
            }
            //fprintf(stderr,"valid\n");
        }
    }
    //fprintf(stderr,"done new block\n");

    // setup the header and buid the Merkle tree
    unsigned int extraNonce;
    IncrementExtraNonce(pblock, pindexPrev, extraNonce, true);

    return pblocktemplate.release();
}
 
/*
 #ifdef ENABLE_WALLET
 boost::optional<CScript> GetMinerScriptPubKey(CReserveKey& reservekey)
 #else
 boost::optional<CScript> GetMinerScriptPubKey()
 #endif
 {
 CKeyID keyID;
 CBitcoinAddress addr;
 if (addr.SetString(GetArg("-mineraddress", ""))) {
 addr.GetKeyID(keyID);
 } else {
 #ifdef ENABLE_WALLET
 CPubKey pubkey;
 if (!reservekey.GetReservedKey(pubkey)) {
 return boost::optional<CScript>();
 }
 keyID = pubkey.GetID();
 #else
 return boost::optional<CScript>();
 #endif
 }
 
 CScript scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
 return scriptPubKey;
 }
 
 #ifdef ENABLE_WALLET
 CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
 {
 boost::optional<CScript> scriptPubKey = GetMinerScriptPubKey(reservekey);
 #else
 CBlockTemplate* CreateNewBlockWithKey()
 {
 boost::optional<CScript> scriptPubKey = GetMinerScriptPubKey();
 #endif
 
 if (!scriptPubKey) {
 return NULL;
 }
 return CreateNewBlock(*scriptPubKey);
 }*/

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

#ifdef ENABLE_MINING

class MinerAddressScript : public CReserveScript
{
    // CReserveScript requires implementing this function, so that if an
    // internal (not-visible) wallet address is used, the wallet can mark it as
    // important when a block is mined (so it then appears to the user).
    // If -mineraddress is set, the user already knows about and is managing the
    // address, so we don't need to do anything here.
    void KeepScript() {}
};

void GetScriptForMinerAddress(boost::shared_ptr<CReserveScript> &script)
{
    CTxDestination addr = DecodeDestination(GetArg("-mineraddress", ""));
    if (!IsValidDestination(addr)) {
        return;
    }

    boost::shared_ptr<MinerAddressScript> mAddr(new MinerAddressScript());
    CKeyID keyID = boost::get<CKeyID>(addr);

    script = mAddr;
    script->reserveScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, int32_t nHeight, int32_t gpucount, bool isStake)
{
    CPubKey pubkey; CScript scriptPubKey; uint8_t *ptr; int32_t i;
    if ( nHeight == 1 && ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 )
    {
        scriptPubKey = CScript() << ParseHex(ASSETCHAINS_OVERRIDE_PUBKEY) << OP_CHECKSIG;
    }
    else if ( USE_EXTERNAL_PUBKEY != 0 )
    {
        //fprintf(stderr,"use notary pubkey\n");
        scriptPubKey = CScript() << ParseHex(NOTARY_PUBKEY) << OP_CHECKSIG;
    }
    else
    {
        if (!isStake)
        {
            if (!reservekey.GetReservedKey(pubkey))
            {
                return NULL;
            }
            scriptPubKey.resize(35);
            ptr = (uint8_t *)pubkey.begin();
            scriptPubKey[0] = 33;
            for (i=0; i<33; i++)
                scriptPubKey[i+1] = ptr[i];
            scriptPubKey[34] = OP_CHECKSIG;
            //scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
        }
    }
    return CreateNewBlock(Params(), scriptPubKey, gpucount, isStake);
}

void komodo_broadcast(const CBlock *pblock,int32_t limit)
{
    int32_t n = 1;
    //fprintf(stderr,"broadcast new block t.%u\n",(uint32_t)time(NULL));
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if ( pnode->hSocket == INVALID_SOCKET )
                continue;
            if ( (rand() % n) == 0 )
            {
                pnode->PushMessage("block", *pblock);
                if ( n++ > limit )
                    break;
            }
        }
    }
    //fprintf(stderr,"finished broadcast new block t.%u\n",(uint32_t)time(NULL));
}

static bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
#else
static bool ProcessBlockFound(CBlock* pblock)
#endif // ENABLE_WALLET
{
    int32_t height = chainActive.LastTip()->GetHeight()+1;
    //LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s height.%d\n", FormatMoney(pblock->vtx[0].vout[0].nValue), height);

    // Found a solution
    {
        if (pblock->hashPrevBlock != chainActive.LastTip()->GetBlockHash())
        {
            uint256 hash; int32_t i;
            hash = pblock->hashPrevBlock;
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- prev (stale)\n");
            hash = chainActive.LastTip()->GetBlockHash();
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- chainTip (stale)\n");
            
            return error("VerusMiner: generated block is stale");
        }
    }
    
#ifdef ENABLE_WALLET
    // Remove key from key pool
    if ( IS_KOMODO_NOTARY == 0 )
    {
        if (GetArg("-mineraddress", "").empty()) {
            // Remove key from key pool
            reservekey.KeepKey();
        }
    }
    // Track how many getdata requests this block gets
    //if ( 0 )
    {
        //fprintf(stderr,"lock cs_wallet\n");
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }
#endif
    //fprintf(stderr,"process new block\n");

    // Process this block (almost) the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(1, chainActive.LastTip()->GetHeight()+1, state, Params(), NULL, pblock, true, NULL))
        return error("VerusMiner: ProcessNewBlock, block not accepted");
    
    TrackMinedBlock(pblock->GetHash());
    komodo_broadcast(pblock,16);
    return true;
}

int32_t komodo_baseid(char *origbase);
int32_t komodo_eligiblenotary(uint8_t pubkeys[66][33],int32_t *mids,uint32_t *blocktimes,int32_t *nonzpkeysp,int32_t height);
arith_uint256 komodo_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);
int32_t FOUND_BLOCK,KOMODO_MAYBEMINED;
extern int32_t KOMODO_LASTMINED,KOMODO_INSYNC;
int32_t roundrobin_delay;
arith_uint256 HASHTarget,HASHTarget_POW;
int32_t komodo_longestchain();

// wait for peers to connect
void waitForPeers(const CChainParams &chainparams)
{
    if (chainparams.MiningRequiresPeers())
    {
        bool fvNodesEmpty;
        {
            boost::this_thread::interruption_point();
            LOCK(cs_vNodes);
            fvNodesEmpty = vNodes.empty();
        }
        int longestchain = komodo_longestchain();
        int lastlongest = 0;
        if (fvNodesEmpty || IsNotInSync() || (longestchain != 0 && longestchain > chainActive.LastTip()->GetHeight()))
        {
            int loops = 0, blockDiff = 0, newDiff = 0;
            
            do {
                if (fvNodesEmpty)
                {
                    MilliSleep(1000 + rand() % 4000);
                    boost::this_thread::interruption_point();
                    LOCK(cs_vNodes);
                    fvNodesEmpty = vNodes.empty();
                    loops = 0;
                    blockDiff = 0;
                    lastlongest = 0;
                }
                else if ((newDiff = IsNotInSync()) > 0)
                {
                    if (blockDiff != newDiff)
                    {
                        blockDiff = newDiff;
                    }
                    else
                    {
                        if (++loops <= 5)
                        {
                            MilliSleep(1000);
                        }
                        else break;
                    }
                    lastlongest = 0;
                }
                else if (!fvNodesEmpty && !IsNotInSync() && longestchain > chainActive.LastTip()->GetHeight())
                {
                    // the only thing may be that we are seeing a long chain that we'll never get
                    // don't wait forever
                    if (lastlongest == 0)
                    {
                        MilliSleep(3000);
                        lastlongest = longestchain;
                    }
                }
            } while (fvNodesEmpty || IsNotInSync());
            MilliSleep(500 + rand() % 1000);
        }
    }
}

#ifdef ENABLE_WALLET
CBlockIndex *get_chainactive(int32_t height)
{
    if ( chainActive.LastTip() != 0 )
    {
        if ( height <= chainActive.LastTip()->GetHeight() )
        {
            LOCK(cs_main);
            return(chainActive[height]);
        }
        // else fprintf(stderr,"get_chainactive height %d > active.%d\n",height,chainActive.Tip()->GetHeight());
    }
    //fprintf(stderr,"get_chainactive null chainActive.Tip() height %d\n",height);
    return(0);
}

/*
 * A separate thread to stake, while the miner threads mine.
 */
void static VerusStaker(CWallet *pwallet)
{
    LogPrintf("Verus staker thread started\n");
    RenameThread("verus-staker");

    const CChainParams& chainparams = Params();
    auto consensusParams = chainparams.GetConsensus();

    // Each thread has its own key
    CReserveKey reservekey(pwallet);

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    try {
        static int32_t lastStakingHeight = 0;

        while (true)
        {
            waitForPeers(chainparams);
            CBlockIndex* pindexPrev = chainActive.LastTip();

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();

            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            // try to stake a block
            CBlockTemplate *ptr = NULL;

            // get height locally for consistent reporting
            int32_t newHeight = Mining_height;

            if (newHeight > VERUS_MIN_STAKEAGE)
                ptr = CreateNewBlockWithKey(reservekey, newHeight, 0, true);

            // TODO - putting this output here tends to help mitigate announcing a staking height earlier than
            // announcing the last block win when we start staking before a block's acceptance has been
            // acknowledged by the mining thread - a better solution may be to put the output on the submission
            // thread.
            if ( ptr == 0 && newHeight != lastStakingHeight )
            {
                printf("Staking height %d for %s\n", newHeight, ASSETCHAINS_SYMBOL);
            }
            lastStakingHeight = newHeight;

            if ( ptr == 0 )
            {
                // wait to try another staking block until after the tip moves again
                while ( chainActive.LastTip() == pindexPrev )
                    MilliSleep(250);
                continue;
            }

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in %s staker: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                              ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in %s staker: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                }
                return;
            }

            CBlock *pblock = &pblocktemplate->block;
            LogPrintf("Staking with %u transactions in block (%u bytes)\n", pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            if (vNodes.empty() && chainparams.MiningRequiresPeers())
            {
                if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                {
                    fprintf(stderr,"no nodes, attempting reconnect\n");
                    continue;
                }
            }

            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            {
                fprintf(stderr,"timeout, retrying\n");
                continue;
            }

            if ( pindexPrev != chainActive.LastTip() )
            {
                printf("Block %d added to chain\n", chainActive.LastTip()->GetHeight());
                MilliSleep(250);
                continue;
            }

            int32_t unlockTime = komodo_block_unlocktime(Mining_height);
            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);

            uint256 hashTarget = ArithToUint256(arith_uint256().SetCompact(pblock->nBits));

            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

            UpdateTime(pblock, consensusParams, pindexPrev);

            if (ProcessBlockFound(pblock, *pwallet, reservekey))
            {
                LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                LogPrintf("Staked block found  \n  hash: %s  \ntarget: %s\n", pblock->GetHash().GetHex(), hashTarget.GetHex());
                printf("Found block %d \n", newHeight);
                printf("staking reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                arith_uint256 post;
                post.SetCompact(pblock->GetVerusPOSTarget());

                CTransaction &sTx = pblock->vtx[pblock->vtx.size()-1];
                printf("POS hash: %s  \ntarget:   %s\n", 
                    CTransaction::_GetVerusPOSHash(&(pblock->nNonce), 
                                                     sTx.vin[0].prevout.hash, 
                                                     sTx.vin[0].prevout.n, 
                                                     newHeight, 
                                                     chainActive.GetVerusEntropyHash(Mining_height), 
                                                     sTx.vout[0].nValue).GetHex().c_str(), 
                                                     ArithToUint256(post).GetHex().c_str());
                if (unlockTime > newHeight && subsidy >= ASSETCHAINS_TIMELOCKGTE)
                    printf("- timelocked until block %i\n", unlockTime);
                else
                    printf("\n");
            }
            else
            {
                LogPrintf("Found block rejected at staking height: %d\n", Mining_height);
                printf("Found block rejected at staking height: %d\n", Mining_height);
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();

            sleep(3);

            // In regression test mode, stop mining after a block is found.
            if (chainparams.MineBlocksOnDemand()) {
                throw boost::thread_interrupted();
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("VerusStaker terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("VerusStaker runtime error: %s\n", e.what());
        return;
    }
}

typedef bool (*minefunction)(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);
bool mine_verus_v2_port(CBlockHeader &bh, CVerusHashV2bWriter &vhw, uint256 &finalHash, uint256 &target, uint64_t start, uint64_t *count);

void static BitcoinMiner_noeq(CWallet *pwallet)
#else
void static BitcoinMiner_noeq()
#endif
{
    LogPrintf("%s miner started\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
    RenameThread("verushash-miner");

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif

    miningTimer.clear();

    const CChainParams& chainparams = Params();
    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total,checktoshis; int32_t i,j;

    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) ) //chainActive.Tip()->GetHeight() != 235300 &&
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }

    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // try a nice clean peer connection to start
    CBlockIndex *pindexPrev, *pindexCur;
    do {
        pindexPrev = chainActive.LastTip();
        MilliSleep(5000 + rand() % 5000);
        waitForPeers(chainparams);
        pindexCur = chainActive.LastTip();
    } while (pindexPrev != pindexCur);

    // make sure that we have checked for PBaaS availability
    ConnectedChains.CheckVerusPBaaSAvailable();

    // this will not stop printing more than once in all cases, but it will allow us to print in all cases
    // and print duplicates rarely without having to synchronize
    static CBlockIndex *lastChainTipPrinted;
    static int32_t lastMiningHeight = 0;

    miningTimer.start();

    try {
        printf("Mining %s with %s\n", ASSETCHAINS_SYMBOL, ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);

        while (true)
        {
            miningTimer.stop();
            waitForPeers(chainparams);

            pindexPrev = chainActive.LastTip();

            // prevent forking on startup before the diff algorithm kicks in,
            // but only for a startup Verus test chain. PBaaS chains have the difficulty inherited from
            // their parent
            if (chainparams.MiningRequiresPeers() && ((IsVerusActive() && pindexPrev->GetHeight() < 50) || pindexPrev != chainActive.LastTip()))
            {
                do {
                    pindexPrev = chainActive.LastTip();
                    MilliSleep(2000 + rand() % 2000);
                } while (pindexPrev != chainActive.LastTip());
            }

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                if (lastMiningHeight != Mining_height)
                {
                    lastMiningHeight = Mining_height;
                    printf("Mining %s at height %d\n", ASSETCHAINS_SYMBOL, Mining_height);
                }
                Mining_start = (uint32_t)time(NULL);
            }

            miningTimer.start();

#ifdef ENABLE_WALLET
            CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, Mining_height, 0);
#else
            CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif
            if ( ptr == 0 )
            {
                static uint32_t counter;
                if ( counter++ % 40 == 0 )
                {
                    if (!IsVerusActive() &&
                        ConnectedChains.IsVerusPBaaSAvailable() &&
                        ConnectedChains.notaryChainHeight < ConnectedChains.ThisChain().startBlock)
                    {
                        fprintf(stderr,"Waiting for block %d on %s chain to start. Current block is %d\n", ConnectedChains.ThisChain().startBlock,
                                                                                                           ConnectedChains.notaryChain.chainDefinition.name.c_str(),
                                                                                                           ConnectedChains.notaryChainHeight);
                    }
                    else
                    {
                        fprintf(stderr,"Unable to create valid block... will continue to try\n");
                    }
                }
                MilliSleep(2000);
                continue;
            }

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in %s miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n",
                              ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in %s miner: Invalid %s -mineraddress\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], ASSETCHAINS_SYMBOL);
                }
                miningTimer.stop();
                miningTimer.clear();
                return;
            }
            CBlock *pblock = &pblocktemplate->block;

            uint32_t savebits;
            bool mergeMining = false;
            savebits = pblock->nBits;

            uint32_t solutionVersion = CConstVerusSolutionVector::Version(pblock->nSolution);
            if (pblock->nVersion != CBlockHeader::VERUS_V2)
            {
                // must not be in sync
                printf("Mining on incorrect block version.\n");
                sleep(2);
                continue;
            }
            bool verusSolutionPBaaS = solutionVersion >= CActivationHeight::ACTIVATE_PBAAS;

            // v2 hash writer with adjustments for the current height
            CVerusHashV2bWriter ss2 = CVerusHashV2bWriter(SER_GETHASH, PROTOCOL_VERSION, solutionVersion);

            if ( ASSETCHAINS_SYMBOL[0] != 0 )
            {
                if ( ASSETCHAINS_REWARD[0] == 0 && !ASSETCHAINS_LASTERA )
                {
                    if ( pblock->vtx.size() == 1 && pblock->vtx[0].vout.size() == 1 && Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        static uint32_t counter;
                        if ( counter++ < 10 )
                            fprintf(stderr,"skip generating %s on-demand block, no tx avail\n",ASSETCHAINS_SYMBOL);
                        sleep(10);
                        continue;
                    } else fprintf(stderr,"%s vouts.%d mining.%d vs %d\n",ASSETCHAINS_SYMBOL,(int32_t)pblock->vtx[0].vout.size(),Mining_height,ASSETCHAINS_MINHEIGHT);
                }
            }

            // set our easiest target, if V3+, no need to rebuild the merkle tree
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, verusSolutionPBaaS ? false : true, &savebits);

            // update PBaaS header
            if (verusSolutionPBaaS)
            {
                if (!IsVerusActive() && ConnectedChains.IsVerusPBaaSAvailable())
                {

                    UniValue params(UniValue::VARR);
                    UniValue error(UniValue::VARR);
                    params.push_back(EncodeHexBlk(*pblock));
                    params.push_back(ASSETCHAINS_SYMBOL);
                    params.push_back(ASSETCHAINS_RPCHOST);
                    params.push_back(ASSETCHAINS_RPCPORT);
                    params.push_back(ASSETCHAINS_RPCCREDENTIALS);
                    try
                    {
                        ConnectedChains.lastSubmissionFailed = false;
                        params = RPCCallRoot("addmergedblock", params);
                        params = find_value(params, "result");
                        error = find_value(params, "error");
                    } catch (std::exception e)
                    {
                        printf("Failed to connect to %s chain\n", ConnectedChains.notaryChain.chainDefinition.name.c_str());
                        params = UniValue(e.what());
                    }
                    if (mergeMining = (params.isNull() && error.isNull()))
                    {
                        printf("Merge mining %s with %s as the hashing chain\n", ASSETCHAINS_SYMBOL, ConnectedChains.notaryChain.chainDefinition.name.c_str());
                        LogPrintf("Merge mining with %s as the hashing chain\n", ConnectedChains.notaryChain.chainDefinition.name.c_str());
                    }
                }
            }

            LogPrintf("Running %s miner with %u transactions in block (%u bytes)\n",ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO],
                       pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            int64_t nStart = GetTime();

            arith_uint256 hashTarget = arith_uint256().SetCompact(savebits);
            uint256 uintTarget = ArithToUint256(hashTarget);
            arith_uint256 ourTarget;
            ourTarget.SetCompact(pblock->nBits);

            Mining_start = 0;

            if ( pindexPrev != chainActive.LastTip() )
            {
                if (lastChainTipPrinted != chainActive.LastTip())
                {
                    lastChainTipPrinted = chainActive.LastTip();
                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                }
                MilliSleep(100);
                continue;
            }

            uint64_t count;
            uint64_t hashesToGo = 0;
            uint64_t totalDone = 0;

            int64_t subsidy = (int64_t)(pblock->vtx[0].vout[0].nValue);
            count = ((ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3) + 1) / ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
            CVerusHashV2 *vh2 = &ss2.GetState();
            u128 *hashKey;
            verusclhasher &vclh = vh2->vclh;
            minefunction mine_verus;
            mine_verus = IsCPUVerusOptimized() ? &mine_verus_v2 : &mine_verus_v2_port;

            while (true)
            {
                uint256 hashResult = uint256();

                unsigned char *curBuf;

                if (mergeMining)
                {
                    // loop for a few minutes before refreshing the block
                    while (true)
                    {
                        uint256 ourMerkle = pblock->hashMerkleRoot;
                        if ( pindexPrev != chainActive.LastTip() )
                        {
                            if (lastChainTipPrinted != chainActive.LastTip())
                            {
                                lastChainTipPrinted = chainActive.LastTip();
                                printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                                arith_uint256 target;
                                target.SetCompact(lastChainTipPrinted->nBits);
                                if (ourMerkle == lastChainTipPrinted->hashMerkleRoot)
                                {
                                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                    printf("Found block %d \n", lastChainTipPrinted->GetHeight());
                                    printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
                                    printf("  hash: %s\ntarget: %s\n", lastChainTipPrinted->GetBlockHash().GetHex().c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                                }
                            }
                            break;
                        }

                        // if PBaaS is no longer available, we can't count on merge mining
                        if (!ConnectedChains.IsVerusPBaaSAvailable())
                        {
                            break;
                        }

                        if (vNodes.empty() && chainparams.MiningRequiresPeers())
                        {
                            if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                            {
                                fprintf(stderr,"no nodes, attempting reconnect\n");
                                break;
                            }
                        }

                        // update every few minutes, regardless
                        int64_t elapsed = GetTime() - nStart;

                        if ((mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && elapsed > 60) || elapsed > 60 || ConnectedChains.lastSubmissionFailed)
                        {
                            break;
                        }

                        boost::this_thread::interruption_point();
                        MilliSleep(500);
                    }
                    break;
                }
                else
                {
                    // check NONCEMASK at a time
                    for (uint64_t i = 0; i < count; i++)
                    {
                        // this is the actual mining loop, which enables us to drop out and queue a header anytime we earn a block that is good enough for a
                        // merge mined block, but not our own
                        bool blockFound;
                        arith_uint256 arithHash;
                        totalDone = 0;
                        do
                        {
                            // pickup/remove any new/deleted headers
                            if (ConnectedChains.dirty || (pblock->NumPBaaSHeaders() < ConnectedChains.mergeMinedChains.size() + 1))
                            {
                                IncrementExtraNonce(pblock, pindexPrev, nExtraNonce, verusSolutionPBaaS ? false : true, &savebits);

                                hashTarget.SetCompact(savebits);
                                uintTarget = ArithToUint256(hashTarget);
                            }

                            // hashesToGo gets updated with actual number run for metrics
                            hashesToGo = ASSETCHAINS_HASHESPERROUND[ASSETCHAINS_ALGO];
                            uint64_t start = i * hashesToGo + totalDone;
                            hashesToGo -= totalDone;

                            if (verusSolutionPBaaS)
                            {
                                // mine on canonical header for merge mining
                                CPBaaSPreHeader savedHeader(*pblock);

                                pblock->ClearNonCanonicalData();
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                                savedHeader.SetBlockData(*pblock);
                            }
                            else
                            {
                                blockFound = (*mine_verus)(*pblock, ss2, hashResult, uintTarget, start, &hashesToGo);
                            }

                            arithHash = UintToArith256(hashResult);
                            totalDone += hashesToGo + 1;
                            if (blockFound && IsVerusActive())
                            {
                                ConnectedChains.QueueNewBlockHeader(*pblock);
                                if (arithHash > ourTarget)
                                {
                                    // all blocks qualified with this hash will be submitted
                                    // until we redo the block, we might as well not try again with anything over this hash
                                    hashTarget = arithHash;
                                    uintTarget = ArithToUint256(hashTarget);
                                }
                            }
                        } while (blockFound && arithHash > ourTarget);

                        if (!blockFound || arithHash > ourTarget)
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();
                            if ( pindexPrev != chainActive.LastTip() )
                            {
                                if (lastChainTipPrinted != chainActive.LastTip())
                                {
                                    lastChainTipPrinted = chainActive.LastTip();
                                    printf("Block %d added to chain\n", lastChainTipPrinted->GetHeight());
                                }
                                break;
                            }
                            else if ((i + 1) < count)
                            {
                                // if we'll not drop through, update hashcount
                                {
                                    miningTimer += totalDone;
                                    totalDone = 0;
                                }
                            }
                        }
                        else
                        {
                            // Check for stop or if block needs to be rebuilt
                            boost::this_thread::interruption_point();

                            if (pblock->nSolution.size() != 1344)
                            {
                                LogPrintf("ERROR: Block solution is not 1344 bytes as it should be");
                                break;
                            }

                            SetThreadPriority(THREAD_PRIORITY_NORMAL);

                            int32_t unlockTime = komodo_block_unlocktime(Mining_height);

#ifdef VERUSHASHDEBUG
                            std::string validateStr = hashResult.GetHex();
                            std::string hashStr = pblock->GetHash().GetHex();
                            uint256 *bhalf1 = (uint256 *)vh2->CurBuffer();
                            uint256 *bhalf2 = bhalf1 + 1;
#else
                            std::string hashStr = hashResult.GetHex();
#endif

                            LogPrintf("Using %s algorithm:\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
                            LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hashStr, ArithToUint256(ourTarget).GetHex());
                            printf("Found block %d \n", Mining_height );
                            printf("mining reward %.8f %s!\n", (double)subsidy / (double)COIN, ASSETCHAINS_SYMBOL);
#ifdef VERUSHASHDEBUG
                            printf("  hash: %s\n   val: %s  \ntarget: %s\n\n", hashStr.c_str(), validateStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
                            printf("intermediate %lx\n", intermediate);
                            printf("Curbuf: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
                            bhalf1 = (uint256 *)verusclhasher_key.get();
                            bhalf2 = bhalf1 + ((vh2->vclh.keyMask + 1) >> 5);
                            printf("   Key: %s%s\n", bhalf1->GetHex().c_str(), bhalf2->GetHex().c_str());
#else
                            printf("  hash: %s\ntarget: %s", hashStr.c_str(), ArithToUint256(ourTarget).GetHex().c_str());
#endif
                            if (unlockTime > Mining_height && subsidy >= ASSETCHAINS_TIMELOCKGTE)
                                printf(" - timelocked until block %i\n", unlockTime);
                            else
                                printf("\n");
#ifdef ENABLE_WALLET
                            ProcessBlockFound(pblock, *pwallet, reservekey);
#else
                            ProcessBlockFound(pblock);
#endif
                            SetThreadPriority(THREAD_PRIORITY_LOWEST);
                            break;
                        }
                    }

                    {
                        miningTimer += totalDone;
                    }
                }
                

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();

                if (vNodes.empty() && chainparams.MiningRequiresPeers())
                {
                    if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        fprintf(stderr,"no nodes, attempting reconnect\n");
                        break;
                    }
                }

                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                {
                    fprintf(stderr,"timeout, retrying\n");
                    break;
                }

                if ( pindexPrev != chainActive.LastTip() )
                {
                    if (lastChainTipPrinted != chainActive.LastTip())
                    {
                        lastChainTipPrinted = chainActive.LastTip();
                        printf("Block %d added to chain\n\n", lastChainTipPrinted->GetHeight());
                    }
                    break;
                }

                // totalDone now has the number of hashes actually done since starting on one nonce mask worth
                uint64_t hashesPerNonceMask = ASSETCHAINS_NONCEMASK[ASSETCHAINS_ALGO] >> 3;
                if (!(totalDone < hashesPerNonceMask))
                {
#ifdef _WIN32
                    printf("%llu mega hashes complete - working\n", (hashesPerNonceMask + 1) / 1048576);
#else
                    printf("%lu mega hashes complete - working\n", (hashesPerNonceMask + 1) / 1048576);
#endif
                }
                break;

            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner terminated\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO]);
        throw;
    }
    catch (const std::runtime_error &e)
    {
        miningTimer.stop();
        miningTimer.clear();
        LogPrintf("%s miner runtime error: %s\n", ASSETCHAINS_ALGORITHMS[ASSETCHAINS_ALGO], e.what());
        return;
    }
    miningTimer.stop();
    miningTimer.clear();
}

void static BitcoinMiner(CWallet *pwallet)
{
    LogPrintf("KomodoMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("komodo-miner");

    const CChainParams& chainparams = Params();

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif
    
    // Each thread has its own counter
    unsigned int nExtraNonce = 0;
    
    unsigned int n = chainparams.GetConsensus().EquihashN();
    unsigned int k = chainparams.GetConsensus().EquihashK();
    uint8_t *script; uint64_t total,checktoshis; int32_t i,j,gpucount=KOMODO_MAXGPUCOUNT,notaryid = -1;
    while ( (ASSETCHAIN_INIT == 0 || KOMODO_INITDONE == 0) )
    {
        sleep(1);
        if ( komodo_baseid(ASSETCHAINS_SYMBOL) < 0 )
            break;
    }
    if ( ASSETCHAINS_SYMBOL[0] == 0 )
        komodo_chosennotary(&notaryid,chainActive.LastTip()->GetHeight(),NOTARY_PUBKEY33,(uint32_t)chainActive.LastTip()->GetBlockTime());
    if ( notaryid != My_notaryid )
        My_notaryid = notaryid;
    std::string solver;
    //if ( notaryid >= 0 || ASSETCHAINS_SYMBOL[0] != 0 )
    solver = "tromp";
    //else solver = "default";
    assert(solver == "tromp" || solver == "default");
    LogPrint("pow", "Using Equihash solver \"%s\" with n = %u, k = %u\n", solver, n, k);
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
        fprintf(stderr,"notaryid.%d Mining.%s with %s\n",notaryid,ASSETCHAINS_SYMBOL,solver.c_str());
    std::mutex m_cs;
    bool cancelSolver = false;
    boost::signals2::connection c = uiInterface.NotifyBlockTip.connect(
                                                                       [&m_cs, &cancelSolver](const uint256& hashNewTip) mutable {
                                                                           std::lock_guard<std::mutex> lock{m_cs};
                                                                           cancelSolver = true;
                                                                       }
                                                                       );
    miningTimer.start();
    
    try {
        if ( ASSETCHAINS_SYMBOL[0] != 0 )
            fprintf(stderr,"try %s Mining with %s\n",ASSETCHAINS_SYMBOL,solver.c_str());
        while (true)
        {
            if (chainparams.MiningRequiresPeers()) //chainActive.LastTip()->GetHeight() != 235300 &&
            {
                //if ( ASSETCHAINS_SEED != 0 && chainActive.LastTip()->GetHeight() < 100 )
                //    break;
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                miningTimer.stop();
                do {
                    bool fvNodesEmpty;
                    {
                        //LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty && !IsInitialBlockDownload(chainparams))
                        break;
                    MilliSleep(15000);
                    //fprintf(stderr,"fvNodesEmpty %d IsInitialBlockDownload(%s) %d\n",(int32_t)fvNodesEmpty,ASSETCHAINS_SYMBOL,(int32_t)IsInitialBlockDownload());
                    
                } while (true);
                //fprintf(stderr,"%s Found peers\n",ASSETCHAINS_SYMBOL);
                miningTimer.start();
            }
            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.LastTip();
            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }
            if ( ASSETCHAINS_SYMBOL[0] != 0 && ASSETCHAINS_STAKED == 0 )
            {
                //fprintf(stderr,"%s create new block ht.%d\n",ASSETCHAINS_SYMBOL,Mining_height);
                //sleep(3);
            }

#ifdef ENABLE_WALLET
            // notaries always default to staking
            CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, pindexPrev->GetHeight()+1, gpucount, ASSETCHAINS_STAKED != 0 && GetArg("-genproclimit", 0) == 0);
#else
            CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif
            if ( ptr == 0 )
            {
                static uint32_t counter;
                if ( counter++ < 100 && ASSETCHAINS_STAKED == 0 )
                    fprintf(stderr,"created illegal block, retry\n");
                sleep(1);
                continue;
            }
            //fprintf(stderr,"get template\n");
            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in KomodoMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in KomodoMiner: Invalid -mineraddress\n");
                }
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            if ( ASSETCHAINS_SYMBOL[0] != 0 )
            {
                if ( ASSETCHAINS_REWARD[0] == 0 && !ASSETCHAINS_LASTERA )
                {
                    if ( pblock->vtx.size() == 1 && pblock->vtx[0].vout.size() == 1 && Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        static uint32_t counter;
                        if ( counter++ < 10 )
                            fprintf(stderr,"skip generating %s on-demand block, no tx avail\n",ASSETCHAINS_SYMBOL);
                        sleep(10);
                        continue;
                    } else fprintf(stderr,"%s vouts.%d mining.%d vs %d\n",ASSETCHAINS_SYMBOL,(int32_t)pblock->vtx[0].vout.size(),Mining_height,ASSETCHAINS_MINHEIGHT);
                }
            }
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
            //fprintf(stderr,"Running KomodoMiner.%s with %u transactions in block\n",solver.c_str(),(int32_t)pblock->vtx.size());
            LogPrintf("Running KomodoMiner.%s with %u transactions in block (%u bytes)\n",solver.c_str(),pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));
            //
            // Search
            //
            uint8_t pubkeys[66][33]; arith_uint256 bnMaxPoSdiff; uint32_t blocktimes[66]; int mids[256],nonzpkeys,i,j,externalflag; uint32_t savebits; int64_t nStart = GetTime();
            pblock->nBits         = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
            savebits = pblock->nBits;
            HASHTarget = arith_uint256().SetCompact(savebits);
            roundrobin_delay = ROUNDROBIN_DELAY;
            if ( ASSETCHAINS_SYMBOL[0] == 0 && notaryid >= 0 )
            {
                j = 65;
                if ( (Mining_height >= 235300 && Mining_height < 236000) || (Mining_height % KOMODO_ELECTION_GAP) > 64 || (Mining_height % KOMODO_ELECTION_GAP) == 0 || Mining_height > 1000000 )
                {
                    int32_t dispflag = 0;
                    if ( notaryid <= 3 || notaryid == 32 || (notaryid >= 43 && notaryid <= 45) &&notaryid == 51 || notaryid == 52 || notaryid == 56 || notaryid == 57 )
                        dispflag = 1;
                    komodo_eligiblenotary(pubkeys,mids,blocktimes,&nonzpkeys,pindexPrev->GetHeight());
                    if ( nonzpkeys > 0 )
                    {
                        for (i=0; i<33; i++)
                            if( pubkeys[0][i] != 0 )
                                break;
                        if ( i == 33 )
                            externalflag = 1;
                        else externalflag = 0;
                        if ( IS_KOMODO_NOTARY != 0 )
                        {
                            for (i=1; i<66; i++)
                                if ( memcmp(pubkeys[i],pubkeys[0],33) == 0 )
                                    break;
                            if ( externalflag == 0 && i != 66 && mids[i] >= 0 )
                                printf("VIOLATION at %d, notaryid.%d\n",i,mids[i]);
                            for (j=gpucount=0; j<65; j++)
                            {
                                if ( dispflag != 0 )
                                {
                                    if ( mids[j] >= 0 )
                                        fprintf(stderr,"%d ",mids[j]);
                                    else fprintf(stderr,"GPU ");
                                }
                                if ( mids[j] == -1 )
                                    gpucount++;
                            }
                            if ( dispflag != 0 )
                                fprintf(stderr," <- prev minerids from ht.%d notary.%d gpucount.%d %.2f%% t.%u\n",pindexPrev->GetHeight(),notaryid,gpucount,100.*(double)gpucount/j,(uint32_t)time(NULL));
                        }
                        for (j=0; j<65; j++)
                            if ( mids[j] == notaryid )
                                break;
                        if ( j == 65 )
                            KOMODO_LASTMINED = 0;
                    } else fprintf(stderr,"no nonz pubkeys\n");
                    if ( (Mining_height >= 235300 && Mining_height < 236000) || (j == 65 && Mining_height > KOMODO_MAYBEMINED+1 && Mining_height > KOMODO_LASTMINED+64) )
                    {
                        HASHTarget = arith_uint256().SetCompact(KOMODO_MINDIFF_NBITS);
                        fprintf(stderr,"I am the chosen one for %s ht.%d\n",ASSETCHAINS_SYMBOL,pindexPrev->GetHeight()+1);
                    } //else fprintf(stderr,"duplicate at j.%d\n",j);
                } else Mining_start = 0;
            } else Mining_start = 0;
            if ( ASSETCHAINS_STAKED != 0 )
            {
                int32_t percPoS,z; bool fNegative,fOverflow;
                HASHTarget_POW = komodo_PoWtarget(&percPoS,HASHTarget,Mining_height,ASSETCHAINS_STAKED);
                HASHTarget.SetCompact(KOMODO_MINDIFF_NBITS,&fNegative,&fOverflow);
                if ( ASSETCHAINS_STAKED < 100 )
                {
                    for (z=31; z>=0; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&HASHTarget_POW)[z]);
                    fprintf(stderr," PoW for staked coin PoS %d%% vs target %d%%\n",percPoS,(int32_t)ASSETCHAINS_STAKED);
                }
            }
            while (true)
            {
                if ( KOMODO_INSYNC == 0 )
                {
                    fprintf(stderr,"Mining when blockchain might not be in sync longest.%d vs %d\n",KOMODO_LONGESTCHAIN,Mining_height);
                    if ( KOMODO_LONGESTCHAIN != 0 && Mining_height >= KOMODO_LONGESTCHAIN )
                        KOMODO_INSYNC = 1;
                    sleep(3);
                }
                // Hash state
                KOMODO_CHOSEN_ONE = 0;
                
                crypto_generichash_blake2b_state state;
                EhInitialiseState(n, k, state);
                // I = the block header minus nonce and solution.
                CEquihashInput I{*pblock};
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << I;
                // H(I||...
                crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());
                // H(I||V||...
                crypto_generichash_blake2b_state curr_state;
                curr_state = state;
                crypto_generichash_blake2b_update(&curr_state,pblock->nNonce.begin(),pblock->nNonce.size());
                // (x_1, x_2, ...) = A(I, V, n, k)
                LogPrint("pow", "Running Equihash solver \"%s\" with nNonce = %s\n",solver, pblock->nNonce.ToString());
                arith_uint256 hashTarget;
                if ( KOMODO_MININGTHREADS > 0 && ASSETCHAINS_STAKED > 0 && ASSETCHAINS_STAKED < 100 && Mining_height > 10 )
                    hashTarget = HASHTarget_POW;
                else hashTarget = HASHTarget;
                std::function<bool(std::vector<unsigned char>)> validBlock =
#ifdef ENABLE_WALLET
                [&pblock, &hashTarget, &pwallet, &reservekey, &m_cs, &cancelSolver, &chainparams]
#else
                [&pblock, &hashTarget, &m_cs, &cancelSolver, &chainparams]
#endif
                (std::vector<unsigned char> soln) {
                    int32_t z; arith_uint256 h; CBlock B;
                    // Write the solution to the hash and compute the result.
                    LogPrint("pow", "- Checking solution against target\n");
                    pblock->nSolution = soln;
                    solutionTargetChecks.increment();
                    B = *pblock;
                    h = UintToArith256(B.GetHash());
                    /*for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                    fprintf(stderr," mined ");
                    for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&HASHTarget)[z]);
                    fprintf(stderr," hashTarget ");
                    for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&HASHTarget_POW)[z]);
                    fprintf(stderr," POW\n");*/
                    if ( h > hashTarget )
                    {
                        //if ( ASSETCHAINS_STAKED != 0 && KOMODO_MININGTHREADS == 0 )
                        //    sleep(1);
                        return false;
                    }
                    if ( IS_KOMODO_NOTARY != 0 && B.nTime > GetAdjustedTime() )
                    {
                        //fprintf(stderr,"need to wait %d seconds to submit block\n",(int32_t)(B.nTime - GetAdjustedTime()));
                        while ( GetAdjustedTime() < B.nTime-2 )
                        {
                            sleep(1);
                            if ( chainActive.LastTip()->GetHeight() >= Mining_height )
                            {
                                fprintf(stderr,"new block arrived\n");
                                return(false);
                            }
                        }
                    }
                    if ( ASSETCHAINS_STAKED == 0 )
                    {
                        if ( IS_KOMODO_NOTARY != 0 )
                        {
                            int32_t r;
                            if ( (r= ((Mining_height + NOTARY_PUBKEY33[16]) % 64) / 8) > 0 )
                                MilliSleep((rand() % (r * 1000)) + 1000);
                        }
                    }
                    else
                    {
                        while ( B.nTime-57 > GetAdjustedTime() )
                        {
                            sleep(1);
                            if ( chainActive.LastTip()->GetHeight() >= Mining_height )
                                return(false);
                        }
                        uint256 tmp = B.GetHash();
                        int32_t z; for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&tmp)[z]);
                        fprintf(stderr," mined %s block %d!\n",ASSETCHAINS_SYMBOL,Mining_height);
                    }
                    CValidationState state;
                    if ( !TestBlockValidity(state, Params(), B, chainActive.LastTip(), true, false))
                    {
                        h = UintToArith256(B.GetHash());
                        for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                        fprintf(stderr," Invalid block mined, try again\n");
                        return(false);
                    }
                    KOMODO_CHOSEN_ONE = 1;
                    // Found a solution
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    LogPrintf("KomodoMiner:\n");
                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", B.GetHash().GetHex(), HASHTarget.GetHex());
#ifdef ENABLE_WALLET
                    if (ProcessBlockFound(&B, *pwallet, reservekey)) {
#else
                        if (ProcessBlockFound(&B)) {
#endif
                            // Ignore chain updates caused by us
                            std::lock_guard<std::mutex> lock{m_cs};
                            cancelSolver = false;
                        }
                        KOMODO_CHOSEN_ONE = 0;
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand()) {
                            // Increment here because throwing skips the call below
                            ehSolverRuns.increment();
                            throw boost::thread_interrupted();
                        }
                        return true;
                    };
                    std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                        std::lock_guard<std::mutex> lock{m_cs};
                        return cancelSolver;
                    };
                    
                    // TODO: factor this out into a function with the same API for each solver.
                    if (solver == "tromp" ) { //&& notaryid >= 0 ) {
                        // Create solver and initialize it.
                        equi eq(1);
                        eq.setstate(&curr_state);
                        
                        // Initialization done, start algo driver.
                        eq.digit0(0);
                        eq.xfull = eq.bfull = eq.hfull = 0;
                        eq.showbsizes(0);
                        for (u32 r = 1; r < WK; r++) {
                            (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                            eq.xfull = eq.bfull = eq.hfull = 0;
                            eq.showbsizes(r);
                        }
                        eq.digitK(0);
                        ehSolverRuns.increment();
                        
                        // Convert solution indices to byte array (decompress) and pass it to validBlock method.
                        for (size_t s = 0; s < eq.nsols; s++) {
                            LogPrint("pow", "Checking solution %d\n", s+1);
                            std::vector<eh_index> index_vector(PROOFSIZE);
                            for (size_t i = 0; i < PROOFSIZE; i++) {
                                index_vector[i] = eq.sols[s][i];
                            }
                            std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);
                            
                            if (validBlock(sol_char)) {
                                // If we find a POW solution, do not try other solutions
                                // because they become invalid as we created a new block in blockchain.
                                break;
                            }
                        }
                    } else {
                        try {
                            // If we find a valid block, we rebuild
                            bool found = EhOptimisedSolve(n, k, curr_state, validBlock, cancelled);
                            ehSolverRuns.increment();
                            if (found) {
                                int32_t i; uint256 hash = pblock->GetHash();
                                for (i=0; i<32; i++)
                                    fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
                                fprintf(stderr," <- %s Block found %d\n",ASSETCHAINS_SYMBOL,Mining_height);
                                FOUND_BLOCK = 1;
                                KOMODO_MAYBEMINED = Mining_height;
                                break;
                            }
                        } catch (EhSolverCancelledException&) {
                            LogPrint("pow", "Equihash solver cancelled\n");
                            std::lock_guard<std::mutex> lock{m_cs};
                            cancelSolver = false;
                        }
                    }
                    
                    // Check for stop or if block needs to be rebuilt
                    boost::this_thread::interruption_point();
                    // Regtest mode doesn't require peers
                    if ( FOUND_BLOCK != 0 )
                    {
                        FOUND_BLOCK = 0;
                        fprintf(stderr,"FOUND_BLOCK!\n");
                        //sleep(2000);
                    }
                    if (vNodes.empty() && chainparams.MiningRequiresPeers())
                    {
                        if ( ASSETCHAINS_SYMBOL[0] == 0 || Mining_height > ASSETCHAINS_MINHEIGHT )
                        {
                            fprintf(stderr,"no nodes, break\n");
                            break;
                        }
                    }
                    if ((UintToArith256(pblock->nNonce) & 0xffff) == 0xffff)
                    {
                        //if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                        fprintf(stderr,"0xffff, break\n");
                        break;
                    }
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    {
                        if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                            fprintf(stderr,"timeout, break\n");
                        break;
                    }
                    if ( pindexPrev != chainActive.LastTip() )
                    {
                        if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                            fprintf(stderr,"Tip advanced, break\n");
                        break;
                    }
                    // Update nNonce and nTime
                    pblock->nNonce = ArithToUint256(UintToArith256(pblock->nNonce) + 1);
                    pblock->nBits = savebits;
                    /*if ( NOTARY_PUBKEY33[0] == 0 )
                    {
                        int32_t percPoS;
                        UpdateTime(pblock, consensusParams, pindexPrev);
                        if (consensusParams.fPowAllowMinDifficultyBlocks)
                        {
                            // Changing pblock->nTime can change work required on testnet:
                            HASHTarget.SetCompact(pblock->nBits);
                            HASHTarget_POW = komodo_PoWtarget(&percPoS,HASHTarget,Mining_height,ASSETCHAINS_STAKED);
                        }
                    }*/
                }
            }
        }
        catch (const boost::thread_interrupted&)
        {
            miningTimer.stop();
            c.disconnect();
            LogPrintf("KomodoMiner terminated\n");
            throw;
        }
        catch (const std::runtime_error &e)
        {
            miningTimer.stop();
            c.disconnect();
            LogPrintf("KomodoMiner runtime error: %s\n", e.what());
            return;
        }
        miningTimer.stop();
        c.disconnect();
    }

#ifdef ENABLE_WALLET
    void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
#else
    void GenerateBitcoins(bool fGenerate, int nThreads)
#endif
    {
        static CCriticalSection cs_startmining;

        LOCK(cs_startmining);
        if (!AreParamsInitialized())
        {
            return;
        }

        VERUS_MINTBLOCKS = (VERUS_MINTBLOCKS && ASSETCHAINS_LWMAPOS != 0);

        if (fGenerate == true || VERUS_MINTBLOCKS)
        {
            mapArgs["-gen"] = "1";

            if (VERUS_DEFAULT_ZADDR.size() > 0)
            {
                if (defaultSaplingDest == boost::none)
                {
                    LogPrintf("ERROR: -defaultzaddr parameter is invalid Sapling payment address\n");
                    fprintf(stderr, "-defaultzaddr parameter is invalid Sapling payment address\n");
                }
                else
                {
                    LogPrintf("StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                    fprintf(stderr, "StakeGuard searching for double stakes on %s\n", VERUS_DEFAULT_ZADDR.c_str());
                }
            }
        }

        static boost::thread_group* minerThreads = NULL;

        if (nThreads < 0)
            nThreads = GetNumCores();

        if (minerThreads != NULL)
        {
            minerThreads->interrupt_all();
            minerThreads->join_all();
            delete minerThreads;
            minerThreads = NULL;
        }

        //fprintf(stderr,"nThreads.%d fGenerate.%d\n",(int32_t)nThreads,fGenerate);
        if ( nThreads == 0 && ASSETCHAINS_STAKED )
            nThreads = 1;

        if (!fGenerate)
            return;

        minerThreads = new boost::thread_group();

        // add the PBaaS thread when mining or staking
        minerThreads->create_thread(boost::bind(&CConnectedChains::SubmissionThreadStub));

#ifdef ENABLE_WALLET
        if (VERUS_MINTBLOCKS && pwallet != NULL)
        {
            minerThreads->create_thread(boost::bind(&VerusStaker, pwallet));
        }
#endif

        for (int i = 0; i < nThreads; i++) {

#ifdef ENABLE_WALLET
            if (ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH)
                minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
            else
                minerThreads->create_thread(boost::bind(&BitcoinMiner_noeq, pwallet));
#else
            if (ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH)
                minerThreads->create_thread(&BitcoinMiner);
            else
                minerThreads->create_thread(&BitcoinMiner_noeq);
#endif
        }
    }
    
#endif // ENABLE_MINING
