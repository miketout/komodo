/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS identity definition,
 * 
 * This is a decentralized identity class that provides the minimum
 * basic function needed to enable persistent DID-similar identities, 
 * needed for signatories, that will eventually bridge compatibly to
 * DID identities.
 * 
 * 
 */
#include "main.h"
#include "pbaas/pbaas.h"
#include "identity.h"

extern CTxMemPool mempool;

CCommitmentHash::CCommitmentHash(const CTransaction &tx)
{
    for (auto txOut : tx.vout)
    {
        COptCCParams p;
        if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_COMMITMENT && p.vData.size())
        {
            ::FromVector(p.vData[0], *this);
            break;
        }
    }
}

UniValue CNameReservation::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("name", name));
    ret.push_back(Pair("salt", salt.GetHex()));
    ret.push_back(Pair("referral", referral.IsNull() ? "" : EncodeDestination(referral)));

    if (IsVerusActive())
    {
        ret.push_back(Pair("parent", ""));
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "@"))));
    }
    else
    {
        ret.push_back(Pair("parent", ConnectedChains.ThisChain().name));
        ret.push_back(Pair("nameid", EncodeDestination(DecodeDestination(name + "." + ConnectedChains.ThisChain().name + "@"))));
    }

    return ret;
}

CPrincipal::CPrincipal(const UniValue &uni)
{
    nVersion = uni_get_int(find_value(uni, "version"));
    if (nVersion == VERSION_INVALID)
    {
        nVersion = VERSION_VERUSID;
    }
    flags = uni_get_int(find_value(uni, "flags"));
    UniValue primaryAddressesUni = find_value(uni, "primaryaddresses");
    if (primaryAddressesUni.isArray())
    {
        for (int i = 0; i < primaryAddressesUni.size(); i++)
        {
            try
            {
                CTxDestination dest = DecodeDestination(uni_get_str(primaryAddressesUni[i]));
                if (dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PKH)
                {
                    primaryAddresses.push_back(dest);
                }
            }
            catch (const std::exception &e)
            {
                printf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                LogPrintf("%s: bad address %s\n", __func__, primaryAddressesUni[i].write().c_str());
                nVersion = VERSION_INVALID;
            }
        }
    }

    minSigs = uni_get_int(find_value(uni, "minimumsignatures"));
}

CIdentity::CIdentity(const UniValue &uni) : CPrincipal(uni)
{
    parent = uint160(GetDestinationID(DecodeDestination(uni_get_str(find_value(uni, "parent")))));
    name = CleanName(uni_get_str(find_value(uni, "name")), parent);

    UniValue hashesUni = find_value(uni, "contentmap");
    if (hashesUni.isObject())
    {
        std::vector<std::string> keys = hashesUni.getKeys();
        std::vector<UniValue> values = hashesUni.getValues();
        for (int i = 0; i < keys.size(); i++)
        {
            try
            {
                std::vector<unsigned char> vch(ParseHex(keys[i]));
                uint160 key;
                if (vch.size() == 20 && !((key = uint160(vch)).IsNull() || i >= values.size()))
                {
                    contentMap[key] = uint256S(uni_get_str(values[i]));
                }
                else
                {
                    nVersion = VERSION_INVALID;
                }
            }
            catch (const std::exception &e)
            {
                nVersion = VERSION_INVALID;
            }
            if (nVersion == VERSION_INVALID)
            {
                printf("%s: contentmap entry is not valid keys: %s, values: %s\n", __func__, keys[i].c_str(), values[i].write().c_str());
                LogPrintf("%s: contentmap entry is not valid keys: %s, values: %s\n", __func__, keys[i].c_str(), values[i].write().c_str());
                break;
            }
        }
    }
    std::string revocationStr = uni_get_str(find_value(uni, "revocationauthority"));
    std::string recoveryStr = uni_get_str(find_value(uni, "recoveryauthority"));

    revocationAuthority = uint160(GetDestinationID(DecodeDestination(revocationStr == "" ? name + "@" : revocationStr)));
    recoveryAuthority = uint160(GetDestinationID(DecodeDestination(recoveryStr == "" ? name + "@" : recoveryStr)));
    libzcash::PaymentAddress pa = DecodePaymentAddress(uni_get_str(find_value(uni, "privateaddress")));

    if (revocationAuthority.IsNull() || recoveryAuthority.IsNull())
    {
        printf("%s: invalid address\n", __func__);
        LogPrintf("%s: invalid address\n", __func__);
        nVersion = VERSION_INVALID;
    }
    else if (boost::get<libzcash::SaplingPaymentAddress>(&pa) != nullptr)
    {
        privateAddresses.push_back(*boost::get<libzcash::SaplingPaymentAddress>(&pa));
    }
}

CIdentity::CIdentity(const CTransaction &tx, int *voutNum)
{
    std::set<uint160> ids;
    int idIndex;
    bool found = false;

    nVersion = PBAAS_VERSION_INVALID;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        CIdentity foundIdentity(tx.vout[i].scriptPubKey);
        if (foundIdentity.IsValid() && !found)
        {
            *this = foundIdentity;
            found = true;
            idIndex = i;
        }
        else if (foundIdentity.IsValid())
        {
            *this = CIdentity();
        }
    }
    if (voutNum && IsValid())
    {
        *voutNum = idIndex;
    }
}

CIdentity CIdentity::LookupIdentity(const CIdentityID &nameID, uint32_t height, uint32_t *pHeightOut, CTxIn *pIdTxIn)
{
    LOCK(mempool.cs);

    CIdentity ret;

    uint32_t heightOut = 0;

    if (!pHeightOut)
    {
        pHeightOut = &heightOut;
    }
    else
    {
        *pHeightOut = 0;
    }

    CTxIn _idTxIn;
    if (!pIdTxIn)
    {
        pIdTxIn = &_idTxIn;
    }
    CTxIn &idTxIn = *pIdTxIn;

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    CKeyID keyID(CCrossChainRPCData::GetConditionID(nameID, EVAL_IDENTITY_PRIMARY));

    if (GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    // check the mempool for spent/modified
                    CSpentIndexKey key(it->first.txhash, it->first.index);
                    CSpentIndexValue value;

                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_PRIMARY && 
                        (ret = CIdentity(coins.vout[it->first.index].scriptPubKey)).IsValid())
                    {
                        if (ret.GetID() == nameID)
                        {
                            idTxIn = CTxIn(it->first.txhash, it->first.index);
                            *pHeightOut = it->second.blockHeight;
                        }
                        else
                        {
                            // got an identity masquerading as another, clear it
                            ret = CIdentity();
                        }
                    }
                }
            }
        }

        if (height != 0 && *pHeightOut > height)
        {
            *pHeightOut = 0;

            // if we must check up to a specific height that is less than the latest height, do so
            std::vector<CAddressIndexDbEntry> addressIndex;

            if (GetAddressIndex(keyID, 1, addressIndex, 0, height) && addressIndex.size())
            {
                int txIndex = 0;
                // look from last backward to find the first valid ID
                for (int i = addressIndex.size() - 1; i >= 0; i--)
                {
                    if (addressIndex[i].first.blockHeight < *pHeightOut)
                    {
                        break;
                    }
                    CTransaction idTx;
                    uint256 blkHash;
                    COptCCParams p;
                    LOCK(mempool.cs);
                    if (!addressIndex[i].first.spending &&
                        addressIndex[i].first.txindex > txIndex &&    // always select the latest in a block, if there can be more than one
                        myGetTransaction(addressIndex[i].first.txhash, idTx, blkHash) &&
                        idTx.vout[addressIndex[i].first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_PRIMARY && 
                        (ret = CIdentity(idTx.vout[addressIndex[i].first.index].scriptPubKey)).IsValid())
                    {
                        idTxIn = CTxIn(addressIndex[i].first.txhash, addressIndex[i].first.index);
                        *pHeightOut = addressIndex[i].first.blockHeight;
                        txIndex = addressIndex[i].first.txindex;
                    }
                }
            }
            else
            {
                // not found at that height
                ret = CIdentity();
                idTxIn = CTxIn();
            }
        }
    }
    return ret;
}

CIdentity CIdentity::LookupIdentity(const std::string &name, uint32_t height, uint32_t *pHeightOut, CTxIn *idTxIn)
{
    return LookupIdentity(GetID(name), height, pHeightOut, idTxIn);
}

CIdentity CIdentity::LookupFirstIdentity(const CIdentityID &idID, uint32_t *pHeightOut, CTxIn *pIdTxIn, CTransaction *pidTx)
{
    CIdentity ret;

    uint32_t heightOut = 0;

    if (!pHeightOut)
    {
        pHeightOut = &heightOut;
    }
    else
    {
        *pHeightOut = 0;
    }

    CTxIn _idTxIn;
    if (!pIdTxIn)
    {
        pIdTxIn = &_idTxIn;
    }
    CTxIn &idTxIn = *pIdTxIn;

    std::vector<CAddressUnspentDbEntry> unspentOutputs;

    CKeyID keyID(CCrossChainRPCData::GetConditionID(idID, EVAL_IDENTITY_RESERVATION));

    if (GetAddressUnspent(keyID, CScript::P2PKH, unspentOutputs))
    {
        CCoinsViewCache view(pcoinsTip);

        for (auto it = unspentOutputs.begin(); !ret.IsValid() && it != unspentOutputs.end(); it++)
        {
            CCoins coins;

            if (view.GetCoins(it->first.txhash, coins))
            {
                if (coins.IsAvailable(it->first.index))
                {
                    COptCCParams p;
                    if (coins.vout[it->first.index].scriptPubKey.IsPayToCryptoCondition(p) &&
                        p.IsValid() && 
                        p.evalCode == EVAL_IDENTITY_RESERVATION)
                    {
                        CTransaction idTx;
                        uint256 blkHash;
                        if (myGetTransaction(it->first.txhash, idTx, blkHash) && (ret = CIdentity(idTx)).IsValid() && ret.GetID() == idID)
                        {
                            int i;
                            for (i = 0; i < idTx.vout.size(); i++)
                            {
                                COptCCParams p;
                                if (idTx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3 && p.evalCode == EVAL_IDENTITY_PRIMARY)
                                {
                                    break;
                                }
                            }

                            if (i < idTx.vout.size())
                            {
                                if (pidTx)
                                {
                                    *pidTx = idTx;
                                }
                                idTxIn = CTxIn(it->first.txhash, i);
                                *pHeightOut = it->second.blockHeight;
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}

// this enables earliest rejection of invalid CC transactions
bool ValidateSpendingIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height, CCurrencyDefinition issuingChain)
{
    // CHECK #1 - there is only one reservation output, and there is also one identity output that matches the reservation.
    //            the identity output must come first and have from 0 to 3 referral outputs between it and the reservation.
    int numReferrers = 0;
    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
    std::vector<CTxDestination> referrers;
    bool valid = true;

    for (auto &txout : tx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                if (identityCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newIdentity = CIdentity(p.vData[0]);
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newName = CNameReservation(p.vData[0]);
            }
            else if (identityCount && !reservationCount)
            {
                if (!issuingChain.IDReferralLevels() || 
                    p.vKeys.size() < 1 || 
                    referrers.size() > (issuingChain.IDReferralLevels() - 1) || 
                    p.evalCode != 0 || 
                    p.n > 1 || 
                    p.m != 1 || 
                    txout.nValue < issuingChain.IDReferralAmount())
                {
                    valid = false;
                    break;
                }
                referrers.push_back(p.vKeys[0]);
            }
            else if (identityCount != reservationCount)
            {
                valid = false;
                break;
            }
        }
    }

    // we can close a commitment UTXO without an identity
    if (valid && !identityCount)
    {
        return state.Error("Transaction may not have an identity reservation without a matching identity");
    }
    else if (!valid)
    {
        return state.Error("Improperly formed identity definition transaction");
    }

    std::vector<CTxDestination> dests;
    int minSigs;
    txnouttype outType;
    if (ExtractDestinations(tx.vout[outNum].scriptPubKey, outType, dests, minSigs))
    {
        uint160 thisID = newIdentity.GetID();
        for (auto &dest : dests)
        {
            uint160 oneDestID;
            if (dest.which() == COptCCParams::ADDRTYPE_ID && (oneDestID = GetDestinationID(dest)) != thisID && !CIdentity::LookupIdentity(CIdentityID(oneDestID)).IsValid())
            {
                return state.Error("Destination includes invalid identity");
            }
        }
    }

    // CHECK #2 - must be rooted in this chain
    if (newIdentity.parent != ConnectedChains.ThisChain().GetID())
    {
        return state.Error("Identity parent of new identity must be current chain");
    }

    // CHECK #3 - if dupID is valid, we need to be spending it to recover. redefinition is invalid
    CTxIn idTxIn;
    uint32_t priorHeightOut;
    CIdentity dupID = newIdentity.LookupIdentity(newIdentity.GetID(), height - 1, &priorHeightOut, &idTxIn);

    // CHECK #3a - if dupID is invalid, ensure we spend a matching name commitment
    if (dupID.IsValid())
    {
        return state.Error("Identity already exists");
    }

    int commitmentHeight = 0;
    const CCoins *coins;
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    LOCK(mempool.cs);

    CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
    view.SetBackend(viewMemPool);

    CCommitmentHash ch;
    int idx = -1;

    CAmount nValueIn = 0;
    {
        // from here, we must spend a matching name commitment
        std::map<uint256, const CCoins *> txMap;
        for (auto &oneTxIn : tx.vin)
        {
            coins = txMap[oneTxIn.prevout.hash];
            if (!coins && !(coins = view.AccessCoins(oneTxIn.prevout.hash)))
            {
                //LogPrintf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                //printf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                return state.Error("Cannot access input");
            }
            txMap[oneTxIn.prevout.hash] = coins;

            if (oneTxIn.prevout.n >= coins->vout.size())
            {
                //extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
                //UniValue uniTx;
                //TxToJSON(tx, uint256(), uniTx);
                //printf("%s\n", uniTx.write(1, 2).c_str());
                return state.Error("Input index out of range");
            }

            COptCCParams p;
            if (idx == -1 && 
                coins->vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && 
                p.IsValid() && 
                p.evalCode == EVAL_IDENTITY_COMMITMENT && 
                p.vData.size())
            {
                idx = oneTxIn.prevout.n;
                ::FromVector(p.vData[0], ch);
                commitmentHeight = coins->nHeight;
                // this needs to already be in a prior block, or we can't consider it valid
                if (!commitmentHeight || commitmentHeight == -1)
                {
                    return state.Error("ID commitment was not already in blockchain");
                }
            }
        }
    }

    if (idx == -1 || ch.hash.IsNull())
    {
        std::string specificMsg = "Invalid identity commitment in tx: " + tx.GetHash().GetHex();
        return state.Error(specificMsg);
    }

    // are we spending a matching name commitment?
    if (ch.hash != newName.GetCommitment().hash)
    {
        return state.Error("Mismatched identity commitment");
    }

    if (!newName.referral.IsNull() && issuingChain.IDReferralLevels() && !(CIdentity::LookupIdentity(newName.referral, commitmentHeight).IsValid()))
    {
        // invalid referral identity
        return state.Error("Invalid referral identity specified");
    }

    CReserveTransactionDescriptor rtxd(tx, view, height);

    // CHECK #4 - if blockchain referrals are not enabled or if there is no referring identity, make sure the fees of this transaction are full price for an identity, 
    // all further checks only if referrals are enabled and there is a referrer
    if (!issuingChain.IDReferralLevels() || newName.referral.IsNull())
    {
        // make sure the fees of this transaction are full price for an identity, all further checks only if there is a referrer
        if (rtxd.NativeFees() < issuingChain.IDFullRegistrationAmount())
        {
            return state.Error("Invalid identity registration - insufficient fee");
        }
        return true;
    }

    // CHECK #5 - ensure that the first referring output goes to the referring identity followed by up 
    //            to two identities that come from the original definition transaction of the referring identity. account for all outputs between
    //            identity out and reservation out and ensure that they are correct and pay 20% of the price of an identity
    uint32_t heightOut = 0;
    CTransaction referralTx;

    CIdentity firstReferralIdentity = CIdentity::LookupFirstIdentity(newName.referral, &heightOut, &idTxIn, &referralTx);

    // referrer must be mined in when this transaction is put into the mem pool
    if (heightOut >= height || !firstReferralIdentity.IsValid())
    {
        return state.Error("Invalid identity registration referral");
    }

    bool isReferral = false;
    std::vector<CTxDestination> checkReferrers = std::vector<CTxDestination>({newName.referral});
    for (auto &txout : referralTx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                isReferral = true;
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                break;
            }
            else if (isReferral)
            {
                if (p.vKeys.size() == 0 || p.vKeys[0].which() != COptCCParams::ADDRTYPE_ID)
                {
                    // invalid referral
                    return state.Error("Invalid identity registration referral outputs");
                }
                else
                {
                    checkReferrers.push_back(p.vKeys[0]);
                    if (checkReferrers.size() == issuingChain.IDReferralLevels())
                    {
                        break;
                    }
                }
            }
        }
    }
    if (referrers.size() != checkReferrers.size())
    {
        return state.Error("Invalid identity registration - incorrect referral payments");
    }

    // make sure all paid referrers are correct
    for (int i = 0; i < referrers.size(); i++)
    {
        if (referrers[i] != checkReferrers[i])
        {
            return state.Error("Invalid identity registration - incorrect referral payments");
        }
    }

    // CHECK #6 - ensure that the transaction pays the correct mining and refferal fees
    if (rtxd.NativeFees() < (issuingChain.IDReferredRegistrationAmount() - (referrers.size() * issuingChain.IDReferralAmount())))
    {
        return state.Error("Invalid identity registration - insufficient fee");
    }

    return true;
}

bool PrecheckIdentityReservation(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();

    int numReferrers = 0;
    int identityCount = 0;
    int reservationCount = 0;
    CIdentity newIdentity;
    CNameReservation newName;
    std::vector<CTxDestination> referrers;
    bool valid = true;

    AssertLockHeld(cs_main);

    for (auto &txout : tx.vout)
    {
        COptCCParams p;
        if (txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
        {
            if (p.evalCode == EVAL_IDENTITY_PRIMARY)
            {
                if (identityCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newIdentity = CIdentity(p.vData[0]);
            }
            else if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                if (reservationCount++ || p.vData.size() < 2)
                {
                    valid = false;
                    break;
                }
                newName = CNameReservation(p.vData[0]);
            }
            else if (identityCount && !reservationCount)
            {
                if (!thisChain.IDReferralLevels() || 
                    p.vKeys.size() < 1 || 
                    referrers.size() > (thisChain.IDReferralLevels() - 1) || 
                    p.evalCode != 0 || 
                    p.n > 1 || 
                    p.m != 1 || 
                    txout.nValue < thisChain.IDReferralAmount())
                {
                    valid = false;
                    break;
                }
                referrers.push_back(p.vKeys[0]);
            }
            else if (identityCount != reservationCount)
            {
                valid = false;
                break;
            }
        }
    }

    // we can close a commitment UTXO without an identity
    if (valid && !identityCount)
    {
        return state.Error("Transaction may not have an identity reservation without a matching identity");
    }
    else if (!valid)
    {
        return state.Error("Improperly formed identity definition transaction");
    }

    int commitmentHeight = 0;

    LOCK2(cs_main, mempool.cs);

    CCommitmentHash ch;
    int idx = -1;

    CAmount nValueIn = 0;
    {
        LOCK2(cs_main, mempool.cs);

        // from here, we must spend a matching name commitment
        std::map<uint256, CTransaction> txMap;
        uint256 hashBlk;
        for (auto &oneTxIn : tx.vin)
        {
            CTransaction sourceTx = txMap[oneTxIn.prevout.hash];
            if (sourceTx.nVersion <= sourceTx.SPROUT_MIN_CURRENT_VERSION && !myGetTransaction(oneTxIn.prevout.hash, sourceTx, hashBlk))
            {
                //LogPrintf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                //printf("Cannot access input from output %u of transaction %s in transaction %s\n", oneTxIn.prevout.n, oneTxIn.prevout.hash.GetHex().c_str(), tx.GetHash().GetHex().c_str());
                return state.Error("Cannot access input");
            }
            txMap[oneTxIn.prevout.hash] = sourceTx;

            if (oneTxIn.prevout.n >= sourceTx.vout.size())
            {
                //extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
                //UniValue uniTx;
                //TxToJSON(tx, uint256(), uniTx);
                //printf("%s\n", uniTx.write(1, 2).c_str());
                return state.Error("Input index out of range");
            }

            COptCCParams p;
            if (idx == -1 && 
                sourceTx.vout[oneTxIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && 
                p.IsValid() && 
                p.evalCode == EVAL_IDENTITY_COMMITMENT && 
                p.vData.size())
            {
                idx = oneTxIn.prevout.n;
                ::FromVector(p.vData[0], ch);
            }
        }
    }

    if (idx == -1 || ch.hash.IsNull())
    {
        std::string specificMsg = "Invalid identity commitment in tx: " + tx.GetHash().GetHex();
        return state.Error(specificMsg);
    }

    // are we spending a matching name commitment?
    if (ch.hash != newName.GetCommitment().hash)
    {
        return state.Error("Mismatched identity commitment");
    }

    return true;
}

// with the thorough check for an identity reservation, the only thing we need to check is that either 1) this transaction includes an identity reservation output or 2)
// this transaction spends a prior identity transaction that does not create a clearly invalid mutation between the two
bool PrecheckIdentityPrimary(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    AssertLockHeld(cs_main);

    bool validReservation = false;
    bool validIdentity = false;

    CNameReservation nameRes;
    CIdentity identity;
    COptCCParams p, identityP;

    for (auto &output : tx.vout)
    {
        if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= COptCCParams::VERSION_V3 && p.evalCode == EVAL_IDENTITY_RESERVATION && p.vData.size() > 1 && (nameRes = CNameReservation(p.vData[0])).IsValid())
        {
            // twice through makes it invalid
            if (validReservation)
            {
                return state.Error("Invalid multiple identity reservations on one transaction");
            }
            validReservation = true;
        }
        else if (p.IsValid() && p.version >= COptCCParams::VERSION_V3 && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() > 1 && (identity = CIdentity(p.vData[0])).IsValid())
        {
            // twice through makes it invalid
            if (validIdentity)
            {
                return state.Error("Invalid multiple identity definitions on one transaction");
            }
            identityP = p;
            validIdentity = true;
        }
    }

    if (!validIdentity)
    {
        return state.Error("Invalid identity definition");
    }

    CIdentityID idID = identity.GetID();
    p = identityP;

    // ensure that we have all required spend conditions for primary, revocation, and recovery
    // if there are additional spend conditions, their addition or removal is checked for validity
    // depending on which of the mandatory spend conditions is authorized.
    COptCCParams master;
    if (p.vData.size() < 4 || !(master = COptCCParams(p.vData.back())).IsValid() || master.evalCode != 0 || master.m != 1)
    {
        // we need to have 3 authority spend conditions mandatory at a top level for any primary ID output
        bool primary = false, revocation = false, recovery = false;

        for (auto dest : p.vKeys)
        {
            if (dest.which() == COptCCParams::ADDRTYPE_ID && (idID == GetDestinationID(dest)))
            {
                primary = true;
            }
        }
        if (!primary)
        {
            std::string errorOut = "Primary identity output condition of \"" + identity.name + "\" is not spendable by self";
            return state.Error(errorOut.c_str());
        }
        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            // must be valid and composable
            if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
            {
                std::string errorOut = "Invalid output condition from identity: \"" + identity.name + "\"";
                return state.Error(errorOut.c_str());
            }

            if (oneP.evalCode == EVAL_IDENTITY_REVOKE || oneP.evalCode == EVAL_IDENTITY_RECOVER)
            {
                for (auto dest : oneP.vKeys)
                {
                    if (dest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        if (oneP.evalCode == EVAL_IDENTITY_REVOKE && (identity.revocationAuthority == GetDestinationID(dest)))
                        {
                            revocation = true;
                        }
                        else if (oneP.evalCode == EVAL_IDENTITY_RECOVER && (identity.recoveryAuthority == GetDestinationID(dest)))
                        {
                            recovery = true;
                        }
                    }
                }
            }
        }

        // we need separate spend conditions for both revoke and recover in all cases
        if (!revocation || !recovery)
        {
            std::string errorOut = "Primary identity output \"" + identity.name + "\" must be spendable by revocation and recovery authorities";
            return state.Error(errorOut.c_str());
        }
    }

    extern uint160 VERUS_CHAINID;
    extern std::string VERUS_CHAINNAME;

    // compare commitment without regard to case or other textual transformations that are irrelevant to matching
    uint160 parentChain = ConnectedChains.ThisChain().GetID();
    if (validReservation && identity.GetID(nameRes.name, parentChain) == identity.GetID())
    {
        return true;
    }

    // if we made it to here without an early, positive exit, we must determine that we are spending a matching identity, and if so, all is fine so far
    CTransaction inTx;
    uint256 blkHash;
    LOCK(mempool.cs);
    for (auto &input : tx.vin)
    {
        if (input.prevout.hash == inTx.GetHash() || myGetTransaction(input.prevout.hash, inTx, blkHash))
        {
            if (inTx.vout[input.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() > 1 && (identity = CIdentity(p.vData[0])).IsValid())
            {
                return true;
            }
        }
    }

    return state.Error("Invalid primary identity - does not include identity reservation or spend matching identity");
}

CIdentity GetOldIdentity(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx=nullptr, uint32_t *pHeight=nullptr);
CIdentity GetOldIdentity(const CTransaction &spendingTx, uint32_t nIn, CTransaction *pSourceTx, uint32_t *pHeight)
{
    CTransaction _sourceTx;
    CTransaction &sourceTx(pSourceTx ? *pSourceTx : _sourceTx);

    // if not fulfilled, ensure that no part of the primary identity is modified
    CIdentity oldIdentity;
    uint256 blkHash;
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        if (pHeight)
        {
            auto bIt = mapBlockIndex.find(blkHash);
            if (bIt == mapBlockIndex.end() || !bIt->second)
            {
                *pHeight = chainActive.Height();
            }
            else
            {
                *pHeight = bIt->second->GetHeight();
            }
        }
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_IDENTITY_PRIMARY && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1)
        {
            oldIdentity = CIdentity(p.vData[0]);
        }
    }
    return oldIdentity;
}

bool ValidateIdentityPrimary(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);

    if (!oldIdentity.IsValid())
    {
        return eval->Error("Spending invalid identity");
    }

    int idIndex;
    CIdentity newIdentity(spendingTx, &idIndex);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to define invalid identity");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    if (oldIdentity.IsInvalidMutation(newIdentity, height))
    {
        LogPrintf("Invalid identity modification %s\n", spendingTx.GetHash().GetHex().c_str());
        return eval->Error("Invalid identity modification");
    }

    // if not fullfilled and not revoked, we are responsible for rejecting any modification of
    // data under primary authority control
    if (!fulfilled && !oldIdentity.IsRevoked())
    {
        if (oldIdentity.IsPrimaryMutation(newIdentity, height))
        {
            return eval->Error("Unauthorized identity modification");
        }
        // make sure that the primary spend conditions are not modified
        COptCCParams p, q;
        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);
        spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

        if (q.evalCode != EVAL_IDENTITY_PRIMARY ||
            p.version > q.version ||
            p.m != q.m ||
            p.n != q.n ||
            p.vKeys != q.vKeys)
        {
            return eval->Error("Unauthorized modification of identity primary spend condition");
        }
    }

    return true;
}

bool ValidateIdentityRevoke(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    int idIndex;
    CIdentity newIdentity(spendingTx, &idIndex);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    if (oldIdentity.IsInvalidMutation(newIdentity, height))
    {
        return eval->Error("Invalid identity modification");
    }

    if (oldIdentity.IsRevocation(newIdentity) && oldIdentity.recoveryAuthority == oldIdentity.GetID())
    {
        return eval->Error("Cannot revoke an identity with self as the recovery authority");
    }

    // make sure that spend conditions are valid and revocation spend conditions are not modified
    COptCCParams p, q;

    spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

    if (q.evalCode != EVAL_IDENTITY_PRIMARY)
    {
        return eval->Error("Invalid identity output in spending transaction");
    }

    COptCCParams oldRevokeP, newRevokeP;

    for (int i = 1; i < q.vData.size() - 1; i++)
    {
        COptCCParams oneP(q.vData[i]);
        // must be valid and composable
        if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
        {
            std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\"";
            return eval->Error(errorOut.c_str());
        }

        if (oneP.evalCode == EVAL_IDENTITY_REVOKE)
        {
            if (newRevokeP.IsValid())
            {
                std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\", more than one revocation condition";
                return eval->Error(errorOut.c_str());
            }
            newRevokeP = oneP;
        }
    }

    if (!newRevokeP.IsValid())
    {
        std::string errorOut = "Invalid revocation output condition for identity: \"" + newIdentity.name + "\"";
        return eval->Error(errorOut.c_str());
    }

    // if not fulfilled, neither revocation data nor its spend condition may be modified
    if (!fulfilled)
    {
        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);

        if (oldIdentity.IsRevocation(newIdentity) || oldIdentity.IsRevocationMutation(newIdentity, height))
        {
            return eval->Error("Unauthorized modification of revocation information");
        }

        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            if (oneP.evalCode == EVAL_IDENTITY_REVOKE)
            {
                oldRevokeP = oneP;
            }
        }

        if (!oldRevokeP.IsValid() || 
            !newRevokeP.IsValid() ||
            oldRevokeP.version > newRevokeP.version ||
            oldRevokeP.m != newRevokeP.m ||
            oldRevokeP.n != newRevokeP.n ||
            oldRevokeP.vKeys != newRevokeP.vKeys)
        {
            return eval->Error("Unauthorized modification of identity revocation spend condition");
        }
    }

    return true;
}

bool ValidateIdentityRecover(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    CTransaction sourceTx;
    CIdentity oldIdentity = GetOldIdentity(spendingTx, nIn, &sourceTx);
    if (!oldIdentity.IsValid())
    {
        return eval->Error("Invalid source identity");
    }

    int idIndex;
    CIdentity newIdentity(spendingTx, &idIndex);
    if (!newIdentity.IsValid())
    {
        return eval->Error("Attempting to replace identity with one that is invalid");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    if (oldIdentity.IsInvalidMutation(newIdentity, height))
    {
        return eval->Error("Invalid identity modification");
    }

    // make sure that spend conditions are valid and revocation spend conditions are not modified
    COptCCParams p, q;

    spendingTx.vout[idIndex].scriptPubKey.IsPayToCryptoCondition(q);

    if (q.evalCode != EVAL_IDENTITY_PRIMARY)
    {
        return eval->Error("Invalid identity output in spending transaction");
    }

    COptCCParams oldRecoverP, newRecoverP;

    for (int i = 1; i < q.vData.size() - 1; i++)
    {
        COptCCParams oneP(q.vData[i]);
        // must be valid and composable
        if (!oneP.IsValid() || oneP.version < oneP.VERSION_V3)
        {
            std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\"";
            return eval->Error(errorOut.c_str());
        }

        if (oneP.evalCode == EVAL_IDENTITY_RECOVER)
        {
            if (newRecoverP.IsValid())
            {
                std::string errorOut = "Invalid output condition from identity: \"" + newIdentity.name + "\", more than one recovery condition";
                return eval->Error(errorOut.c_str());
            }
            newRecoverP = oneP;
        }
    }

    if (!newRecoverP.IsValid())
    {
        std::string errorOut = "Invalid recovery output condition for identity: \"" + newIdentity.name + "\"";
        return eval->Error(errorOut.c_str());
    }

    // if not fulfilled, neither recovery data nor its spend condition may be modified
    if (!fulfilled)
    {
        sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p);

        // if revoked, only fulfilled recovery condition allows primary mutation
        if (oldIdentity.IsRevoked() && (oldIdentity.IsPrimaryMutation(newIdentity, height)))
        {
            return eval->Error("Unauthorized modification of revoked identity without recovery authority");
        }

        if (oldIdentity.IsRecovery(newIdentity) || oldIdentity.IsRecoveryMutation(newIdentity, height))
        {
            return eval->Error("Unauthorized modification of recovery information");
        }

        for (int i = 1; i < p.vData.size() - 1; i++)
        {
            COptCCParams oneP(p.vData[i]);
            if (oneP.evalCode == EVAL_IDENTITY_RECOVER)
            {
                oldRecoverP = oneP;
            }
        }

        if (!oldRecoverP.IsValid() || 
            !newRecoverP.IsValid() ||
            oldRecoverP.version > newRecoverP.version ||
            oldRecoverP.m != newRecoverP.m ||
            oldRecoverP.n != newRecoverP.n ||
            oldRecoverP.vKeys != newRecoverP.vKeys)
        {
            return eval->Error("Unauthorized modification of identity recovery spend condition");
        }
    }
    return true;
}

bool ValidateIdentityCommitment(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // if not fulfilled, fail
    if (!fulfilled)
    {
        return eval->Error("missing required signature to spend");
    }

    if (!chainActive.LastTip())
    {
        return eval->Error("unable to find chain tip");
    }
    uint32_t height = chainActive.LastTip()->GetHeight() + 1;

    CCommitmentHash ch;
    CNameReservation reservation;
    CTransaction sourceTx;
    uint256 blkHash;

    LOCK(mempool.cs);
    if (myGetTransaction(spendingTx.vin[nIn].prevout.hash, sourceTx, blkHash))
    {
        COptCCParams p;
        if (sourceTx.vout[spendingTx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() && 
            p.evalCode == EVAL_IDENTITY_COMMITMENT && 
            p.version >= COptCCParams::VERSION_V3 &&
            p.vData.size() > 1 &&
            !blkHash.IsNull())
        {
            ch = CCommitmentHash(p.vData[0]);
        }
        else
        {
            return eval->Error("Invalid source commitment output");
        }

        int i;
        int outputNum = -1;
        for (i = 0; i < spendingTx.vout.size(); i++)
        {
            auto &output = spendingTx.vout[i];
            if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_RESERVATION && p.vData.size() > 1)
            {
                if (reservation.IsValid())
                {
                    return eval->Error("Invalid identity reservation output spend");
                }
                else
                {
                    reservation = CNameReservation(p.vData[0]);
                    if (!reservation.IsValid() || reservation.GetCommitment().hash != ch.hash)
                    {
                        return eval->Error("Identity reservation output spend does not match commitment");
                    }
                    outputNum = i;
                }
            }
        }
        if (outputNum != -1)
        {
            // can only be spent by a matching name reservation if validated
            // if there is no matching name reservation, it can be spent just by a valid signature
            CCurrencyDefinition &thisChain = ConnectedChains.ThisChain();
            return ValidateSpendingIdentityReservation(spendingTx, outputNum, eval->state, height, thisChain);
        }
    }
    return true;
}

bool ValidateIdentityReservation(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    // identity reservations are unspendable
    return eval->Error("Identity reservations are unspendable");
}

// quantum key outputs can be spent without restriction
bool ValidateQuantumKeyOut(struct CCcontract_info *cp, Eval* eval, const CTransaction &spendingTx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsQuantumKeyOutInput(const CScript &scriptSig)
{
    return false;
}

bool PrecheckQuantumKeyOut(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // need to ensure that the output is used for a signature in the tx before authorizing it
    return true;
}

bool IsIdentityInput(const CScript &scriptSig)
{
    return false;
}

bool ValidateFinalizeExport(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    return true;
}

bool IsFinalizeExportInput(const CScript &scriptSig)
{
    return false;
}

bool FinalizeExportContextualPreCheck(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    return true;
}

