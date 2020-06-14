// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "core_io.h"

#include "key_io.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

#include "cc/eval.h"
#include "pbaas/reserves.h"
#include "pbaas/notarization.h"

#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

using namespace std;

string FormatScript(const CScript& script)
{
    string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_CHECKMULTISIGVERIFY) {
                string str(GetOpName(op));
                if (str.substr(0, 3) == string("OP_")) {
                    ret += str.substr(3, string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } else {
                ret += strprintf("0x%x", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const map<unsigned char, string> mapSigHashTypes =
    boost::assign::map_list_of
    (static_cast<unsigned char>(SIGHASH_ALL), string("ALL"))
    (static_cast<unsigned char>(SIGHASH_ALL|SIGHASH_ANYONECANPAY), string("ALL|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_NONE), string("NONE"))
    (static_cast<unsigned char>(SIGHASH_NONE|SIGHASH_ANYONECANPAY), string("NONE|ANYONECANPAY"))
    (static_cast<unsigned char>(SIGHASH_SINGLE), string("SINGLE"))
    (static_cast<unsigned char>(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY), string("SINGLE|ANYONECANPAY"))
    ;

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    string str;
    opcodetype opcode;
    vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, NULL)) {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

string EncodeHexTx(const CTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

string EncodeHexBlk(const CBlock& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey,
                        UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses) {
        a.push_back(EncodeDestination(addr));
    }
    out.pushKV("addresses", a);
}

UniValue ValueFromAmount(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%08d", sign ? "-" : "", quotient, remainder));
}

UniValue CNodeData::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("networkaddress", networkAddress));
    obj.push_back(Pair("nodeidentity", EncodeDestination(CIdentityID(nodeIdentity))));
    return obj;
}

CCurrencyValueMap::CCurrencyValueMap(const UniValue &uni)
{
    // must be an array of key:value, where key is currency ID encoded as i-address
    if (uni.isObject())
    {
        const std::vector<std::string> &keys(uni.getKeys());
        const std::vector<UniValue> &values(uni.getValues());
        for (int i = 0; i < keys.size(); i++)
        {
            uint160 currencyID = GetDestinationID(DecodeDestination(keys[i]));
            if (currencyID.IsNull())
            {
                LogPrintf("Invalid JSON CurrencyValueMap\n");
                valueMap.clear();
                break;
            }
            if (valueMap.count(currencyID))
            {
                LogPrintf("Duplicate currency in JSON CurrencyValueMap\n");
                valueMap.clear();
                break;
            }

            try
            {
                valueMap[currencyID] = AmountFromValueNoErr(values[i]);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
                valueMap.clear();
                break;
            }
        }
    }
}

UniValue CCurrencyValueMap::ToUniValue() const
{
    UniValue retVal(UniValue::VOBJ);
    for (auto &curValue : valueMap)
    {
        retVal.push_back(Pair(EncodeDestination(CIdentityID(curValue.first)), ValueFromAmount(curValue.second)));
    }
    return retVal;
}

uint160 CCurrencyDefinition::GetID(const std::string &Name, uint160 &Parent)
{
    return CIdentity::GetID(Name, Parent);
}

uint160 CCurrencyDefinition::GetConditionID(int32_t condition) const
{
    return CCrossChainRPCData::GetConditionID(name, condition);
}

UniValue CCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("flags", (int32_t)flags));

    if (IsValid() && IsFractional())
    {
        UniValue currencyArr(UniValue::VARR);
        for (int i = 0; i < currencies.size(); i++)
        {
            UniValue currencyObj(UniValue::VOBJ);
            currencyObj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencies[i]))));
            currencyObj.push_back(Pair("weight", ValueFromAmount(i < weights.size() ? weights[i] : 0)));
            currencyObj.push_back(Pair("reserves", ValueFromAmount(i < reserves.size() ? reserves[i] : 0)));
            currencyObj.push_back(Pair("priceinreserve", ValueFromAmount(PriceInReserve(i))));
            currencyArr.push_back(currencyObj);
        }
        ret.push_back(Pair("reservecurrencies", currencyArr));
    }
    ret.push_back(Pair("initialsupply", ValueFromAmount(initialSupply)));
    ret.push_back(Pair("emitted", ValueFromAmount(emitted)));
    ret.push_back(Pair("supply", ValueFromAmount(supply)));
    return ret;
}

template <typename INNERVECTOR>
UniValue ValueVectorsToUniValue(const std::vector<std::string> &rowNames,
                                const std::vector<std::string> &columnNames,
                                const std::vector<INNERVECTOR *> &vec,
                                bool columnVectors)
{
    UniValue retVal(UniValue::VOBJ);
    if (columnVectors)
    {
        for (int i = 0; i < rowNames.size(); i++)
        {
            UniValue row(UniValue::VOBJ);
            for (int j = 0; j < columnNames.size(); j++)
            {
                row.push_back(Pair(columnNames[j], ValueFromAmount((*(vec[j])).size() > i ? (*(vec[j]))[i] : 0)));
            }
            retVal.push_back(Pair(rowNames[i], row));
        }
    }
    else
    {
        for (int i = 0; i < rowNames.size(); i++)
        {
            UniValue row(UniValue::VOBJ);
            for (int j = 0; j < columnNames.size(); j++)
            {
                row.push_back(Pair(columnNames[j], ValueFromAmount((*(vec[i])).size() > j ? (*(vec[i]))[j] : 0)));
            }
            retVal.push_back(Pair(rowNames[i], row));
        }
    }
    return retVal;
}

UniValue CCoinbaseCurrencyState::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret = ((CCurrencyState *)this)->ToUniValue();
    std::vector<std::string> rowNames;
    for (int i = 0; i < currencies.size(); i++)
    {
        rowNames.push_back(EncodeDestination(CIdentityID(currencies[i])));
    }
    std::vector<std::string> columnNames({"reservein", "nativein", "reserveout", "lastconversionprice", "fees", "conversionfees"});
    std::vector<const std::vector<CAmount> *> data = {&reserveIn, &nativeIn, &reserveOut, &conversionPrice, &fees, &conversionFees};

    ret.push_back(Pair("currencies", ValueVectorsToUniValue(rowNames, columnNames, data, true)));
    ret.push_back(Pair("nativefees", nativeFees));
    ret.push_back(Pair("nativeconversionfees", nativeConversionFees));
    return ret;
}

UniValue CPBaaSNotarization::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(currencyID))));
    obj.push_back(Pair("notaryaddress", EncodeDestination(notaryDest)));
    obj.push_back(Pair("notarizationheight", (int32_t)notarizationHeight));
    obj.push_back(Pair("mmrroot", mmrRoot.GetHex()));
    obj.push_back(Pair("notarizationprehash", notarizationPreHash.GetHex()));
    obj.push_back(Pair("work", ((UintToArith256(compactPower) << 128) >> 128).ToString()));
    obj.push_back(Pair("stake", (UintToArith256(compactPower) >> 128).ToString()));
    obj.push_back(Pair("currencystate", currencyState.ToUniValue()));
    obj.push_back(Pair("prevnotarization", prevNotarization.GetHex()));
    obj.push_back(Pair("prevheight", prevHeight));
    obj.push_back(Pair("crossnotarization", crossNotarization.GetHex()));
    obj.push_back(Pair("crossheight", crossHeight));
    UniValue nodesUni(UniValue::VARR);
    for (auto node : nodes)
    {
        nodesUni.push_back(node.ToUniValue());
    }
    obj.push_back(Pair("nodes", nodesUni));
    return obj;
}

UniValue CCurrencyDefinition::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);

    obj.push_back(Pair("name", name));
    obj.push_back(Pair("version", (int64_t)nVersion));
    obj.push_back(Pair("options", (int64_t)options));
    obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("currencyid", EncodeDestination(CIdentityID(GetID()))));
    obj.push_back(Pair("notarizationprotocol", (int)notarizationProtocol));
    obj.push_back(Pair("proofprotocol", (int)proofProtocol));

    obj.push_back(Pair("idregistrationprice", idRegistrationAmount));
    obj.push_back(Pair("idreferrallevels", idReferralLevels));

    // notaries are identities that perform specific functions for the currency's operation
    // related to notarizing an external currency source, as well as proving imports
    if (notaries.size())
    {
        UniValue notaryArr(UniValue::VARR);
        for (auto &notary : notaries)
        {
            notaryArr.push_back(EncodeDestination(CIdentityID(notary)));
        }
        obj.push_back(Pair("notaries", notaryArr));
    }
    obj.push_back(Pair("minnotariesconfirm", minNotariesConfirm));

    obj.push_back(Pair("billingperiod", billingPeriod));
    obj.push_back(Pair("notarizationreward", notarizationReward));
    obj.push_back(Pair("startblock", (int32_t)startBlock));
    obj.push_back(Pair("endblock", (int32_t)endBlock));

    // notaries are identities that perform specific functions for the currency's operation
    // related to notarizing an external currency source, as well as proving imports
    if (currencies.size())
    {
        UniValue currencyArr(UniValue::VARR);
        for (auto &currency : currencies)
        {
            currencyArr.push_back(EncodeDestination(CIdentityID(currency)));
        }
        obj.push_back(Pair("currencies", currencyArr));
    }

    if (weights.size())
    {
        UniValue weightArr(UniValue::VARR);
        for (auto &weight : weights)
        {
            weightArr.push_back(ValueFromAmount(weight));
        }
        obj.push_back(Pair("weights", weightArr));
    }

    if (conversions.size())
    {
        UniValue conversionArr(UniValue::VARR);
        for (auto &conversion : conversions)
        {
            conversionArr.push_back(ValueFromAmount(conversion));
        }
        obj.push_back(Pair("conversions", conversionArr));
    }

    if (minPreconvert.size())
    {
        UniValue minPreconvertArr(UniValue::VARR);
        for (auto &oneMin : minPreconvert)
        {
            minPreconvertArr.push_back(ValueFromAmount(oneMin));
        }
        obj.push_back(Pair("minpreconversion", minPreconvertArr));
    }

    if (maxPreconvert.size())
    {
        UniValue maxPreconvertArr(UniValue::VARR);
        for (auto &oneMax : maxPreconvert)
        {
            maxPreconvertArr.push_back(ValueFromAmount(oneMax));
        }
        obj.push_back(Pair("maxpreconversion", maxPreconvertArr));
    }

    if (preAllocationRatio)
    {
        obj.push_back(Pair("preallocationratio", ValueFromAmount(preAllocationRatio)));
    }

    if (preAllocation.size())
    {
        UniValue preAllocationArr(UniValue::VARR);
        for (auto &onePreAllocation : preAllocation)
        {
            UniValue onePreAlloc(UniValue::VOBJ);
            onePreAlloc.push_back(Pair(onePreAllocation.first.IsNull() ? "blockoneminer" : EncodeDestination(CIdentityID(onePreAllocation.first)), 
                                       ValueFromAmount(onePreAllocation.second)));
            preAllocationArr.push_back(onePreAlloc);
        }
        obj.push_back(Pair("preallocation", preAllocationArr));
    }

    if (contributions.size())
    {
        UniValue initialContributionArr(UniValue::VARR);
        for (auto &oneCurContributions : contributions)
        {
            initialContributionArr.push_back(ValueFromAmount(oneCurContributions));
        }
        obj.push_back(Pair("initialcontributions", initialContributionArr));
    }

    if (preconverted.size())
    {
        UniValue preconversionArr(UniValue::VARR);
        for (auto &onePreconversion : preconverted)
        {
            preconversionArr.push_back(ValueFromAmount(onePreconversion));
        }
        obj.push_back(Pair("preconversions", preconversionArr));
    }

    UniValue eraArr(UniValue::VARR);
    for (int i = 0; i < rewards.size(); i++)
    {
        UniValue era(UniValue::VOBJ);
        era.push_back(Pair("reward", rewards.size() > i ? rewards[i] : (int64_t)0));
        era.push_back(Pair("decay", rewardsDecay.size() > i ? rewardsDecay[i] : (int64_t)0));
        era.push_back(Pair("halving", halving.size() > i ? (int32_t)halving[i] : (int32_t)0));
        era.push_back(Pair("eraend", eraEnd.size() > i ? (int32_t)eraEnd[i] : (int32_t)0));
        eraArr.push_back(era);
    }
    obj.push_back(Pair("eras", eraArr));
    return obj;
}

UniValue CTokenOutput::ToUniValue() const
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("version", (int64_t)nVersion));
    ret.push_back(Pair("currencyid", currencyID.IsNull() ? "NULL" : EncodeDestination(CIdentityID(currencyID))));
    ret.push_back(Pair("value", ValueFromAmount(nValue)));
    return ret;
}

UniValue CReserveTransfer::ToUniValue() const
{
    UniValue ret(((CTokenOutput *)this)->ToUniValue());
    if (flags & PREALLOCATE)
    {
        ret.push_back(Pair("preallocation", true));
    }
    else if (flags & MINT_CURRENCY)
    {
        ret.push_back(Pair("mintedcurrency", true));
    }
    else
    {
        ret.push_back(Pair("convert", (bool)(flags & CONVERT)));
        ret.push_back(Pair("preconvert", (bool)(flags & PRECONVERT)));
        ret.push_back(Pair("feeoutput", (bool)(flags & FEE_OUTPUT)));
        ret.push_back(Pair("sendback", (bool)(flags & SEND_BACK)));
    }
    ret.push_back(Pair("fees", ValueFromAmount(nFees)));
    ret.push_back(Pair("destinationcurrencyid", EncodeDestination(CIdentityID(destCurrencyID))));
    std::string destStr;
    switch (destination.type)
    {
    case CTransferDestination::DEST_PKH:
        destStr = EncodeDestination(CKeyID(uint160(destination.destination)));
        break;

    case CTransferDestination::DEST_SH:
        destStr = EncodeDestination(CScriptID(uint160(destination.destination)));
        break;

    case CTransferDestination::DEST_ID:
        destStr = EncodeDestination(CIdentityID(uint160(destination.destination)));
        break;

    case CTransferDestination::DEST_QUANTUM:
        destStr = EncodeDestination(CQuantumID(uint160(destination.destination)));
        break;

    default:
        destStr = HexStr(destination.destination);
        break;
    }
    ret.push_back(Pair("destination", destStr));
    return ret;
}

UniValue CReserveExchange::ToUniValue() const
{
    UniValue ret(((CTokenOutput *)this)->ToUniValue());
    ret.push_back(Pair("toreserve", (bool)(flags & TO_RESERVE)));
    ret.push_back(Pair("tonative", !((bool)(flags & TO_RESERVE))));
    ret.push_back(Pair("limitorder", (bool)(flags & LIMIT)));
    if (flags & LIMIT)
    {
        ret.push_back(Pair("limitprice", ValueFromAmount(nLimit)));
    }
    ret.push_back(Pair("fillorkill", (bool)(flags & FILL_OR_KILL)));
    if (flags & FILL_OR_KILL)
    {
        ret.push_back(Pair("validbeforeblock", (int32_t)nValidBefore));
    }
    ret.push_back(Pair("sendoutput", (bool)(flags & SEND_OUTPUT)));
    return ret;
}

UniValue CCrossChainExport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int)nVersion));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("numinputs", numInputs));
    obj.push_back(Pair("totalamounts", totalAmounts.ToUniValue()));
    obj.push_back(Pair("totalfees", totalFees.ToUniValue()));
    return obj;
}

UniValue CCrossChainImport::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int)nVersion));
    obj.push_back(Pair("systemid", EncodeDestination(CIdentityID(systemID))));
    obj.push_back(Pair("valuein", importValue.ToUniValue()));
    obj.push_back(Pair("tokensout", totalReserveOutMap.ToUniValue()));
    return obj;
}

UniValue CPrincipal::ToUniValue() const
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", (int32_t)nVersion));
    obj.push_back(Pair("flags", (int32_t)flags));

    UniValue primaryAddressesUni(UniValue::VARR);
    for (int i = 0; i < primaryAddresses.size(); i++)
    {
        primaryAddressesUni.push_back(EncodeDestination(primaryAddresses[i]));
    }
    obj.push_back(Pair("primaryaddresses", primaryAddressesUni));
    obj.push_back(Pair("minimumsignatures", minSigs));
    return obj;
}

UniValue CIdentity::ToUniValue() const
{
    UniValue obj = ((CPrincipal *)this)->ToUniValue();

    obj.push_back(Pair("identityaddress", EncodeDestination(CIdentityID(GetID()))));
    obj.push_back(Pair("parent", EncodeDestination(CIdentityID(parent))));
    obj.push_back(Pair("name", name));

    UniValue hashes(UniValue::VOBJ);
    for (auto &entry : contentMap)
    {
        hashes.push_back(Pair(entry.first.GetHex(), entry.second.GetHex()));
    }
    obj.push_back(Pair("contentmap", hashes));

    obj.push_back(Pair("revocationauthority", EncodeDestination(CTxDestination(CIdentityID(revocationAuthority)))));
    obj.push_back(Pair("recoveryauthority", EncodeDestination(CTxDestination(CIdentityID(recoveryAuthority)))));
    if (privateAddresses.size())
    {
        obj.push_back(Pair("privateaddress", EncodePaymentAddress(privateAddresses[0])));
    }
    return obj;
}

UniValue CMMRProof::ToUniValue() const
{
    UniValue retObj(UniValue::VOBJ);
    for (auto &proof : proofSequence)
    {
        UniValue branchArray(UniValue::VARR);
        switch (proof->branchType)
        {
            case CMerkleBranchBase::BRANCH_BTC:
            {
                CBTCMerkleBranch &branch = *(CBTCMerkleBranch *)(proof);
                retObj.push_back(Pair("branchtype", "BTC"));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_NODE:
            {
                CMMRNodeBranch &branch = *(CMMRNodeBranch *)(proof);
                retObj.push_back(Pair("branchtype", "MMRBLAKENODE"));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                retObj.push_back(Pair("mmvsize", (int64_t)(branch.nSize)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
            case CMerkleBranchBase::BRANCH_MMRBLAKE_POWERNODE:
            {
                CMMRPowerNodeBranch &branch = *(CMMRPowerNodeBranch *)(proof);
                retObj.push_back(Pair("branchtype", "MMRBLAKEPOWERNODE"));
                retObj.push_back(Pair("index", (int64_t)(branch.nIndex)));
                retObj.push_back(Pair("mmvsize", (int64_t)(branch.nSize)));
                for (auto &oneHash : branch.branch)
                {
                    branchArray.push_back(oneHash.GetHex());
                }
                retObj.push_back(Pair("hashes", branchArray));
                break;
            }
        };
    }
    return retObj;
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex, bool fIncludeAsm)
{
    txnouttype type;
    vector<CTxDestination> addresses;

    // needs to be an object
    if (!out.isObject())
    {
        out = UniValue(UniValue::VOBJ);
    }

    int nRequired;
    ExtractDestinations(scriptPubKey, type, addresses, nRequired);
    out.push_back(Pair("type", GetTxnOutputType(type)));

    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.version >= COptCCParams::VERSION_V2)
    {
        switch(p.evalCode)
        {
            case EVAL_CURRENCY_DEFINITION:
            {
                CCurrencyDefinition definition;

                if (p.vData.size() && (definition = CCurrencyDefinition(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("currencydefinition", definition.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("currencydefinition", "invalid"));
                }
                break;
            }

            case EVAL_SERVICEREWARD:
            {
                CServiceReward reward;

                if (p.vData.size() && (reward = CServiceReward(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("pbaasServiceReward", reward.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("pbaasServiceReward", "invalid"));
                }
                break;
            }

            case EVAL_EARNEDNOTARIZATION:
            case EVAL_ACCEPTEDNOTARIZATION:
            {
                CPBaaSNotarization notarization;

                if (p.vData.size() && (notarization = CPBaaSNotarization(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("pbaasNotarization", notarization.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("pbaasNotarization", "invalid"));
                }
                break;
            }

            case EVAL_FINALIZE_NOTARIZATION:
            {
                CTransactionFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CTransactionFinalization(p.vData[0]);
                    out.push_back(Pair("finalizeNotarization", finalization.ToUniValue()));
                }
                break;
            }

            case EVAL_CURRENCYSTATE:
            {
                CCoinbaseCurrencyState cbcs;

                if (p.vData.size() && (cbcs = CCoinbaseCurrencyState(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("currencystate", cbcs.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("currencystate", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_TRANSFER:
            {
                CReserveTransfer rt;

                if (p.vData.size() && (rt = CReserveTransfer(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reservetransfer", rt.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reservetransfer", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_OUTPUT:
            {
                CTokenOutput ro;

                if (p.vData.size() && (ro = CTokenOutput(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reserveoutput", ro.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reserveoutput", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_EXCHANGE:
            {
                CReserveExchange rex;

                if (p.vData.size() && (rex = CReserveExchange(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reserveexchange", rex.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reserveexchange", "invalid"));
                }
                break;
            }

            case EVAL_RESERVE_DEPOSIT:
            {
                CTokenOutput ro;

                if (p.vData.size() && (ro = CTokenOutput(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("reservedeposit", ro.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("reservedeposit", "invalid"));
                }
                break;
            }

            case EVAL_CROSSCHAIN_EXPORT:
            {
                CCrossChainExport ccx;

                if (p.vData.size() && (ccx = CCrossChainExport(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("crosschainexport", ccx.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("crosschainexport", "invalid"));
                }
                break;
            }

            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci;

                if (p.vData.size() && (cci = CCrossChainImport(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("crosschainimport", cci.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("crosschainimport", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_PRIMARY:
            {
                CIdentity identity;

                if (p.vData.size() && (identity = CIdentity(p.vData[0])).IsValid())
                {
                    out.push_back(Pair("identityprimary", identity.ToUniValue()));
                }
                else
                {
                    out.push_back(Pair("identityprimary", "invalid"));
                }
                break;
            }

            case EVAL_IDENTITY_REVOKE:
                out.push_back(Pair("identityrevoke", ""));
                break;

            case EVAL_IDENTITY_RECOVER:
                out.push_back(Pair("identityrecover", ""));
                break;

            case EVAL_IDENTITY_COMMITMENT:
                out.push_back(Pair("identitycommitment", ""));
                break;

            case EVAL_IDENTITY_RESERVATION:
                out.push_back(Pair("identityreservation", ""));
                break;

            case EVAL_STAKEGUARD:
                out.push_back(Pair("stakeguard", ""));
                break;

            case EVAL_FINALIZE_EXPORT:
            {
                CTransactionFinalization finalization;

                if (p.vData.size())
                {
                    finalization = CTransactionFinalization(p.vData[0]);
                    out.push_back(Pair("finalizeexport", finalization.ToUniValue()));
                }
                break;
            }

            default:
                out.push_back(Pair("unknown", ""));
        }
    }

    if (addresses.size())
    {
        out.push_back(Pair("reqSigs", nRequired));

        UniValue a(UniValue::VARR);
        for (const CTxDestination& addr : addresses) {
            a.push_back(EncodeDestination(addr));
        }
        out.push_back(Pair("addresses", a));
    }

    if (fIncludeAsm)
    {
        out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    }

    if (fIncludeHex)
    {
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
    }
}

void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true, false);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
