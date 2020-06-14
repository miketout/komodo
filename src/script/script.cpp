// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "script.h"

#include "tinyformat.h"
#include "utilstrencodings.h"
#include "script/cc.h"
#include "cc/eval.h"
#include "cryptoconditions/include/cryptoconditions.h"
#include "standard.h"
#include "pbaas/reserves.h"
#include "key_io.h"
#include "univalue.h"
#include "pbaas/identity.h"

using namespace std;

namespace {
    inline std::string ValueString(const std::vector<unsigned char>& vch)
    {
        if (vch.size() <= 4)
            return strprintf("%d", CScriptNum(vch, false).getint());
        else
            return HexStr(vch);
    }
} // anon namespace

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";
    case OP_CHECKCRYPTOCONDITION   : return "OP_CHECKCRYPTOCONDITION";
    case OP_CHECKCRYPTOCONDITIONVERIFY
                                   : return "OP_CHECKCRYPTOCONDITIONVERIFY";

    // expansion
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLDATA/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

uint160 GetConditionID(uint160 cid, int32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

CTxDestination TransferDestinationToDestination(const CTransferDestination &transferDest)
{
    CTxDestination retDest;
    switch (transferDest.type)
    {
    case CTransferDestination::DEST_PKH:
        retDest = CKeyID(uint160(transferDest.destination));
        break;

    case CTransferDestination::DEST_PK:
        {
            CPubKey pk;
            pk.Set(transferDest.destination.begin(), transferDest.destination.end());
            retDest = pk;
            break;
        }

    case CTransferDestination::DEST_SH:
        retDest = CScriptID(uint160(transferDest.destination));
        break;

    case CTransferDestination::DEST_ID:
        retDest = CIdentityID(uint160(transferDest.destination));
        break;

    case CTransferDestination::DEST_FULLID:
        retDest = CIdentityID(CIdentity(transferDest.destination).GetID());
        break;

    case CTransferDestination::DEST_QUANTUM:
        retDest = CQuantumID(uint160(transferDest.destination));
        break;
    }
    return retDest;
}

CTransferDestination DestinationToTransferDestination(const CTxDestination &dest)
{
    CTransferDestination retDest;
    switch (dest.which())
    {
    case CTransferDestination::DEST_PKH:
    case CTransferDestination::DEST_PK:
    case CTransferDestination::DEST_SH:
    case CTransferDestination::DEST_ID:
    case CTransferDestination::DEST_QUANTUM:
        retDest = CTransferDestination(dest.which(), GetDestinationBytes(dest));
        break;
    }
    return retDest;
}

CTransferDestination IdentityToTransferDestination(const CIdentity &identity)
{
    return CTransferDestination(CTransferDestination::DEST_FULLID, ::AsVector(identity));
}

CIdentity TransferDestinationToIdentity(const CTransferDestination &dest)
{
    CIdentity retIdentity;
    switch (dest.type)
    {
        case CTransferDestination::DEST_FULLID:
        {
            ::FromVector(dest.destination, retIdentity);
            break;
        }        
    }
    return retIdentity;
}

std::vector<CTxDestination> TransferDestinationsToDestinations(const std::vector<CTransferDestination> &transferDests)
{
    std::vector<CTxDestination> retDests;
    for (auto &dest : transferDests)
    {
        retDests.push_back(TransferDestinationToDestination(dest));
    }
    return retDests;
}

std::vector<CTransferDestination> DestinationsToTransferDestinations(const std::vector<CTxDestination> &dests)
{
    std::vector<CTransferDestination> retDests;
    for (auto &dest : dests)
    {
        retDests.push_back(DestinationToTransferDestination(dest));
    }
    return retDests;
}

CStakeInfo::CStakeInfo(std::vector<unsigned char> vch)
{
    ::FromVector(vch, *this);
}

std::vector<unsigned char> CStakeInfo::AsVector() const
{
    return ::AsVector(*this);
}

unsigned int CScript::MAX_SCRIPT_ELEMENT_SIZE = MAX_SCRIPT_ELEMENT_SIZE_V2;

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToPublicKeyHash() const
{
    // Extra-fast test for pay-to-pubkey-hash CScripts:
    return (this->size() == 25 &&
	    (*this)[0] == OP_DUP &&
	    (*this)[1] == OP_HASH160 &&
	    (*this)[2] == 0x14 &&
	    (*this)[23] == OP_EQUALVERIFY &&
	    (*this)[24] == OP_CHECKSIG);
}

bool CScript::IsPayToPublicKey() const
{
    // Extra-fast test for pay-to-pubkey CScripts:
    return (this->size() == 35 &&
            (*this)[0] == 33 &&
            (*this)[34] == OP_CHECKSIG);
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL);
}

// this returns true if either there is nothing left and pc points at the end, or 
// all instructions from the pc to the end of the script are balanced pushes and pops
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetBalancedData(const_iterator& pc, std::vector<std::vector<unsigned char>>& vSolutions) const
{
    int netPushes = 0;
    vSolutions.clear();

    while (pc < end())
    {
        vector<unsigned char> data;
        opcodetype opcode;
        if (this->GetOp(pc, opcode, data))
        {
            if (opcode == OP_DROP)
            {
                // this should never pop what it hasn't pushed (like a success code)
                if (--netPushes < 0)
                    return false;
            } 
            else 
            {
                // push or fail
                netPushes++;
                if (opcode == OP_0)
                {
                    data.resize(1);
                    data[0] = 0;
                    vSolutions.push_back(data);
                }
                else if (opcode >= OP_1 && opcode <= OP_16)
                {
                    data.resize(1);
                    data[0] = (opcode - OP_1) + 1;
                    vSolutions.push_back(data);
                }
                else if (opcode > 0 && opcode <= OP_PUSHDATA4 && data.size() > 0)
                {
                    vSolutions.push_back(data);
                }
                else
                    return false;
            }
        }
        else
            return false;
    }
    return netPushes == 0;
}

// this returns true if either there is nothing left and pc points at the end
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetPushedData(CScript::const_iterator pc, std::vector<std::vector<unsigned char>>& vData) const
{
    vector<unsigned char> data;
    opcodetype opcode;
    std::vector<unsigned char> vch1 = std::vector<unsigned char>(1);

    vData.clear();

    while (pc < end())
    {
        if (GetOp(pc, opcode, data))
        {
            if (opcode == OP_0)
            {
                vch1[0] = 0;
                vData.push_back(vch1);
            }
            else if (opcode >= OP_1 && opcode <= OP_16)
            {
                vch1[0] = (opcode - OP_1) + 1;
                vData.push_back(vch1);
            }
            else if (opcode > 0 && opcode <= OP_PUSHDATA4 && data.size() > 0)
            {
                vData.push_back(data);
            }
            else
                return false;
        }
    }
    return vData.size() != 0;
}

// this returns true if either there is nothing left and pc points at the end
// if there is data, it also returns all the values as byte vectors in a list of vectors
bool CScript::GetOpretData(std::vector<std::vector<unsigned char>>& vData) const
{
    vector<unsigned char> data;
    opcodetype opcode;
    CScript::const_iterator pc = this->begin();

    if (GetOp(pc, opcode, data) && opcode == OP_RETURN)
    {
        return GetPushedData(pc, vData);
    }
    else return false;
}

bool CScript::IsPayToCryptoCondition(CScript *pCCSubScript, std::vector<std::vector<unsigned char>>& vParams) const
{
    const_iterator pc = begin();
    vector<unsigned char> firstParam;
    vector<unsigned char> data;
    opcodetype opcode;
    if (this->GetOp(pc, opcode, firstParam))
        // Sha256 conditions are <76 bytes
        if (opcode > OP_0 && opcode < OP_PUSHDATA1)
            if (this->GetOp(pc, opcode, data))
                if (opcode == OP_CHECKCRYPTOCONDITION)
                {
                    const_iterator pcCCEnd = pc;
                    if (GetBalancedData(pc, vParams))
                    {
                        if (pCCSubScript)
                            *pCCSubScript = CScript(begin(), pcCCEnd);
                        vParams.push_back(firstParam);
                        return true;
                    }
                }
    return false;
}

bool CScript::IsPayToCryptoCondition(CScript *pCCSubScript) const
{
    std::vector<std::vector<unsigned char>> vParams;
    return IsPayToCryptoCondition(pCCSubScript, vParams);
}

bool CScript::IsPayToCryptoCondition() const
{
    return IsPayToCryptoCondition((CScript *)NULL);
}

extern uint160 ASSETCHAINS_CHAINID, VERUS_CHAINID;

bool CScript::IsInstantSpend() const
{
    COptCCParams p;
    bool isInstantSpend = false;
    if (!_IsVerusActive() && IsPayToCryptoCondition(p) && p.IsValid())
    {
        // instant spends must be to expected instant spend crypto conditions and to the right address as well
        if ((p.evalCode == EVAL_EARNEDNOTARIZATION && GetDestinationID(p.vKeys[0]) == GetConditionID(VERUS_CHAINID, p.evalCode)) || 
            (p.evalCode == EVAL_CURRENCYSTATE && GetDestinationID(p.vKeys[0]) == GetConditionID(ASSETCHAINS_CHAINID, p.evalCode)) || 
            (p.evalCode == EVAL_CROSSCHAIN_IMPORT && GetDestinationID(p.vKeys[0]) == GetConditionID(VERUS_CHAINID, p.evalCode)) ||
            (p.evalCode == EVAL_CROSSCHAIN_EXPORT && GetDestinationID(p.vKeys[0]) == GetConditionID(VERUS_CHAINID, p.evalCode)))
        {
            isInstantSpend = true;
        }
    }
    return isInstantSpend;
}

bool CScript::IsPayToCryptoCondition(COptCCParams &ccParams) const
{
    CScript subScript;
    std::vector<std::vector<unsigned char>> vParams;

    if (IsPayToCryptoCondition(&subScript, vParams))
    {
        if (!vParams.empty())
        {
            ccParams = COptCCParams(vParams[0]);
            for (int i = 1; i < vParams.size(); i++)
            {
                ccParams.vData.push_back(vParams[i]);
            }
        }
        else
        {
            // make sure that we return it in a consistent and known state
            ccParams = COptCCParams();
        }
        return true;
    }
    ccParams = COptCCParams();
    return false;
}

bool CScript::IsPayToCryptoCondition(CScript *ccSubScript, std::vector<std::vector<unsigned char>> &vParams, COptCCParams &optParams) const
{
    if (IsPayToCryptoCondition(ccSubScript, vParams))
    {
        if (vParams.size() > 0)
        {
            optParams = COptCCParams(vParams[0]);
            return optParams.IsValid();
        }
    }
    return false;
}

bool CScript::IsPayToCryptoCondition(uint32_t *ecode) const
{
    CScript sub;
    std::vector<std::vector<unsigned char>> vParams;
    COptCCParams p;
    if (IsPayToCryptoCondition(&sub, vParams, p))
    {
        *ecode = p.evalCode;
        return true;
    }
    return false;
}

CScript &CScript::ReplaceCCParams(const COptCCParams &params)
{
    CScript subScript;
    std::vector<std::vector<unsigned char>> vParams;
    COptCCParams p;
    if (this->IsPayToCryptoCondition(&subScript, vParams, p) || p.evalCode != params.evalCode)
    {
        // add the object to the end of the script
        *this = subScript;
        *this << params.AsVector() << OP_DROP;
    }
    return *this;
}

bool CScript::IsSpendableOutputType(const COptCCParams &p) const
{
    bool isSpendable = true;
    if (!p.IsValid())
    {
        return isSpendable;
    }
    switch (p.evalCode)
    {
        case EVAL_CURRENCYSTATE:
        case EVAL_RESERVE_TRANSFER:
        case EVAL_RESERVE_EXCHANGE:
        case EVAL_CROSSCHAIN_IMPORT:
        case EVAL_IDENTITY_COMMITMENT:
        case EVAL_IDENTITY_PRIMARY:
        case EVAL_IDENTITY_REVOKE:
        case EVAL_IDENTITY_RECOVER:
        case EVAL_IDENTITY_RESERVATION:
        {
            isSpendable = false;
            break;
        }
    }
    return isSpendable;
}

bool CScript::IsSpendableOutputType() const
{
    COptCCParams p;
    if (IsPayToCryptoCondition(p))
    {
        return IsSpendableOutputType(p);
    }
    // default for non-CC outputs is true, this is to protect from accidentally spending specific CC output types, 
    // even though they could be spent
    return true;
}

CCurrencyValueMap CScript::ReserveOutValue(COptCCParams &p, bool spendableOnly) const
{
    CCurrencyValueMap retVal;

    // already validated above
    if (IsPayToCryptoCondition(p) && p.IsValid() && (!spendableOnly || IsSpendableOutputType(p)))
    {
        switch (p.evalCode)
        {
            case EVAL_RESERVE_OUTPUT:
            {
                CTokenOutput ro(p.vData[0]);
                if (ro.nValue)
                {
                    retVal.valueMap[ro.currencyID] = ro.nValue;
                }
                break;
            }

            case EVAL_RESERVE_DEPOSIT:
            {
                CTokenOutput ro(p.vData[0]);
                if (ro.nValue)
                {
                    retVal.valueMap[ro.currencyID] = ro.nValue;
                }
                break;
            }

            case EVAL_CURRENCYSTATE:
            {
                CCoinbaseCurrencyState cbcs(p.vData[0]);
                for (int i = 0; i < cbcs.currencies.size(); i++)
                {
                    if (cbcs.reserveOut[i])
                    {
                        retVal.valueMap[cbcs.currencies[i]] = cbcs.reserveOut[i];
                    }
                }
                break;
            }

            case EVAL_RESERVE_TRANSFER:
            {
                CReserveTransfer rt(p.vData[0]);
                // this currency can only be present as native
                if (!(rt.flags & (rt.MINT_CURRENCY | rt.PREALLOCATE)) && rt.currencyID != ASSETCHAINS_CHAINID)
                {
                    retVal.valueMap[rt.currencyID] = rt.nValue + rt.nFees;
                }
                break;
            }

            case EVAL_RESERVE_EXCHANGE:
            {
                CReserveExchange re(p.vData[0]);
                // reserve out amount when converting to reserve is 0, since the amount cannot be calculated in isolation as an input
                // if reserve in, we can consider the output the same reserve value as the input
                if (!(re.flags & re.TO_RESERVE))
                {
                    retVal.valueMap[re.currencyID] = re.nValue;
                }
                break;
            }
            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci(p.vData[0]);
                // reserve out amount when converting to reserve is 0, since the amount cannot be calculated in isolation as an input
                // if reserve in, we can consider the output the same reserve value as the input
                retVal = cci.totalReserveOutMap;
                break;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CScript::ReserveOutValue() const
{
    COptCCParams p;
    return ReserveOutValue(p);
}

bool CScript::SetReserveOutValue(const CCurrencyValueMap &newValues)
{
    COptCCParams p;
    CAmount newVal = 0;

    // already validated above
    if (::IsPayToCryptoCondition(*this, p) && p.IsValid())
    {
        switch (p.evalCode)
        {
            case EVAL_RESERVE_OUTPUT:
            {
                if (newValues.valueMap.size() != 1)
                {
                    return false;
                }
                CTokenOutput ro(p.vData[0]);
                ro.currencyID = newValues.valueMap.begin()->first;
                ro.nValue = newValues.valueMap.begin()->second;
                p.vData[0] = ro.AsVector();
                break;
            }
            case EVAL_RESERVE_TRANSFER:
            {
                if (newValues.valueMap.size() != 1)
                {
                    return false;
                }
                CReserveTransfer rt(p.vData[0]);
                rt.currencyID = newValues.valueMap.begin()->first;
                rt.nValue = newValues.valueMap.begin()->second;
                p.vData[0] = rt.AsVector();
                break;
            }
            case EVAL_RESERVE_EXCHANGE:
            {
                if (newValues.valueMap.size() != 1)
                {
                    return false;
                }
                CReserveExchange re(p.vData[0]);
                re.currencyID = newValues.valueMap.begin()->first;
                re.nValue = newValues.valueMap.begin()->second;
                p.vData[0] = re.AsVector();
                break;
            }
            case EVAL_CROSSCHAIN_IMPORT:
            {
                CCrossChainImport cci(p.vData[0]);
                cci.importValue = newValues;
                p.vData[0] = cci.AsVector();
                break;
            }
            // cross chain import thread holds the original conversion amounts
            case EVAL_CURRENCYSTATE:
            {
                CCoinbaseCurrencyState cbcs(p.vData[0]);
                for (int i = 0; i < cbcs.currencies.size(); i++)
                {
                    auto it = newValues.valueMap.find(cbcs.currencies[i]);
                    if (it != newValues.valueMap.end())
                    {
                        cbcs.reserveOut[i] = it->second;
                    }
                }
                p.vData[0] = cbcs.AsVector();
                break;
            }

            default:
                return false;
        }
        *this = ReplaceCCParams(p);
        return true;
    }
    return false;
}

bool CScript::MayAcceptCryptoCondition() const
{
    // Get the type mask of the condition
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (!this->GetOp(pc, opcode, data)) return false;
    if (!(opcode > OP_0 && opcode < OP_PUSHDATA1)) return false;
    CC *cond = cc_readConditionBinary(data.data(), data.size());
    if (!cond) return false;

    uint32_t eCode;
    if (!IsPayToCryptoCondition(&eCode))
    {
        return false;
    }

    bool out = IsSupportedCryptoCondition(cond, eCode);

    cc_free(cond);
    return out;
}

// also checks if the eval code is consistent
bool CScript::MayAcceptCryptoCondition(int evalCode) const
{
    // Get the type mask of the condition
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (!this->GetOp(pc, opcode, data)) return false;
    if (!(opcode > OP_0 && opcode < OP_PUSHDATA1)) return false;
    CC *cond = cc_readConditionBinary(data.data(), data.size());
    if (!cond) return false;

    bool out = IsSupportedCryptoCondition(cond, evalCode);

    cc_free(cond);
    return out;
}

bool CScript::IsCoinImport() const
{
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (this->GetOp(pc, opcode, data))
        if (opcode > OP_0 && opcode <= OP_PUSHDATA4)
            return data.begin()[0] == EVAL_IMPORTCOIN;
    return false;
}

bool CScript::IsPushOnly() const
{
    const_iterator pc = begin();
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

// if the front of the script has check lock time verify. this is a fairly simple check.
// accepts NULL as parameter if unlockTime is not needed.
bool CScript::IsCheckLockTimeVerify(int64_t *unlockTime) const
{
    opcodetype op;
    std::vector<unsigned char> unlockTimeParam = std::vector<unsigned char>();
    CScript::const_iterator it = this->begin();

    if (this->GetOp2(it, op, &unlockTimeParam))
    {
        if (unlockTimeParam.size() >= 0 && unlockTimeParam.size() < 6 &&
            (*this)[unlockTimeParam.size() + 1] == OP_CHECKLOCKTIMEVERIFY)
        {
            int i = unlockTimeParam.size() - 1;
            for (*unlockTime = 0; i >= 0; i--)
            {
                *unlockTime <<= 8;
                *unlockTime |= *((unsigned char *)unlockTimeParam.data() + i);
            }
            return true;
        }
    }
    return false;
}

bool CScript::IsCheckLockTimeVerify() const
{
    int64_t ult;
    return this->IsCheckLockTimeVerify(&ult);
}

std::string CScript::ToString() const
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const_iterator pc = begin();
    while (pc < end())
    {
        if (!str.empty())
            str += " ";
        if (!GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4)
            str += ValueString(vch);
        else
            str += GetOpName(opcode);
    }
    return str;
}

CScript::ScriptType CScript::GetType() const
{
    if (this->IsPayToPublicKeyHash())
    {
        return CScript::P2PKH;
    }
    else if (this->IsPayToScriptHash())
    {
        return CScript::P2SH;
    }
    else if (this->IsPayToPublicKey())
    {
        return CScript::P2PK;
    }
    else if (this->IsPayToCryptoCondition())
    {
        return CScript::P2CC;
    }

    // We don't know this script type
    return CScript::UNKNOWN;
}

uint160 CScript::AddressHash() const
{
    uint160 addressHash;
    COptCCParams p;
    if (this->IsPayToScriptHash()) {
        addressHash = uint160(std::vector<unsigned char>(this->begin()+2, this->begin()+22));
    }
    else if (this->IsPayToPublicKeyHash())
    {
        addressHash = uint160(std::vector<unsigned char>(this->begin()+3, this->begin()+23));
    }
    else if (this->IsPayToPublicKey())
    {
        std::vector<unsigned char> hashBytes(this->begin()+1, this->begin()+34);
        addressHash = Hash160(hashBytes);
    }
    else if (this->IsPayToCryptoCondition(p)) {
        if (p.IsValid() && (p.vKeys.size()))
        {
            COptCCParams master;
            if (p.version >= p.VERSION_V3 && p.vData.size() > 1 && (master = COptCCParams(p.vData.back())).IsValid() && master.vKeys.size())
            {
                addressHash = GetDestinationID(master.vKeys[0]);
            }
            else
            {
                addressHash = GetDestinationID(p.vKeys[0]);
            }
        }
        else
        {
            vector<unsigned char> hashBytes(this->begin(), this->end());
            addressHash = Hash160(hashBytes);
        }
    }
    return addressHash;
}

std::vector<CTxDestination> CScript::GetDestinations() const
{
    std::vector<CTxDestination> destinations;
    COptCCParams p;
    if (this->IsPayToCryptoCondition(p))
    {
        if (p.IsValid() && (p.vKeys.size()))
        {
            destinations = p.GetDestinations();
        }
        else
        {
            vector<unsigned char> hashBytes(this->begin(), this->end());
            destinations.push_back(CKeyID(Hash160(hashBytes)));
        }
    }
    else if (this->IsPayToScriptHash()) {
        destinations.push_back(CScriptID(uint160(std::vector<unsigned char>(this->begin()+2, this->begin()+22))));
    }
    else if (this->IsPayToPublicKeyHash())
    {
        destinations.push_back(CKeyID(uint160(std::vector<unsigned char>(this->begin()+3, this->begin()+23))));
    }
    else if (this->IsPayToPublicKey())
    {
        std::vector<unsigned char> hashBytes(this->begin()+1, this->begin()+34);
        destinations.push_back(CPubKey(hashBytes));
    }
    return destinations;
}

uint160 GetNameID(const std::string &Name, const uint160 &parent)
{
    uint160 writeable = parent;
    return CIdentity::GetID(Name, writeable);
}

CAmount AmountFromValueNoErr(const UniValue& value)
{
    try
    {
        CAmount amount;
        if (!value.isNum() && !value.isStr())
        {
            amount = 0;
        }
        else if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        {
            amount = 0;
        }
        else if (!MoneyRange(amount))
        {
            amount = 0;
        }
        return amount;
    }
    catch(const std::exception& e)
    {
        return 0;
    }
}

CCurrencyValueMap::CCurrencyValueMap(const std::vector<uint160> &currencyIDs, const std::vector<CAmount> &amounts)
{
    int commonNum = currencyIDs.size() >= amounts.size() ? amounts.size() : currencyIDs.size();
    for (int i = 0; i < commonNum; i++)
    {
        valueMap[currencyIDs[i]] = amounts[i];
    }
}

bool operator<(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    // to be less than means, in this order:
    // 1. To have fewer non-zero currencies.
    // 2. If not fewer currencies, to be unable to be subtracted from the one being checked
    //    without creating negative values
    if (!a.valueMap.size() && !b.valueMap.size())
    {
        return false;
    }
    bool isaltb = false;

    for (auto &oneVal : b.valueMap)
    {
        if (oneVal.second)
        {
            auto it = a.valueMap.find(oneVal.first);
            if (it == a.valueMap.end() || it->second < oneVal.second)
            {
                isaltb = true;
            }
        }
    }
    return isaltb;
}

bool operator>(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return b < a;
}

bool operator==(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    if (a.valueMap.size() != b.valueMap.size())
    {
        return false;
    }

    bool isaeqb = true;
    for (auto &oneVal : a.valueMap)
    {
        auto it = b.valueMap.find(oneVal.first);
        if (it == b.valueMap.end() || it->second != oneVal.second)
        {
            isaeqb = false;
            break;
        }
    }
    return isaeqb;
}

bool operator!=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return !(a == b);
}

bool operator<=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return (a < b) || (a == b);
}

bool operator>=(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    return b <= a;
}

CCurrencyValueMap operator+(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    CCurrencyValueMap retVal = a;
    if (a.valueMap.size() || b.valueMap.size())
    {
        for (auto &oneVal : b.valueMap)
        {
            auto it = retVal.valueMap.find(oneVal.first);
            if (it == retVal.valueMap.end())
            {
                retVal.valueMap[oneVal.first] = oneVal.second;
            }
            else
            {
                it->second += oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap operator-(const CCurrencyValueMap& a, const CCurrencyValueMap& b)
{
    CCurrencyValueMap retVal = a;
    if (a.valueMap.size() || b.valueMap.size())
    {
        for (auto &oneVal : b.valueMap)
        {
            auto it = retVal.valueMap.find(oneVal.first);
            if (it == retVal.valueMap.end())
            {
                retVal.valueMap[oneVal.first] = -oneVal.second;
            }
            else
            {
                it->second -= oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap operator+(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second += b;
    }
    return retVal;
}

CCurrencyValueMap operator-(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second -= b;
    }
    return retVal;
}

CCurrencyValueMap operator*(const CCurrencyValueMap& a, int b)
{
    CCurrencyValueMap retVal = a;
    for (auto &oneVal : retVal.valueMap)
    {
        oneVal.second *= b;
    }
    return retVal;
}

const CCurrencyValueMap &CCurrencyValueMap::operator-=(const CCurrencyValueMap& operand)
{
    return *this = *this - operand;
}

const CCurrencyValueMap &CCurrencyValueMap::operator+=(const CCurrencyValueMap& operand)
{
    return *this = *this + operand;
}

// determine if the operand intersects this map
bool CCurrencyValueMap::Intersects(const CCurrencyValueMap& operand) const
{
    bool retVal = false;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end())
            {
                if (it->second > 0 && oneVal.second > 0)
                {
                    retVal = true;
                    break;
                }
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::IntersectingValues(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end() &&
                it->second != 0 && 
                oneVal.second != 0)
            {
                retVal.valueMap[oneVal.first] = oneVal.second;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::CanonicalMap() const
{
    CCurrencyValueMap retVal;
    for (auto valPair : valueMap)
    {
        if (valPair.second != 0)
        {
            retVal.valueMap.insert(valPair);
        }
    }
    return retVal;
}

CCurrencyValueMap CCurrencyValueMap::NonIntersectingValues(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal = operand;

    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end())
            {
                if (it->second > 0 && oneVal.second > 0)
                {
                    retVal.valueMap.erase(it);
                }
            }
        }
    }
    return retVal;
}

bool CCurrencyValueMap::IsValid() const
{
    for (auto &oneVal : valueMap)
    {
        if (oneVal.first.IsNull())
        {
            return false;
        }
    }
    return true;
}

bool CCurrencyValueMap::HasNegative() const
{
    for (auto &oneVal : valueMap)
    {
        if (oneVal.second < 0)
        {
            return true;
        }
    }
    return false;
}

// subtract, but do not subtract to negative values
CCurrencyValueMap CCurrencyValueMap::SubtractToZero(const CCurrencyValueMap& operand) const
{
    CCurrencyValueMap retVal = *this;
    std::vector<uint160> toRemove;
    if (valueMap.size() && operand.valueMap.size())
    {
        for (auto &oneVal : retVal.valueMap)
        {
            auto it = operand.valueMap.find(oneVal.first);
            if (it != operand.valueMap.end())
            {
                oneVal.second = oneVal.second - it->second;
                if (oneVal.second <= 0)
                {
                    toRemove.push_back(oneVal.first);
                }
            }
        }
    }
    for (auto &toErase : toRemove)
    {
        retVal.valueMap.erase(toErase);
    }
    return retVal;
}

std::vector<CAmount> CCurrencyValueMap::AsCurrencyVector(const std::vector<uint160> &currencies) const
{
    std::vector<CAmount> retVal(currencies.size());
    for (int i = 0; i < currencies.size(); i++)
    {
        auto it = valueMap.find(currencies[i]);
        retVal[i] = it != valueMap.end() ? it->second : 0;
    }
    return retVal;
}
