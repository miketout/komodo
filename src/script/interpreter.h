// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "univalue.h"
#include "script_error.h"
#include "pbaas/crosschainrpc.h"
#include "primitives/transaction.h"
#include "script/cc.h"

#include <vector>
#include <map>
#include <stdint.h>
#include <string>
#include <climits>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Special case nIn for signing JoinSplits. */
const unsigned int NOT_AN_INPUT = UINT_MAX;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    // In Zcash this is required, and validation of non-strict-DER signatures is not implemented.
    //SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),
};

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror);

struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs, hashJoinSplits, hashShieldedSpends, hashShieldedOutputs;

    PrecomputedTransactionData(const CTransaction& tx);
};

enum SigVersion
{
    SIGVERSION_SPROUT = 0,
    SIGVERSION_OVERWINTER = 1,
    SIGVERSION_SAPLING = 2,
};

// smart transactions are derived from crypto-conditions, but they are not the same thing. A smart transaction is described
// along with any eval-specific parameters, as an object encoded in the COptCCParams following the OP_CHECK_CRYPTOCONDITION opcode
// of a script. smart transactions are not encoded with ASN.1, but with standard Bitcoin serialization and an object model
// defined in PBaaS. while as of this comment, the cryptocondition code is used to validate crypto-conditions, that is only
// internally to determine thresholds and remain compatible with evals. The protocol contains only PBaaS serialized descriptions,
// and the signatures contain a vector of this object, serialized in one fulfillment that gets updated for multisig.
class CSmartTransactionSignature
{
public:
    enum {
        SIGTYPE_NONE = 0,
        SIGTYPE_SECP256K1 = 1,
        SIGTYPE_SECP256K1_LEN = 64,
        SIGTYPE_FALCON = 2
    };

    uint8_t sigType;
    std::vector<unsigned char> pubKeyData;
    std::vector<unsigned char> signature;

    CSmartTransactionSignature() : sigType(SIGTYPE_NONE) {}
    CSmartTransactionSignature(uint8_t sType, const std::vector<unsigned char> &pkData, const std::vector<unsigned char> &sig) : sigType(sType), pubKeyData(pubKeyData), signature(sig) {}
    CSmartTransactionSignature(uint8_t sType, const CPubKey &pk, const std::vector<unsigned char> &sig) : sigType(sType), pubKeyData(pk.begin(), pk.end()), signature(sig) {}
    CSmartTransactionSignature(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sigType);
        READWRITE(pubKeyData);
        READWRITE(signature);
    }

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("signaturetype", (int)sigType));
        obj.push_back(Pair("publickeydata", HexBytes(&pubKeyData[0], pubKeyData.size())));
        obj.push_back(Pair("signature", HexBytes(&signature[0], signature.size())));
        return obj;
    }

    bool IsValid()
    {
        return (sigType == SIGTYPE_SECP256K1 || sigType == SIGTYPE_FALCON) &&
               CPubKey(pubKeyData).IsFullyValid();
    }
};

class CSmartTransactionSignatures
{
public:
    enum {
        FIRST_VERSION = 1,
        LAST_VERSION = 1,
        VERSION = 1
    };
    uint8_t version;
    uint8_t sigHashType;
    std::map<uint160, CSmartTransactionSignature> signatures;

    CSmartTransactionSignatures() : version(VERSION) {}
    CSmartTransactionSignatures(uint8_t hashType, const std::map<uint160, CSmartTransactionSignature> &signatureMap, uint8_t ver=VERSION) : version(ver), sigHashType(hashType), signatures(signatureMap) {}
    CSmartTransactionSignatures(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(sigHashType);
        std::vector<CSmartTransactionSignature> sigVec;
        if (ser_action.ForRead())
        {
            READWRITE(sigVec);
            for (auto oneSig : sigVec)
            {
                if (oneSig.sigType == oneSig.SIGTYPE_SECP256K1)
                {
                    CPubKey pk(oneSig.pubKeyData);
                    if (pk.IsFullyValid())
                    {
                        signatures[pk.GetID()] = oneSig;
                    }
                }
            }
        }
        else
        {
            for (auto oneSigPair : signatures)
            {
                sigVec.push_back(oneSigPair.second);
            }
            READWRITE(sigVec);
        }
    }

    bool AddSignature(const CSmartTransactionSignature &oneSig)
    {
        if (oneSig.sigType == oneSig.SIGTYPE_SECP256K1)
        {
            CPubKey pk(oneSig.pubKeyData);
            if (pk.IsFullyValid())
            {
                signatures[pk.GetID()] = oneSig;
		return true;
            }
        }
	return false;
    }

    UniValue ToUniValue() const
    {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("version", (int)version));
        obj.push_back(Pair("signaturehashtype", (int)sigHashType));
        UniValue uniSigs(UniValue::VARR);
        for (auto sig : signatures)
        {
            uniSigs.push_back(sig.second.ToUniValue());
        }
        obj.push_back(Pair("signatures", uniSigs));
        return obj;
    }

    bool IsValid()
    {
        if (!(version >= FIRST_VERSION && version <= LAST_VERSION))
        {
            return false;
        }
        for (auto oneSig : signatures)
        {
            if (oneSig.second.sigType == oneSig.second.SIGTYPE_SECP256K1)
            {
                CPubKey pk(oneSig.second.pubKeyData);
                uint160 pubKeyHash = pk.GetID();
                //printf("pk.IsFullyValid(): %s, pk.GetID(): %s, oneSig.first: %s\n", pk.IsFullyValid() ? "true" : "false", pk.GetID().GetHex().c_str(), oneSig.first.GetHex().c_str());
                if (!pk.IsFullyValid() || pk.GetID() != oneSig.first)
                {
                    return false;
                }
            }
            else if (oneSig.second.sigType == oneSig.second.SIGTYPE_FALCON)
            {
                return false;
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }
};

uint256 SignatureHash(
    const CScript &scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType,
    const CAmount& amount,
    uint32_t consensusBranchId,
    const PrecomputedTransactionData* cache = NULL);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(
        const std::vector<unsigned char>& scriptSig,
        const std::vector<unsigned char>& vchPubKey,
        const CScript& scriptCode,
        uint32_t consensusBranchId) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual int CheckCryptoCondition(
            const std::vector<unsigned char>& condBin,
            const std::vector<unsigned char>& ffillBin,
            const CScript& scriptCode,
            uint32_t consensusBranchId) const
    {
        return false;
    }

    static std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> ExtractIDMap(const CScript &scriptPubKeyIn, const CKeyStore &keystore, uint32_t spendHeight=INT32_MAX); // use wallet

    virtual void SetIDMap(const std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> &map) {}
    virtual std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> IDMap()
    {
        return std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>>();
    }
    virtual bool IsIDMapSet() const { return false; }
    virtual bool CanValidateIDs() const { return false; }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
protected:
    const CTransaction* txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;
    std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> idMap;
    bool idMapSet;

    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> *pIdMap);
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn, const std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> *pIdMap);
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const CScript *pScriptPubKeyIn=nullptr, const CKeyStore *pKeyStore=nullptr, uint32_t spendHeight=INT32_MAX);
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn, const CScript *pScriptPubKeyIn=nullptr, const CKeyStore *pKeyStore=nullptr, uint32_t spendHeight=INT32_MAX);
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, uint32_t consensusBranchId) const;
    bool CheckLockTime(const CScriptNum& nLockTime) const;
    void SetIDMap(const std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> &map)
    {
        idMapSet = true;
        idMap = map;
    }
    std::map<uint160, std::pair<int, std::vector<std::vector<unsigned char>>>> IDMap()
    {
        return idMap;
    }
    bool IsIDMapSet() const { return idMapSet; }
    int CheckCryptoCondition(
        const std::vector<unsigned char>& condBin,
        const std::vector<unsigned char>& ffillBin,
        const CScript& scriptCode,
        uint32_t consensusBranchId) const;
    virtual int CheckEvalCondition(const CC *cond, int fulfilled) const;
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amount) : TransactionSignatureChecker(&txTo, nInIn, amount), txTo(*txToIn) {}
};

bool EvalScript(
    std::vector<std::vector<unsigned char> >& stack,
    const CScript& script,
    unsigned int flags,
    const BaseSignatureChecker& checker,
    uint32_t consensusBranchId,
    ScriptError* error = NULL);
bool VerifyScript(
    const CScript& scriptSig,
    const CScript& scriptPubKey,
    unsigned int flags,
    const BaseSignatureChecker& checker,
    uint32_t consensusBranchId,
    ScriptError* serror = NULL);
#endif // BITCOIN_SCRIPT_INTERPRETER_H
