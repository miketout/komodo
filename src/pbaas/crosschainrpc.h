/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for PBaaS cross chain communication.
 * 
 * In merge mining and notarization, Verus acts as a hub that other PBaaS chains
 * call via RPC in order to get information that allows earning and submitting
 * notarizations.
 * 
 */

#ifndef CROSSCHAINRPC_H
#define CROSSCHAINRPC_H

#include "version.h"
#include "uint256.h"
#include <univalue/include/univalue.h>
#include <sstream>
#include "streams.h"
#include "boost/algorithm/string.hpp"

static const int DEFAULT_RPC_TIMEOUT=900;
static const uint32_t PBAAS_VERSION = 1;
static const uint32_t PBAAS_VERSION_INVALID = 0;

class CTransaction;
class CScript;

class CCrossChainRPCData
{
public:
    std::string host;
    int32_t port;
    std::string credentials;

    CCrossChainRPCData() : port(0) {}

    CCrossChainRPCData(std::string Host, int32_t Port, std::string Credentials) :
        host(Host), port(Port), credentials(Credentials) {}
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(host);
        READWRITE(port);        
        READWRITE(credentials);
    }

    static CCrossChainRPCData LoadFromConfig(std::string fPath="");

    static uint160 GetID(std::string name);

    static uint160 GetConditionID(uint160 cid, int32_t condition);
    static uint160 GetConditionID(std::string name, int32_t condition);

    UniValue ToUniValue() const;
};

// credentials for now are "user:password"
UniValue RPCCall(const std::string& strMethod, 
                 const UniValue& params, 
                 const std::string credentials="user:pass", 
                 int port=27486, 
                 const std::string host="127.0.0.1", 
                 int timeout=DEFAULT_RPC_TIMEOUT);

UniValue RPCCallRoot(const std::string& strMethod, const UniValue& params, int timeout=DEFAULT_RPC_TIMEOUT);

template <typename SERIALIZABLE>
std::vector<unsigned char> AsVector(const SERIALIZABLE &obj)
{
    CDataStream s = CDataStream(SER_NETWORK, PROTOCOL_VERSION);
    s << obj;
    return std::vector<unsigned char>(s.begin(), s.end());
}

template <typename SERIALIZABLE>
void FromVector(const std::vector<unsigned char> &vch, SERIALIZABLE &obj)
{
    CDataStream s(vch, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        obj.Unserialize(s);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

bool uni_get_bool(UniValue uv, bool def=false);
int32_t uni_get_int(UniValue uv, int32_t def=0);
int64_t uni_get_int64(UniValue uv, int64_t def =0);
std::string uni_get_str(UniValue uv, std::string def="");
std::vector<UniValue> uni_getValues(UniValue uv, std::vector<UniValue> def=std::vector<UniValue>());

class CNodeData
{
public:
    std::string networkAddress;
    uint160 nodeIdentity;

    CNodeData() {}
    CNodeData(const UniValue &uni);
    CNodeData(std::string netAddr, uint160 paymentID) : networkAddress(netAddr), nodeIdentity(paymentID) {}
    CNodeData(std::string netAddr, std::string paymentAddr);
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(networkAddress);
        READWRITE(nodeIdentity);        
    }

    UniValue ToUniValue() const;
    bool IsValid()
    {
        return networkAddress != "";
    }
};

class CTransferDestination
{
public:
    enum
    {
        DEST_INVALID = 0,
        DEST_PK = 1,
        DEST_PKH = 2,
        DEST_SH = 3,
        DEST_ID = 4,
        DEST_FULLID = 5,
        DEST_QUANTUM = 6,
        DEST_RAW = 127
    };
    uint8_t type;
    std::vector<unsigned char> destination;

    CTransferDestination() : type(DEST_INVALID) {}
    CTransferDestination(uint8_t Type, std::vector<unsigned char> Destination) : type(Type), destination(Destination) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(type);
        READWRITE(destination);
    }
};

extern int64_t AmountFromValueNoErr(const UniValue& value);

// convenience class for collections of currencies that supports comparisons, including ==, >, >=, <, <=, as well as addition, and subtraction
class CCurrencyValueMap
{
public:
    std::map<uint160, int64_t> valueMap;

    CCurrencyValueMap() {}
    CCurrencyValueMap(const std::map<uint160, int64_t> &vMap) : valueMap(vMap) {}
    CCurrencyValueMap(const std::vector<uint160> &currencyIDs, const std::vector<int64_t> &amounts);
    CCurrencyValueMap(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(valueMap);
        std::vector<std::pair<uint160, int64_t>> vPairs;
        if (ser_action.ForRead())
        {
            READWRITE(vPairs);
            for (auto &oneVal : vPairs)
            {
                valueMap.insert(oneVal);
            }
        }
        else
        {
            for (auto &oneVal : valueMap)
            {
                vPairs.push_back(oneVal);
            }
            READWRITE(vPairs);
        }
    }

    friend bool operator<(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator>(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator==(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator!=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator<=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend bool operator>=(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator+(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator-(const CCurrencyValueMap& a, const CCurrencyValueMap& b);
    friend CCurrencyValueMap operator+(const CCurrencyValueMap& a, int b);
    friend CCurrencyValueMap operator-(const CCurrencyValueMap& a, int b);
    friend CCurrencyValueMap operator*(const CCurrencyValueMap& a, int b);

    const CCurrencyValueMap &operator-=(const CCurrencyValueMap& operand);
    const CCurrencyValueMap &operator+=(const CCurrencyValueMap& operand);

    // determine if the operand intersects this map
    bool Intersects(const CCurrencyValueMap& operand) const;
    CCurrencyValueMap CanonicalMap() const;
    CCurrencyValueMap IntersectingValues(const CCurrencyValueMap& operand) const;
    CCurrencyValueMap NonIntersectingValues(const CCurrencyValueMap& operand) const;
    bool IsValid() const;
    bool HasNegative() const;

    // subtract, but do not subtract to negative values
    CCurrencyValueMap SubtractToZero(const CCurrencyValueMap& operand) const;

    std::vector<int64_t> AsCurrencyVector(const std::vector<uint160> &currencies) const;

    UniValue ToUniValue() const;
};

// This defines the currency characteristics of a PBaaS currency that will be the native coins of a PBaaS chain
class CCurrencyDefinition
{
public:
    static const int64_t DEFAULT_ID_REGISTRATION_AMOUNT = 10000000000;

    enum ELimitsDefaults
    {
        MIN_PER_BLOCK_NOTARIZATION = 1000000, // 0.01 VRSC per block notarization minimum
        MIN_RESERVE_CONTRIBUTION = 1000000, // 0.01 minimum per reserve contribution minimum
        MIN_BILLING_PERIOD = 960,           // 16 hour minimum billing period for notarization, typically expect days/weeks/months
        MIN_CURRENCY_LIFE = 480,            // 8 hour minimum lifetime, which gives 8 hours of minimum billing to notarize conclusion
        DEFAULT_OUTPUT_VALUE = 0,           // 0 VRSC default output value
        DEFAULT_ID_REFERRAL_LEVELS = 3,
        MAX_NAME_LEN = 64
    };

    enum ECurrencyOptions
    {
        OPTION_FRACTIONAL = 1,              // allows reserve conversion using base calculations when set
        OPTION_ID_ISSUANCE = 2,             // clear is permissionless, if set, IDs may only be created by controlling ID
        OPTION_ID_STAKING = 4,              // all IDs on chain stake equally, rather than value-based staking
        OPTION_ID_REFERRALS = 8,            // if set, this chain supports referrals
        OPTION_ID_REFERRALREQUIRED = 0x10,  // if set, this chain requires referrals
        OPTION_TOKEN = 0x20,                // if set, notarizations and import/export are for an external currency bridge or token
        OPTION_CANBERESERVE = 0x40,         // if set, this currency can be used as a reserve for a liquid currency
        OPTION_FEESASRESERVE = 0x80,         // if set, this currency can be used as a reserve for a liquid currency
        OPTION_GATEWAY = 0x100,              // if set, notarizations and import/export are for an external currency bridge or token
    };

    // these should be pluggable in function
    enum ENotarizationProtocol
    {
        NOTARIZATION_INVALID = 0,           // notarization protocol must have valid type
        NOTARIZATION_AUTO = 1,              // PBaaS autonotarization
        NOTARIZATION_NOTARY_CONFIRM = 2,    // autonotarization with confirmation by specified notaries
        NOTARIZATION_NOTARY_CHAINID = 3     // chain identity controls notarization and currency supply
    };

    enum EProofProtocol
    {
        PROOF_INVALID = 0,                  // proof protocol must have valid type
        PROOF_PBAASMMR = 1,                 // Verus MMR proof, no notaries required
        PROOF_CHAINID = 2,                  // if signed by the chain ID, that is considered proof
        PROOF_KOMODONOTARIZATION = 3        // proven by Komodo notarization
    };

    uint32_t nVersion;                      // version of this chain definition data structure to allow for extensions (not daemon version)
    uint32_t options;                       // flags to determine fungibility, type of currency, blockchain and ID options, and conversion

    uint160 parent;                         // parent PBaaS namespace
    std::string name;                       // currency name matching name of identity in namespace

    // the interface to the currency controller. systemID refers to the controlling blockchain or currency that serves as a gateway
    uint160 systemID;                       // native system of currency home, for BTC.VRSC: BTC, for VQUAD.VRSC: QUAD.VRSC, for QUAD.VRSC, QUAD.VRSC
    CTransferDestination nativeCurrencyID;  // ID of the currency in its native system
    int32_t notarizationProtocol;           // method of notarization
    int32_t proofProtocol;                  // method of proving imports and other elements

    int64_t idRegistrationAmount;           // normal cost of ID registration
    int32_t idReferralLevels;               // number of referral levels to divide among

    // notaries, if present, have the power to control an external bridge interface to either other blockchains, or
    // other currency systems, and/or map them to tokens on other cryptocurrency ecosystems
    std::vector<uint160> notaries;          // a list of notary IDs, which if present, are the only identities capable of confirming notarizations
    int32_t minNotariesConfirm;             // requires this many unique notaries to confirm a notarization
    int32_t billingPeriod;                  // number of blocks in one billing period
    int64_t notarizationReward;             // default amount per block for all costs of notarization

    // parent start and end time if there is an end time for the expected use of this currency
    int32_t startBlock;                     // block # that indicates the end of pre-launch when a chain fails or begins running and if token, becomes active for use
    int32_t endBlock;                       // block after which this is considered end-of-lifed, which applies to task-specific currencies

    // initial states for reserve currencies
    std::vector<uint160> currencies;        // currency identifiers
    std::vector<int32_t> weights;           // value weights of each currency

    std::vector<int64_t> conversions;       // initial conversion ratio in each currency value is conversion * maxpreconvert/(maxpreconvert + premine)
    std::vector<int64_t> minPreconvert;     // can be used for Kickstarter-like launch and return all non-network fees upon failure to meet minimum
    std::vector<int64_t> maxPreconvert;     // maximum amount of each reserve that can be pre-converted

    int32_t preAllocationRatio;             // if non-zero, a ratio of the initial supply instead of a fixed number is used to calculate total preallocation
    std::vector<std::pair<uint160, int64_t>> preAllocation; // pre-allocation recipients, from pre-allocation/premine, emitted after reserve weights are set
    std::vector<int64_t> contributions;     // initial contributions
    std::vector<int64_t> preconverted;      // actual converted amount if known

    // for PBaaS chains, this defines the currency issuance schedule
    // external chains or custodial tokens do not require a PBaaS chain to import and export currency
    std::vector<int64_t> rewards;           // initial reward in each of native coin, if this is a reserve the number represents percentage of supply w/satoshis
    std::vector<int64_t> rewardsDecay;      // decay of rewards at halvings during the era
    std::vector<int32_t> halving;           // number of blocks between halvings
    std::vector<int32_t> eraEnd;            // block number that ends each ERA

    CCurrencyDefinition() : nVersion(PBAAS_VERSION_INVALID) {}

    CCurrencyDefinition(const UniValue &obj);

    CCurrencyDefinition(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCurrencyDefinition(const CScript &scriptPubKey);
    static std::vector<CCurrencyDefinition> GetCurrencyDefinitions(const CTransaction &tx);

    CCurrencyDefinition(uint32_t Options, uint160 Parent, const std::string &Name, const uint160 &SystemID, const CTransferDestination &NativeID,
                        ENotarizationProtocol NotarizationProtocol, EProofProtocol ProofProtocol, int64_t IDRegistrationAmount, int32_t IDReferralLevels,
                        const std::vector<uint160> &Notaries, int32_t MinNotariesConfirm, int32_t BillingPeriod, int64_t NotaryReward,
                        int32_t StartBlock, int32_t EndBlock, std::vector<uint160> Currencies, std::vector<int32_t> Weights, 
                        std::vector<int64_t> Conversions, std::vector<int64_t> MinPreconvert, std::vector<int64_t> MaxPreconvert,
                        int32_t PreAllocationRatio, std::vector<std::pair<uint160, int64_t>> PreAllocation, std::vector<int64_t> Contributions,
                        std::vector<int64_t> Preconverted, const std::vector<int64_t> &chainRewards, const std::vector<int64_t> &chainRewardsDecay,
                        const std::vector<int32_t> &chainHalving, const std::vector<int32_t> &chainEraEnd) :
                        nVersion(PBAAS_VERSION),
                        options(Options),
                        parent(Parent),
                        name(Name),
                        systemID(SystemID),
                        nativeCurrencyID(NativeID),
                        notarizationProtocol(NotarizationProtocol),
                        proofProtocol(ProofProtocol),
                        idRegistrationAmount(IDRegistrationAmount),
                        idReferralLevels(IDReferralLevels),
                        notaries(Notaries),
                        minNotariesConfirm(MinNotariesConfirm),
                        billingPeriod(BillingPeriod),
                        notarizationReward(NotaryReward),
                        startBlock(StartBlock),
                        endBlock(EndBlock),
                        currencies(Currencies),
                        weights(Weights),
                        conversions(Conversions),
                        minPreconvert(MinPreconvert),
                        maxPreconvert(MaxPreconvert),
                        preAllocationRatio(PreAllocationRatio),
                        preAllocation(PreAllocation),
                        contributions(Contributions),
                        preconverted(Preconverted),
                        rewards(chainRewards),
                        rewardsDecay(chainRewardsDecay),
                        halving(chainHalving),
                        eraEnd(chainEraEnd)
    {
        if (name.size() > (KOMODO_ASSETCHAIN_MAXLEN - 1))
        {
            name.resize(KOMODO_ASSETCHAIN_MAXLEN - 1);
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(options);        
        READWRITE(parent);        
        READWRITE(LIMITED_STRING(name, MAX_NAME_LEN));        
        READWRITE(systemID);
        READWRITE(nativeCurrencyID);
        READWRITE(notarizationProtocol);
        READWRITE(proofProtocol);
        READWRITE(VARINT(idRegistrationAmount));
        READWRITE(VARINT(idReferralLevels));
        READWRITE(notaries);
        READWRITE(VARINT(minNotariesConfirm));
        READWRITE(VARINT(billingPeriod));
        READWRITE(VARINT(notarizationReward));
        READWRITE(VARINT(startBlock));
        READWRITE(VARINT(endBlock));
        READWRITE(currencies);
        READWRITE(weights);
        READWRITE(conversions);
        READWRITE(minPreconvert);
        READWRITE(maxPreconvert);
        READWRITE(VARINT(preAllocationRatio));
        READWRITE(preAllocation);
        READWRITE(contributions);
        READWRITE(preconverted);
        READWRITE(rewards);
        READWRITE(rewardsDecay);
        READWRITE(halving);
        READWRITE(eraEnd);
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    static uint160 GetID(const std::string &Name, uint160 &Parent);

    static inline uint160 GetID(const std::string &Name)
    {
        uint160 Parent;
        return GetID(Name, Parent);
    }

    uint160 GetID() const
    {
        uint160 Parent = parent;
        return GetID(name, Parent);
    }

    uint160 GetConditionID(int32_t condition) const;

    bool IsValid() const
    {
        return (nVersion != PBAAS_VERSION_INVALID) && name.size() > 0 && name.size() <= (KOMODO_ASSETCHAIN_MAXLEN - 1);
    }

    int32_t ChainOptions() const
    {
        return options;
    }

    UniValue ToUniValue() const;

    int GetDefinedPort() const;

    bool IsFractional() const
    {
        return ChainOptions() & OPTION_FRACTIONAL;
    }

    bool CanBeReserve() const
    {
        return ChainOptions() & OPTION_CANBERESERVE;
    }

    bool IsToken() const
    {
        return ChainOptions() & OPTION_TOKEN;
    }

    void SetToken(bool isToken)
    {
        if (isToken)
        {
            options |= OPTION_TOKEN;
        }
        else
        {
            options &= ~OPTION_TOKEN;
        }
    }

    std::map<uint160, int32_t> GetCurrenciesMap() const
    {
        std::map<uint160, int32_t> retVal;
        for (int i = 0; i < currencies.size(); i++)
        {
            retVal[currencies[i]] = i;
        }
        return retVal;
    }

    bool IDRequiresPermission() const
    {
        return ChainOptions() & OPTION_ID_ISSUANCE;
    }

    bool IDStaking() const
    {
        return ChainOptions() & OPTION_ID_STAKING;
    }

    bool IDReferrals() const
    {
        return ChainOptions() & OPTION_ID_REFERRALS;
    }

    bool IDReferralRequired() const
    {
        return ChainOptions() & OPTION_ID_REFERRALREQUIRED;
    }

    int IDReferralLevels() const
    {
        if (IDReferrals() || IDReferralRequired())
        {
            return idReferralLevels;
        }
        else
        {
            return 0;
        }
    }

    int64_t IDFullRegistrationAmount() const
    {
        return idRegistrationAmount;
    }

    int64_t IDReferredRegistrationAmount() const
    {
        if (!IDReferrals())
        {
            return idRegistrationAmount;
        }
        else
        {
            return (idRegistrationAmount * (idReferralLevels + 1)) / (idReferralLevels + 2);
        }
    }

    int64_t IDReferralAmount() const
    {
        if (!IDReferrals())
        {
            return 0;
        }
        else
        {
            return idRegistrationAmount / (idReferralLevels + 2);
        }
    }

    static int64_t CalculateRatioOfValue(int64_t value, int64_t ratio);
    int64_t GetTotalPreallocation() const;

    std::vector<std::pair<uint160, int64_t>> GetPreAllocationAmounts() const;
};

extern int64_t AmountFromValue(const UniValue& value);
extern int64_t AmountFromValueNoErr(const UniValue& value);
extern UniValue ValueFromAmount(const int64_t& amount);

#endif
