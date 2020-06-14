/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides reserve currency functions, leveraging the multi-precision boost libraries to calculate reserve currency conversions
 * in a predictable manner that can achieve consensus.
 * 
 */

#ifndef PBAAS_RESERVES_H
#define PBAAS_RESERVES_H

#include <sstream>
#include <univalue/include/univalue.h>
#include "pbaas/crosschainrpc.h"
#include "arith_uint256.h"
#include <boost/multiprecision/cpp_dec_float.hpp>
#include "librustzcash.h"
#include "pubkey.h"
#include "amount.h"
#include <map>

#ifndef SATOSHIDEN
#define SATOSHIDEN ((uint64_t)100000000L)
#endif

using boost::multiprecision::cpp_dec_float_50;
class CCoinsViewCache;
class CInputDescriptor;
class CBaseChainObject;
class CTransaction;
class CMutableTransaction;
class CTxOut;
class CReserveTransactionDescriptor;
class CCurrencyState;

// reserve output is a special kind of token output that does not have to carry it's identifier, as it
// is always assumed to be the reserve currency of the current chain.
class CTokenOutput
{
public:
    enum
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRSTVALID = 1,
        VERSION_LASTVALID = 1,
    };

    static std::vector<uint160> *reserveIDs;

    uint32_t nVersion;              // information about this currency
    uint160 currencyID;             // currency ID
    CAmount nValue;                 // amount of input reserve coins this UTXO represents before any conversion

    CTokenOutput(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CTokenOutput(const UniValue &obj);

    CTokenOutput() : nVersion(VERSION_CURRENT), nValue(0) { }

    CTokenOutput(const uint160 &curID, CAmount value) : nVersion(VERSION_CURRENT), currencyID(curID), nValue(value) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nVersion));
        READWRITE(currencyID);
        READWRITE(VARINT(nValue));
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        // we don't support op returns, value must be in native or reserve
        return nVersion >= VERSION_FIRSTVALID && nVersion <= VERSION_LASTVALID;
    }
};

class CReserveTransfer : public CTokenOutput
{
public:
    enum EOptions
    {
        VALID = 1,
        CONVERT = 2,
        PRECONVERT = 4,
        FEE_OUTPUT = 8,                     // one per import, amount must match total percentage of fees for exporter, no pre-convert allowed
        SEND_BACK = 0x10,                   // fee is sent back immediately to destination on exporting chain
        MINT_CURRENCY = 0x20,               // set when this output is being minted on import
        PREALLOCATE = 0x40                  // combined with minting for pre-allocation of currency
    };

    enum EConstants
    {
        DESTINATION_BYTE_DIVISOR = 128      // destination vector is divided by this and result is multiplied by normal fee and added to transfer fee
    };

    static const CAmount DEFAULT_PER_STEP_FEE = 10000; // default fee for each step of each transfer (initial mining, transfer, mining on new chain)

    uint32_t flags;                         // type of transfer and options
    CAmount nFees;                          // cross-chain network fees only, separated out to enable market conversions, conversion fees are additional
    uint160 destCurrencyID;                 // system to export to, which may represent a PBaaS chain or external bridge
    CTransferDestination destination;       // system specific address to send funds to on the target chain

    CReserveTransfer(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveTransfer() : CTokenOutput(), flags(0), nFees(0) { }

    CReserveTransfer(uint32_t Flags, const uint160 &cID, CAmount value, CAmount fees, const uint160 &destCurID, const CTransferDestination &dest) : 
        CTokenOutput(cID, value), flags(Flags), nFees(fees), destCurrencyID(destCurID), destination(dest) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
        READWRITE(VARINT(flags));
        READWRITE(VARINT(nFees));
        READWRITE(destCurrencyID);
        READWRITE(destination);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    CCurrencyValueMap CalculateFee(uint32_t flags, CAmount transferTotal) const;

    static CAmount CalculateTransferFee(const CTransferDestination &destination);

    CAmount CalculateTransferFee() const;

    bool IsValid() const
    {
        return CTokenOutput::IsValid() && (nFees > 0 || flags & FEE_OUTPUT) && destination.destination.size();
    }
};

// convert from $VRSC to fractional reserve coin or vice versa. coinID determines which
// in either direction, this is burned in the block. if burned, the block must contain less than a
// maximum reasonable number of exchange outputs, which must be sorted, hashed, and used to validate
// the outputs that must match exactly on any transaction spending the output. since fees are not
// included in outputs, it is assumed that a miner will spend the output in the same block to recover
// exchange fees
class CReserveExchange : public CTokenOutput
{
public:
    // flags
    enum EFlags
    {
        VALID = 1,
        TO_RESERVE = 0x80000,           // from fractional currency to reserve, default is reserve to fractional
        LIMIT = 0x100000,               // observe the limit when converting
        FILL_OR_KILL = 0x200000,        // if not filled before nValidBefore but before expiry, no execution, mined with fee, output pass through
        ALL_OR_NONE = 0x400000,         // will not execute partial order
        SEND_OUTPUT = 0x800000          // send the output of this exchange to the target chain, only valid if output is reserve
    };

    // success fee is calculated by multiplying the amount by this number and dividing by satoshis (100,000,000), not less than 10x the absolute SUCCESS_FEE
    // failure fee, meaning the valid before block is past but it is not expired is the difference between input and output and must follow those rules
    // it is deducted in the success case from the success fee, so there is no fee beyond the success fee paid
    static const CAmount SUCCESS_FEE = 25000;
    static const CAmount MIN_SUCCESS_FEE = 50000;
    static const CAmount MIN_PARTIAL = 10000000;        // making partial fill minimum the number at which minimum fee meets standard percent fee,
    static const CAmount MIN_NET_CONVERSION = 10000000; // minimum conversion for input
    static const CAmount FILL_OR_KILL_FEE = 10000;

    uint32_t flags;                                     // type of transfer and options
    CAmount nLimit;                                     // limit price to sell or buy currency
    uint32_t nValidBefore;                              // if not filled on or after this block, can mine tx, but is spendable to refund input

    CReserveExchange(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CReserveExchange() : CTokenOutput(), nLimit(0), nValidBefore(0) { }

    CReserveExchange(uint32_t Flags, const uint160 &cID, CAmount amountIn, CAmount Limit=0, uint32_t ValidBefore=0) : 
        CTokenOutput(cID, amountIn), flags(Flags), nLimit(Limit), nValidBefore(ValidBefore) {}

    CReserveExchange(const UniValue &uni);
    CReserveExchange(const CTransaction &tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
        READWRITE(VARINT(flags));
        READWRITE(VARINT(nLimit));
        READWRITE(nValidBefore);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        // this needs an actual check
        return CTokenOutput::IsValid();
    }

    UniValue ToUniValue() const;

    bool IsExpired(int32_t height)
    {
        return height >= nValidBefore;
    }
};

// import transactions and tokens from another chain
// this represents the chain, the currencies, and the amounts of each
// it may also import IDs from the chain on which they were defined
class CCrossChainImport
{
public:
    static const uint32_t VERSION_INVALID = 0;
    static const uint32_t VERSION_CURRENT = 1;
    static const uint32_t VERSION_LAST = 1;
    uint32_t nVersion;
    uint160 systemID;                                   // the blockchain or currency system source from where these transactions come
    CCurrencyValueMap importValue;                      // total amount of coins imported from chain with or without conversion, including fees
    CCurrencyValueMap totalReserveOutMap;               // all non-native currencies being held in this thread and released on import

    CCrossChainImport() : nVersion(VERSION_INVALID) {}
    CCrossChainImport(const uint160 &cID, const CCurrencyValueMap &ImportValue, const CCurrencyValueMap &InitialReserveOutput=CCurrencyValueMap()) : 
                        nVersion(VERSION_CURRENT), systemID(cID), importValue(ImportValue), totalReserveOutMap(InitialReserveOutput) { }

    CCrossChainImport(const std::vector<unsigned char> &asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCrossChainImport(const CTransaction &tx, int32_t *pOutNum=nullptr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(systemID);
        READWRITE(importValue);
        READWRITE(totalReserveOutMap);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion > VERSION_INVALID && nVersion <= VERSION_LAST && !systemID.IsNull();
    }

    UniValue ToUniValue() const;
};

// describes an entire output that will be realized on a target chain. target is specified as part of an aggregated transaction.
class CCrossChainExport
{
public:
    static const int MIN_BLOCKS = 10;
    static const int MIN_INPUTS = 10;
    static const int MAX_EXPORT_INPUTS = 50;
    static const uint32_t VERSION_INVALID = 0;
    static const uint32_t VERSION_CURRENT = 1;
    static const uint32_t VERSION_LAST = 1;
    uint32_t nVersion;
    uint160 systemID;                           // target blockchain or currency system ID
    int32_t numInputs;                          // number of inputs aggregated to calculate the fee percentage
    CCurrencyValueMap totalAmounts;             // total amount of inputs of each currency, including fees
    CCurrencyValueMap totalFees;                // total amount of fees of each currency to split between miner on exporting chain and importing chain

    CCrossChainExport() : nVersion(VERSION_INVALID), numInputs(0) {}

    CCrossChainExport(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCrossChainExport(uint160 SystemID, int32_t numin, const CCurrencyValueMap &values, const CCurrencyValueMap &fees) : 
                      nVersion(VERSION_CURRENT), systemID(SystemID), numInputs(numin), totalAmounts(values), totalFees(fees) {}

    CCrossChainExport(const CTransaction &tx, int32_t *pCCXOutputNum=nullptr);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(systemID);
        READWRITE(numInputs);
        READWRITE(totalAmounts);
        READWRITE(totalFees);
    }

    std::vector<unsigned char> AsVector()
    {
        return ::AsVector(*this);
    }

    bool IsValid() const
    {
        return nVersion > VERSION_INVALID && 
               nVersion <= VERSION_LAST && 
               !systemID.IsNull();
    }

    static CCurrencyValueMap CalculateExportFee(const CCurrencyValueMap &fees, int numIn);
    CCurrencyValueMap CalculateExportFee() const;

    CCurrencyValueMap CalculateImportFee() const;
    
    UniValue ToUniValue() const;
};

class CCurrencyState
{
public:
    enum FLAGS {
        FLAG_VALID = 1,
        FLAG_FRACTIONAL = 2,
        FLAG_REFUNDING = 4
    };
    enum CONSTANTS {
        MIN_RESERVE_RATIO = 1000000,        // we will not start a chain with less than 1% reserve ratio in any single currency
        MAX_RESERVE_RATIO = 100000000,      // we will not start a chain with greater than 100% reserve ratio
        SHUTDOWN_RESERVE_RATIO = 500000,    // if we hit this reserve ratio in any currency, initiate chain shutdown
        CONVERSION_TX_SIZE_MIN = 1024,      // minimum size accounted for in a conversion transaction
        MAX_RESERVE_CURRENCIES = 10         // maximum number of reserve currencies that can underly a fractional reserve
    };

    uint32_t flags;         // currency flags (valid, reserve currency, etc.)

    std::vector<uint160> currencies;    // the ID in uin160 form (maps to CIdentityID) if each currency in the reserve
    std::vector<int32_t> weights;       // current, individual weights for all currencies to use in calculations
    std::vector<int64_t> reserves;      // total amount of reserves in each currency

    int64_t initialSupply;              // initial premine + pre-converted coins
    int64_t emitted;                    // emitted coins reduce the reserve ratio and are used to calculate current ratio
    CAmount supply;                     // current supply: total of initial, all emitted, and all purchased coins

    //std::vector<CAmount> Reserves; // reserve currencies amounts controlled by this fractional chain - only present for reserve currencies, currency IDs are in chain definition

    CCurrencyState() : flags(0), initialSupply(0), emitted(0), supply(0) {}

    CCurrencyState(const std::vector<uint160> &Currencies, 
                      const std::vector<int32_t> &Weights, 
                      const std::vector<int64_t> &Reserves, 
                      CAmount InitialSupply, 
                      CAmount Emitted, 
                      CAmount Supply, 
                      uint32_t Flags=FLAG_VALID) : 
        flags(Flags), supply(Supply), initialSupply(InitialSupply), emitted(Emitted), weights(Weights), reserves(Reserves)
    {}

    CCurrencyState(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CCurrencyState(const UniValue &uni);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(flags);
        READWRITE(currencies);        
        READWRITE(weights);        
        READWRITE(reserves);        
        READWRITE(VARINT(initialSupply));
        READWRITE(VARINT(emitted));
        READWRITE(VARINT(supply));
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    // this should be done no more than once to prepare a currency state to be moved to the next state
    // emission occurs for a block before any conversion or exchange and that impact on the currency state is calculated
    CCurrencyState &UpdateWithEmission(CAmount emitted);

    cpp_dec_float_50 GetReserveRatio(int32_t reserveIndex=0) const
    {
        return cpp_dec_float_50(std::to_string(weights[reserveIndex])) / cpp_dec_float_50("100000000");
    }

    template<typename cpp_dec_float_type>
    static bool to_int64(const cpp_dec_float_type &input, int64_t &outval)
    {
        std::stringstream ss(input.str(0));
        try
        {
            ss >> outval;
            return true;
        }
        catch(const std::exception& e)
        {
            return false;
        }
    }

    CAmount PriceInReserve(int32_t reserveIndex=0) const
    {
        if (reserveIndex >= reserves.size())
        {
            return 0;
        }
        if (!IsFractional())
        {
            return reserves[reserveIndex];
        }
        if (supply == 0 || weights[reserveIndex] == 0)
        {
            return weights[reserveIndex];
        }
        arith_uint256 Supply(supply);

        arith_uint256 Reserve(reserves[reserveIndex]);

        arith_uint256 Ratio(weights[reserveIndex]);

        arith_uint256 BigSatoshi(SATOSHIDEN);

        return ((Reserve * arith_uint256(SATOSHIDEN) * arith_uint256(SATOSHIDEN)) / (Supply * Ratio)).GetLow64();
    }

    // return the current price of the fractional reserve in the reserve currency in Satoshis
    cpp_dec_float_50 GetPriceInReserve(int32_t reserveIndex=0) const
    {
        return cpp_dec_float_50(PriceInReserve(reserveIndex));
    }

    std::vector<CAmount> PricesInReserve() const
    {
        std::vector<CAmount> retVal(currencies.size());
        for (int i = 0; i < currencies.size(); i++)
        {
            retVal[i] = PriceInReserve(i);
        }
        return retVal;
    }

    // This considers one currency at a time
    CAmount ConvertAmounts(CAmount inputReserve, CAmount inputFractional, CCurrencyState &newState, int32_t reserveIndex=0) const;

    // convert amounts for multi-reserve fractional reserve currencies
    // one entry in the vector for each currency in and one fractional input for each
    // currency expected as output
    std::vector<CAmount> ConvertAmounts(const std::vector<CAmount> &inputReserve, const std::vector<CAmount> &inputFractional, CCurrencyState &newState) const;

    CAmount CalculateConversionFee(CAmount inputAmount, bool convertToNative = false, int32_t reserveIndex=0) const;
    CAmount ReserveFeeToNative(CAmount inputAmount, CAmount outputAmount, int32_t reserveIndex=0) const;

    CAmount ReserveToNative(CAmount reserveAmount, int32_t reserveIndex) const
    {
        static arith_uint256 bigSatoshi(SATOSHIDEN);
        arith_uint256 bigAmount(reserveAmount);

        int64_t price = PriceInReserve(reserveIndex);
        bigAmount = price ? (bigAmount * bigSatoshi) / arith_uint256(price) : 0;

        return bigAmount.GetLow64();
    }

    CAmount ReserveToNative(const CCurrencyValueMap &reserveAmounts) const
    {
        CAmount nativeOut = 0;
        for (int i = 0; i < currencies.size(); i++)
        {
            auto it = reserveAmounts.valueMap.find(currencies[i]);
            if (it != reserveAmounts.valueMap.end())
            {
                nativeOut += ReserveToNative(it->second, i);
            }
        }
        return nativeOut;
    }

    CAmount ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<CAmount> &exchangeRates) const;
    static CAmount ReserveToNativeRaw(CAmount reserveAmount, CAmount exchangeRate);
    static CAmount ReserveToNativeRaw(const CCurrencyValueMap &reserveAmounts, const std::vector<uint160> &currencies, const std::vector<CAmount> &exchangeRates);

    CAmount NativeToReserve(CAmount nativeAmount, int32_t reserveIndex=0) const
    {
        static arith_uint256 bigSatoshi(SATOSHIDEN);
        arith_uint256 bigAmount(nativeAmount);
        arith_uint256 price = arith_uint256(PriceInReserve());
        return ((bigAmount * arith_uint256(price)) / bigSatoshi).GetLow64();
    }

    const CCurrencyValueMap &NativeToReserve(std::vector<CAmount> nativeAmount, int32_t reserveIndex=0) const;
    static CAmount NativeToReserveRaw(CAmount nativeAmount, CAmount exchangeRate);
    CCurrencyValueMap NativeToReserveRaw(const std::vector<CAmount> &, const std::vector<CAmount> &exchangeRates) const;

    UniValue ToUniValue() const;

    bool IsValid() const
    {
        return flags & FLAG_VALID;
    }

    bool IsFractional() const
    {
        return flags & FLAG_FRACTIONAL;
    }

    bool IsRefunding() const
    {
        return flags & FLAG_REFUNDING;
    }

    void SetRefunding(bool newState=true)
    {
        if (newState)
        {
            flags |= FLAG_REFUNDING;
        }
        else
        {
            flags &= ~FLAG_REFUNDING;
        }
    }

    std::map<uint160, int32_t> GetReserveMap() const
    {
        std::map<uint160, int32_t> retVal;
        for (int i = 0; i < currencies.size(); i++)
        {
            retVal[currencies[i]] = i;
        }
        return retVal;
    }
};

class CCoinbaseCurrencyState : public CCurrencyState
{
public:
    CAmount nativeFees;
    CAmount nativeConversionFees;
    std::vector<CAmount> reserveIn;         // reserve currency converted to native
    std::vector<CAmount> nativeIn;          // native currency converted to reserve
    std::vector<CAmount> reserveOut;        // output can have both normal and reserve output value, if non-0, this is spent by the required output transactions
    std::vector<CAmount> conversionPrice;   // calculated price in reserve for all conversions * 100000000
    std::vector<CAmount> fees;              // fee values in native (or reserve if specified) coins for reserve transaction fees for the block
    std::vector<CAmount> conversionFees;    // total of only conversion fees, which will accrue to the conversion transaction

    CCoinbaseCurrencyState() : nativeFees(0), nativeConversionFees(0) {}

    CCoinbaseCurrencyState(const CCurrencyState &CurrencyState,
                           CAmount NativeFees=0, CAmount NativeConversionFees=0,
                           const std::vector<CAmount> &ReserveIn=std::vector<CAmount>(),
                           const std::vector<CAmount> &NativeIn=std::vector<CAmount>(), 
                           const std::vector<CAmount> &ReserveOut=std::vector<CAmount>(), 
                           const std::vector<CAmount> &ConversionPrice=std::vector<CAmount>(), 
                           const std::vector<CAmount> &Fees=std::vector<CAmount>(), 
                           const std::vector<CAmount> &ConversionFees=std::vector<CAmount>()) : 
        CCurrencyState(CurrencyState), nativeFees(NativeFees), nativeConversionFees(NativeConversionFees),
        reserveIn(ReserveIn),
        nativeIn(NativeIn),
        reserveOut(ReserveOut),
        conversionPrice(ConversionPrice),
        fees(Fees),
        conversionFees(ConversionFees)        
    {
        if (!reserveIn.size()) reserveIn = std::vector<CAmount>(currencies.size());
        if (!nativeIn.size()) nativeIn = std::vector<CAmount>(currencies.size());
        if (!reserveOut.size()) reserveOut = std::vector<CAmount>(currencies.size());
        if (!conversionPrice.size()) conversionPrice = std::vector<CAmount>(currencies.size());
        if (!fees.size()) fees = std::vector<CAmount>(currencies.size());
        if (!conversionFees.size()) conversionFees = std::vector<CAmount>(currencies.size());
    }

    CCoinbaseCurrencyState(const UniValue &uni);

    CCoinbaseCurrencyState(const std::vector<unsigned char> asVector)
    {
        ::FromVector(asVector, *this);
    }

    CCoinbaseCurrencyState(const CTransaction &tx, int *pOutIdx=NULL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CCurrencyState *)this);
        READWRITE(nativeFees);
        READWRITE(nativeConversionFees);
        READWRITE(reserveIn);
        READWRITE(nativeIn);
        READWRITE(reserveOut);
        READWRITE(conversionPrice);
        READWRITE(fees);
        READWRITE(conversionFees);
    }

    std::vector<unsigned char> AsVector() const
    {
        return ::AsVector(*this);
    }

    UniValue ToUniValue() const;

    void ClearForNextBlock()
    {
        nativeFees = 0;
        nativeConversionFees = 0;
        reserveIn = std::vector<CAmount>(currencies.size());
        nativeIn = std::vector<CAmount>(currencies.size());
        reserveOut = std::vector<CAmount>(currencies.size());
        fees = std::vector<CAmount>(currencies.size());
        conversionFees = std::vector<CAmount>(currencies.size());
    }

    CCoinbaseCurrencyState MatchOrders(const std::vector<CReserveTransactionDescriptor> &orders, 
                                       std::vector<CReserveTransactionDescriptor> &reserveFills, 
                                       std::vector<CReserveTransactionDescriptor> &noFills, 
                                       std::vector<const CReserveTransactionDescriptor *> &expiredFillOrKills, 
                                       std::vector<const CReserveTransactionDescriptor *> &rejects, 
                                       std::vector<CAmount> &exchangeRates, 
                                       int32_t height, std::vector<CInputDescriptor> &conversionInputs, 
                                       int64_t maxSerializedSize=LONG_MAX, int64_t *ptotalSerializeSize=NULL, CMutableTransaction *pConversionTx=NULL,
                                       bool feesAsReserve=false) const;
    
    template <typename NUMBERVECTOR>
    NUMBERVECTOR AddVectors(const NUMBERVECTOR &a, const NUMBERVECTOR &b) const
    {
        const NUMBERVECTOR *shortVec, *longVec;
        int64_t count, max;
        if (a.size() <= b.size())
        {
            count = a.size();
            max = b.size();
            shortVec = &a;
            longVec = &b;
        }
        else
        {
            count = b.size();
            max = a.size();
            shortVec = &b;
            longVec = &a;
        }

        NUMBERVECTOR ret;
        ret.reserve(max);
        for (int i = 0; i < count; i++)
        {
            ret[i] = (*longVec)[i] + (*shortVec)[i];
        }
        for (int i = count; i < max; i++)
        {
            ret[i] = (*longVec)[i];
        }
        return ret;
    }
};

class CReserveInOuts
{
public:
    int64_t reserveIn;
    int64_t reserveOut;
    int64_t reserveOutConverted;
    int64_t nativeOutConverted;
    int64_t reserveConversionFees;
    CReserveInOuts() : reserveIn(0), reserveOut(0), reserveOutConverted(0), nativeOutConverted(0), reserveConversionFees(0) {}
    CReserveInOuts(int64_t ReserveIn, int64_t ReserveOut, int64_t ReserveOutConverted, int64_t NativeOutConverted, int64_t ReserveConversionFees) : 
                    reserveIn(ReserveIn), 
                    reserveOut(ReserveOut), 
                    reserveOutConverted(ReserveOutConverted), 
                    nativeOutConverted(NativeOutConverted), 
                    reserveConversionFees(ReserveConversionFees) {}
};

class CReserveTransactionDescriptor
{
public:
    enum {
        IS_VALID=1,                             // known to be valid
        IS_REJECT=2,                            // if set, tx is known to be invalid
        IS_RESERVE=4,                           // if set, this transaction affects reserves and/or price if mined
        IS_RESERVEEXCHANGE=8,                   // is this a reserve/exchange transaction?
        IS_LIMIT=0x10,                          // if reserve exchange, is it a limit order?
        IS_FILLORKILL=0x20,                     // If set, this can expire
        IS_FILLORKILLFAIL=0x40,                 // If set, this is an expired fill or kill in a valid tx
        IS_IMPORT=0x80,                         // If set, this is an expired fill or kill in a valid tx
        IS_EXPORT=0x100,                        // If set, this is an expired fill or kill in a valid tx
        IS_IDENTITY=0x200,                      // If set, this is an identity definition or update
        IS_IDENTITY_DEFINITION=0x400,           // If set, this is an identity definition
        IS_HIGH_FEE=0x800                       // If set, this may have "absurdly high fees"
    };

    const CTransaction *ptx;                    // pointer to the actual transaction if valid
    uint16_t flags;                             // indicates transaction state
    std::map<uint160, CReserveInOuts> currencies; // currency entries in this transaction
    int16_t numBuys = 0;                        // each limit conversion that is valid before a certain block should account for FILL_OR_KILL_FEE
    int16_t numSells = 0;
    int16_t numTransfers = 0;                   // number of transfers, each of which also requires a transfer fee
    CAmount nativeIn = 0;
    CAmount nativeOut = 0;
    CAmount nativeConversionFees = 0;           // non-zero only if there is a conversion
    std::vector<std::pair<int, CReserveExchange>> vRex; // index and rehydrated, validated reserve exchange outputs

    CReserveTransactionDescriptor() : 
        flags(0),
        ptx(NULL),
        numBuys(0),                             // each limit conversion that is valid before a certain block should account for FILL_OR_KILL_FEE
        numSells(0),
        numTransfers(0),
        nativeIn(0),
        nativeOut(0),
        nativeConversionFees(0) {}              // non-zero only if there is a conversion, stored vs. calculated to get exact number with each calculated seperately

    CReserveTransactionDescriptor(const CTransaction &tx, const CCoinsViewCache &view, int32_t nHeight);

    bool IsReject() const { return flags & IS_REJECT; }
    bool IsValid() const { return flags & IS_VALID && !IsReject(); }
    bool IsReserve() const { return IsValid() && flags & IS_RESERVE; }
    bool IsReserveExchange() const { return flags & IS_RESERVEEXCHANGE; }
    bool IsLimit() const { return flags & IS_LIMIT; }
    bool IsFillOrKill() const { return flags & IS_FILLORKILL; }
    bool IsMarket() const { return IsReserveExchange() && !IsLimit(); }
    bool IsFillOrKillFail() const { return flags & IS_FILLORKILLFAIL; }
    bool IsIdentity() const { return flags & IS_IDENTITY; }
    bool IsIdentityDefinition() const { return flags & IS_IDENTITY_DEFINITION; }
    bool IsHighFee() const { return flags & IS_HIGH_FEE; }

    static CAmount CalculateConversionFee(CAmount inputAmount);
    static CAmount CalculateAdditionalConversionFee(CAmount inputAmount);

    CAmount NativeFees() const
    {
        return nativeIn - nativeOut;                                // native out converted does not include conversion
    }

    CCurrencyValueMap ReserveFees() const
    {
        CCurrencyValueMap retFees;
        for (auto &one : currencies)
        {
            CAmount oneFee = one.second.reserveIn - one.second.reserveOut;
            if (oneFee)
            {
                retFees.valueMap[one.first] = oneFee;
            }
        }
        return retFees;
    }

    CAmount AllFeesAsNative(const CCurrencyState &currencyState) const;
    CAmount AllFeesAsNative(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates) const;
    CCurrencyValueMap AllFeesAsReserve(const CCurrencyState &currencyState, int defaultReserve=0) const;
    CCurrencyValueMap AllFeesAsReserve(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates, int defaultReserve=0) const;

    // does not check for errors
    void AddReserveInput(const uint160 &currency, CAmount value);
    void AddReserveOutput(const uint160 &currency, CAmount value);
    void AddReserveOutConverted(const uint160 &currency, CAmount value);
    void AddNativeOutConverted(const uint160 &currency, CAmount value);
    void AddReserveConversionFees(const uint160 &currency, CAmount value);

    CCurrencyValueMap ReserveInputMap() const;
    CCurrencyValueMap ReserveOutputMap() const;
    CCurrencyValueMap ReserveOutConvertedMap() const;
    CCurrencyValueMap NativeOutConvertedMap() const;
    CCurrencyValueMap ReserveConversionFeesMap() const;

    // returns vectors in same size and order as reserve currencies
    std::vector<CAmount> ReserveInputVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveOutputVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveOutConvertedVec(const CCurrencyState &cState) const;
    std::vector<CAmount> NativeOutConvertedVec(const CCurrencyState &cState) const;
    std::vector<CAmount> ReserveConversionFeesVec(const CCurrencyState &cState) const;

    void AddReserveOutput(const CTokenOutput &ro)
    {
        flags |= IS_RESERVE;
        if (!(flags & IS_IMPORT))
        {
            AddReserveOutput(ro.currencyID, ro.nValue);
        }
    }

    // is boolean, since it can fail, which would render the tx invalid
    void AddReserveExchange(const CReserveExchange &rex, int32_t outputIndex, int32_t nHeight);

    void AddReserveTransfer(CReserveTransfer &rt)
    {
        flags |= IS_RESERVE;
        if (!(flags & IS_IMPORT))
        {
            AddReserveOutput(rt.currencyID, rt.nValue + rt.nFees);
            numTransfers++;
        }
    }

    CMutableTransaction &AddConversionInOuts(CMutableTransaction &conversionTx, 
                                             std::vector<CInputDescriptor> &conversionInputs, 
                                             const CCurrencyValueMap &exchangeRates=CCurrencyValueMap(), 
                                             const CCurrencyState *pCurrencyState=nullptr) const;

    bool AddReserveTransferImportOutputs(const uint160 &currencySourceID, 
                                         const CCurrencyDefinition &importCurrencyDef, 
                                         const CCoinbaseCurrencyState &importCurrencyState,
                                         const std::vector<CBaseChainObject *> &exportObjects, 
                                         std::vector<CTxOut> &vOutputs,
                                         CCoinbaseCurrencyState *pNewCurrencyState=nullptr);
};

#endif // PBAAS_RESERVES_H
