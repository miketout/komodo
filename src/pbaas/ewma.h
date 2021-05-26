/********************************************************************
 * (C) 2020 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides support for exponentially weighted moving averages and standard deviations
 * efficiently calculated on a running basis.
 * 
 */
#ifndef EWMA_H
#define EWMA_H

#include "version.h"
#include "uint256.h"
#include <univalue.h>
#include <sstream>
#include "streams.h"
#include "boost/algorithm/string.hpp"
#include "arith_uint256.h"

class CEWMA
{
public:
    // all numbers are in satoshis
    enum
    {
        VERSION_INVALID = 0,
        VERSION_CURRENT = 1,
        VERSION_FIRST = 1,
        VERSION_LAST = 1,
        FLAGS_STARTED = 1,
        SATOSHIDEN = 100000000,
        DEFAULT_LAMBDA = 98000000
    };
    uint8_t nVersion;
    uint8_t flags;
    int64_t lambda;
    int64_t mean;
    arith_uint256 variance2;

    CEWMA() : nVersion(VERSION_CURRENT), flags(0), lambda(DEFAULT_LAMBDA), mean(0), variance2(0) {}

    CEWMA(int64_t Lambda, int64_t Mean, arith_uint256 Variance2, uint8_t Version=VERSION_CURRENT, uint8_t Flags=0) : 
        nVersion(Version), flags(Flags), lambda(Lambda), mean(Mean), variance2(Variance2) {}
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(flags);
        READWRITE(lambda);
        READWRITE(mean);
        uint256 variance2a;
        if (ser_action.ForRead())
        {
            READWRITE(variance2a);
            variance2 = UintToArith256(variance2a);
        }
        else
        {
            variance2a = ArithToUint256(variance2a);
            READWRITE(variance2a);
        }
    }

    UniValue ToUniValue() const
    {
        UniValue uni(UniValue::VOBJ);
        uni.pushKV("lambda", lambda);
        uni.pushKV("mean", mean);
        uni.pushKV("variance", StdDev());
    }

    void Clear()
    {
        flags &= ~FLAGS_STARTED;
        mean = 0;
        variance2 = 0;
    }

    CEWMA AddSample(int64_t nValue)
    {
        arith_uint256 bigValue(nValue);
        if (flags & FLAGS_STARTED)
        {
            arith_uint256 bigMean(mean);
            mean = ((bigMean * lambda) + (bigValue * arith_uint256(SATOSHIDEN - lambda)) / SATOSHIDEN).GetLow64();
            arith_uint256 variance = arith_uint256(nValue - mean);
            variance *= variance;
            variance2 = ((variance2 * lambda) + (variance * arith_uint256(SATOSHIDEN - lambda)) / SATOSHIDEN);
        }
        else
        {
            mean = nValue;
            variance2 = 0;
        }
    }

    int64_t Mean() const
    {
        return mean;
    }

    int64_t StdDev() const
    {
        // Newton-Rhapson square root
        if (!variance2)
        {
            return 0;
        }
        arith_uint256 x((variance2 >> 1) + 1);
        arith_uint256 y((x + (variance2 / x)) / 2);
        while (y < x)
        {
            x = y;
            y = (x + (variance2 / x)) / 2;
        }
        return x.GetLow64();
    }
};

#endif // EWMA_H
