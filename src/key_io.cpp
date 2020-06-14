// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <script/script.h>
#include <utilstrencodings.h>

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

#include "pbaas/identity.h"
#include "cc/CCinclude.h"
#include "boost/algorithm/string.hpp"

#include <assert.h>
#include <string.h>
#include <algorithm>

extern uint160 VERUS_CHAINID;
extern std::string VERUS_CHAINNAME;

CIdentityID VERUS_DEFAULTID;
bool VERUS_PRIVATECHANGE;
std::string VERUS_DEFAULT_ZADDR;

namespace
{
class DestinationEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const CKeyID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CPubKey& key) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        CKeyID id = key.GetID();
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CScriptID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CIdentityID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::IDENTITY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CQuantumID& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::QUANTUM_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const CNoDestination& no) const { return {}; }
};

class DestinationBytes : public boost::static_visitor<std::vector<unsigned char>>
{
public:
    DestinationBytes() {}

    std::vector<unsigned char> operator()(const CKeyID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CPubKey& key) const
    {
        return std::vector<unsigned char>(key.begin(), key.end());
    }

    std::vector<unsigned char> operator()(const CScriptID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CIdentityID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CQuantumID& id) const
    {
        return std::vector<unsigned char>(id.begin(), id.end());
    }

    std::vector<unsigned char> operator()(const CNoDestination& no) const { return {}; }
};

class DestinationID : public boost::static_visitor<uint160>
{
public:
    DestinationID() {}

    uint160 operator()(const CKeyID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CPubKey& key) const
    {
        return (uint160)key.GetID();
    }

    uint160 operator()(const CScriptID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CIdentityID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CQuantumID& id) const
    {
        return (uint160)id;
    }

    uint160 operator()(const CNoDestination& no) const { return CKeyID(); }
};

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params)
{
    std::vector<unsigned char> data;
    uint160 hash;
    if (DecodeBase58Check(str, data)) {
        // base58-encoded Bitcoin addresses.
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return CKeyID(hash);
        }

        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return CScriptID(hash);
        }

        const std::vector<unsigned char>& identity_prefix = params.Base58Prefix(CChainParams::IDENTITY_ADDRESS);
        if (data.size() == hash.size() + identity_prefix.size() && std::equal(identity_prefix.begin(), identity_prefix.end(), data.begin())) {
            std::copy(data.begin() + identity_prefix.size(), data.end(), hash.begin());
            return CIdentityID(hash);
        }

        const std::vector<unsigned char>& quantum_prefix = params.Base58Prefix(CChainParams::QUANTUM_ADDRESS);
        if (data.size() == hash.size() + quantum_prefix.size() && std::equal(quantum_prefix.begin(), quantum_prefix.end(), data.begin())) {
            std::copy(data.begin() + quantum_prefix.size(), data.end(), hash.begin());
            return CQuantumID(hash);
        }
    }
    else if (std::count(str.begin(), str.end(), '@') == 1)
    {
        uint160 parent;
        return CIdentityID(CIdentity::GetID(str, parent));
    }

    return CNoDestination();
}

class PaymentAddressEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    PaymentAddressEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutPaymentAddress& zaddr) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zaddr;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCPAYMENT_ADDRRESS);
        data.insert(data.end(), ss.begin(), ss.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const libzcash::SaplingPaymentAddress& zaddr) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zaddr;
        // ConvertBits requires unsigned char, but CDataStream uses char
        std::vector<unsigned char> seraddr(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        // See calculation comment below
        data.reserve((seraddr.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, seraddr.begin(), seraddr.end());
        return bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_PAYMENT_ADDRESS), data);
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

class ViewingKeyEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    ViewingKeyEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutViewingKey& vk) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << vk;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCVIEWING_KEY);
        data.insert(data.end(), ss.begin(), ss.end());
        std::string ret = EncodeBase58Check(data);
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::SaplingIncomingViewingKey& vk) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << vk;
        std::vector<unsigned char> serkey(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, serkey.begin(), serkey.end());
        std::string ret = bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_INCOMING_VIEWING_KEY), data);
        memory_cleanse(serkey.data(), serkey.size());
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

class SpendingKeyEncoder : public boost::static_visitor<std::string>
{
private:
    const CChainParams& m_params;

public:
    SpendingKeyEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const libzcash::SproutSpendingKey& zkey) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zkey;
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::ZCSPENDING_KEY);
        data.insert(data.end(), ss.begin(), ss.end());
        std::string ret = EncodeBase58Check(data);
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::SaplingExtendedSpendingKey& zkey) const
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << zkey;
        // ConvertBits requires unsigned char, but CDataStream uses char
        std::vector<unsigned char> serkey(ss.begin(), ss.end());
        std::vector<unsigned char> data;
        // See calculation comment below
        data.reserve((serkey.size() * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, serkey.begin(), serkey.end());
        std::string ret = bech32::Encode(m_params.Bech32HRP(CChainParams::SAPLING_EXTENDED_SPEND_KEY), data);
        memory_cleanse(serkey.data(), serkey.size());
        memory_cleanse(data.data(), data.size());
        return ret;
    }

    std::string operator()(const libzcash::InvalidEncoding& no) const { return {}; }
};

// Sizes of SaplingPaymentAddress and SaplingSpendingKey after
// ConvertBits<8, 5, true>(). The calculations below take the
// regular serialized size in bytes, convert to bits, and then
// perform ceiling division to get the number of 5-bit clusters.
const size_t ConvertedSaplingPaymentAddressSize = ((32 + 11) * 8 + 4) / 5;
const size_t ConvertedSaplingExtendedSpendingKeySize = (ZIP32_XSK_SIZE * 8 + 4) / 5;
const size_t ConvertedSaplingIncomingViewingKeySize = (32 * 8 + 4) / 5;
} // namespace

CKey DecodeSecret(const std::string& str)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& privkey_prefix = Params().Base58Prefix(CChainParams::SECRET_KEY);
        if ((data.size() == 32 + privkey_prefix.size() || (data.size() == 33 + privkey_prefix.size() && data.back() == 1)) &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            bool compressed = data.size() == 33 + privkey_prefix.size();
            key.Set(data.begin() + privkey_prefix.size(), data.begin() + privkey_prefix.size() + 32, compressed);
        }
    }
    memory_cleanse(data.data(), data.size());
    return key;
}

std::string EncodeSecret(const CKey& key)
{
    assert(key.IsValid());
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    if (key.IsCompressed()) {
        data.push_back(1);
    }
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str)
{
    CExtKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& prefix = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

std::string EncodeDestination(const CTxDestination& dest)
{
    return boost::apply_visitor(DestinationEncoder(Params()), dest);
}

std::vector<unsigned char> GetDestinationBytes(const CTxDestination& dest)
{
    return boost::apply_visitor(DestinationBytes(), dest);
}

uint160 GetDestinationID(const CTxDestination dest)
{
    return boost::apply_visitor(DestinationID(), dest);
}

CTxDestination DecodeDestination(const std::string& str)
{
    return DecodeDestination(str, Params());
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    return IsValidDestination(DecodeDestination(str, params));
}

bool IsValidDestinationString(const std::string& str)
{
    return IsValidDestinationString(str, Params());
}

std::string EncodePaymentAddress(const libzcash::PaymentAddress& zaddr)
{
    return boost::apply_visitor(PaymentAddressEncoder(Params()), zaddr);
}

libzcash::PaymentAddress DecodePaymentAddress(const std::string& str)
{
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& zaddr_prefix = Params().Base58Prefix(CChainParams::ZCPAYMENT_ADDRRESS);
        if ((data.size() == libzcash::SerializedSproutPaymentAddressSize + zaddr_prefix.size()) &&
            std::equal(zaddr_prefix.begin(), zaddr_prefix.end(), data.begin())) {
            CSerializeData serialized(data.begin() + zaddr_prefix.size(), data.end());
            CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SproutPaymentAddress ret;
            ss >> ret;
            return ret;
        }
    }
    data.clear();
    auto bech = bech32::Decode(str);
    if (bech.first == Params().Bech32HRP(CChainParams::SAPLING_PAYMENT_ADDRESS) &&
        bech.second.size() == ConvertedSaplingPaymentAddressSize) {
        // Bech32 decoding
        data.reserve((bech.second.size() * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin(), bech.second.end())) {
            CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SaplingPaymentAddress ret;
            ss >> ret;
            return ret;
        }
    }
    return libzcash::InvalidEncoding();
}

bool IsValidPaymentAddressString(const std::string& str, uint32_t consensusBranchId) {
    return IsValidPaymentAddress(DecodePaymentAddress(str), consensusBranchId);
}

std::string EncodeViewingKey(const libzcash::ViewingKey& vk)
{
    return boost::apply_visitor(ViewingKeyEncoder(Params()), vk);
}

libzcash::ViewingKey DecodeViewingKey(const std::string& str)
{
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& vk_prefix = Params().Base58Prefix(CChainParams::ZCVIEWING_KEY);
        if ((data.size() == libzcash::SerializedSproutViewingKeySize + vk_prefix.size()) &&
            std::equal(vk_prefix.begin(), vk_prefix.end(), data.begin())) {
            CSerializeData serialized(data.begin() + vk_prefix.size(), data.end());
            CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SproutViewingKey ret;
            ss >> ret;
            memory_cleanse(serialized.data(), serialized.size());
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }
    data.clear();
    auto bech = bech32::Decode(str);
    if(bech.first == Params().Bech32HRP(CChainParams::SAPLING_INCOMING_VIEWING_KEY) &&
       bech.second.size() == ConvertedSaplingIncomingViewingKeySize) {
        // Bech32 decoding
        data.reserve((bech.second.size() * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin(), bech.second.end())) {
            CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SaplingIncomingViewingKey ret;
            ss >> ret;
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }
    return libzcash::InvalidEncoding();
}

std::string EncodeSpendingKey(const libzcash::SpendingKey& zkey)
{
    return boost::apply_visitor(SpendingKeyEncoder(Params()), zkey);
}

libzcash::SpendingKey DecodeSpendingKey(const std::string& str)
{
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data)) {
        const std::vector<unsigned char>& zkey_prefix = Params().Base58Prefix(CChainParams::ZCSPENDING_KEY);
        if ((data.size() == libzcash::SerializedSproutSpendingKeySize + zkey_prefix.size()) &&
            std::equal(zkey_prefix.begin(), zkey_prefix.end(), data.begin())) {
            CSerializeData serialized(data.begin() + zkey_prefix.size(), data.end());
            CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SproutSpendingKey ret;
            ss >> ret;
            memory_cleanse(serialized.data(), serialized.size());
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }
    data.clear();
    auto bech = bech32::Decode(str);
    if (bech.first == Params().Bech32HRP(CChainParams::SAPLING_EXTENDED_SPEND_KEY) &&
        bech.second.size() == ConvertedSaplingExtendedSpendingKeySize) {
        // Bech32 decoding
        data.reserve((bech.second.size() * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, bech.second.begin(), bech.second.end())) {
            CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
            libzcash::SaplingExtendedSpendingKey ret;
            ss >> ret;
            memory_cleanse(data.data(), data.size());
            return ret;
        }
    }
    memory_cleanse(data.data(), data.size());
    return libzcash::InvalidEncoding();
}

uint160 CCrossChainRPCData::GetConditionID(uint160 cid, int32_t condition)
{
    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

uint160 CCrossChainRPCData::GetConditionID(std::string name, int32_t condition)
{
    uint160 parent;
    uint160 cid = CIdentity::GetID(name, parent);

    CHashWriter hw(SER_GETHASH, PROTOCOL_VERSION);
    hw << condition;
    hw << cid;
    uint256 chainHash = hw.GetHash();
    return Hash160(chainHash.begin(), chainHash.end());
}

std::string TrimLeading(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = 0; removeSpaces < nameCopy.size(); removeSpaces++)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    if (removeSpaces)
    {
        nameCopy.erase(nameCopy.begin(), nameCopy.begin() + removeSpaces);
    }
    return nameCopy;
}

std::string TrimTrailing(const std::string &Name, unsigned char ch)
{
    std::string nameCopy = Name;
    int removeSpaces;
    for (removeSpaces = nameCopy.size() - 1; removeSpaces >= 0; removeSpaces--)
    {
        if (nameCopy[removeSpaces] != ch)
        {
            break;
        }
    }
    nameCopy.resize(nameCopy.size() - ((nameCopy.size() - 1) - removeSpaces));
    return nameCopy;
}

std::string TrimSpaces(const std::string &Name)
{
    return TrimTrailing(TrimLeading(Name, ' '), ' ');
}

// this will add the current Verus chain name to subnames if it is not present
// on both id and chain names
std::vector<std::string> ParseSubNames(const std::string &Name, std::string &ChainOut, bool displayfilter, bool addVerus)
{
    std::string nameCopy = Name;
    std::string invalidChars = "\\/:*?\"<>|";
    if (displayfilter)
    {
        invalidChars += "\n\t\r\b\t\v\f\x1B";
    }
    for (int i = 0; i < nameCopy.size(); i++)
    {
        if (invalidChars.find(nameCopy[i]) != std::string::npos)
        {
            return std::vector<std::string>();
        }
    }

    std::vector<std::string> retNames;
    boost::split(retNames, nameCopy, boost::is_any_of("@"));
    if (!retNames.size() || retNames.size() > 2)
    {
        return std::vector<std::string>();
    }

    bool explicitChain = false;
    if (retNames.size() == 2)
    {
        ChainOut = retNames[1];
        explicitChain = true;
    }    

    nameCopy = retNames[0];
    boost::split(retNames, nameCopy, boost::is_any_of("."));

    int numRetNames = retNames.size();

    if (addVerus)
    {
        if (explicitChain)
        {
            std::vector<std::string> chainOutNames;
            boost::split(chainOutNames, ChainOut, boost::is_any_of("."));
            if (boost::to_lower_copy(chainOutNames.back()) != boost::to_lower_copy(VERUS_CHAINNAME))
            {
                chainOutNames.push_back(VERUS_CHAINNAME);
            }
        }
        if (boost::to_lower_copy(retNames.back()) != boost::to_lower_copy(VERUS_CHAINNAME))
        {
            retNames.push_back(VERUS_CHAINNAME);
        }
    }

    for (int i = 0; i < retNames.size(); i++)
    {
        if (retNames[i].size() > KOMODO_ASSETCHAIN_MAXLEN - 1)
        {
            retNames[i] = std::string(retNames[i], 0, (KOMODO_ASSETCHAIN_MAXLEN - 1));
        }
        // spaces are allowed, but no sub-name can have leading or trailing spaces
        if (!retNames[i].size() || retNames[i] != TrimTrailing(TrimLeading(retNames[i], ' '), ' '))
        {
            return std::vector<std::string>();
        }
    }

    // if no explicit chain is specified, default to chain of the ID
    if (!explicitChain && retNames.size())
    {
        for (int i = 1; i < retNames.size(); i++)
        {
            if (ChainOut.size())
            {
                ChainOut = ChainOut + ".";
            }
            ChainOut = ChainOut + retNames[i];
        }
    }

    return retNames;
}

// takes a multipart name, either complete or partially processed with a Parent hash,
// hash its parent names into a parent ID and return the parent hash and cleaned, single name
std::string CleanName(const std::string &Name, uint160 &Parent, bool displayfilter)
{
    std::string chainName;
    std::vector<std::string> subNames = ParseSubNames(Name, chainName);

    if (!subNames.size())
    {
        return "";
    }

    if (!Parent.IsNull() &&
        boost::to_lower_copy(subNames.back()) == boost::to_lower_copy(VERUS_CHAINNAME))
    {
        subNames.pop_back();
    }

    for (int i = subNames.size() - 1; i > 0; i--)
    {
        std::string parentNameStr = boost::algorithm::to_lower_copy(subNames[i]);
        const char *parentName = parentNameStr.c_str();
        uint256 idHash;

        if (Parent.IsNull())
        {
            idHash = Hash(parentName, parentName + parentNameStr.size());
        }
        else
        {
            idHash = Hash(parentName, parentName + strlen(parentName));
            idHash = Hash(Parent.begin(), Parent.end(), idHash.begin(), idHash.end());
        }
        Parent = Hash160(idHash.begin(), idHash.end());
        //printf("uint160 for parent %s: %s\n", parentName, Parent.GetHex().c_str());
    }
    return subNames[0];
}

CNameReservation::CNameReservation(const CTransaction &tx, int *pOutNum)
{
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(tx.vout[i].scriptPubKey, p))
        {
            if (p.evalCode == EVAL_IDENTITY_RESERVATION)
            {
                FromVector(p.vData[0], *this);
                return;
            }
        }
    }
}

CIdentity::CIdentity(const CScript &scriptPubKey)
{
    COptCCParams p;
    if (IsPayToCryptoCondition(scriptPubKey, p) && p.IsValid() && p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size())
    {
        *this = CIdentity(p.vData[0]);
    }
}

CIdentityID CIdentity::GetID(const std::string &Name, uint160 &parent)
{
    std::string cleanName = CleanName(Name, parent);

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());
    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID(const std::string &Name) const
{
    uint160 parent;
    std::string cleanName = CleanName(Name, parent);

    std::string subName = boost::algorithm::to_lower_copy(cleanName);
    const char *idName = subName.c_str();
    //printf("hashing: %s, %s\n", idName, parent.GetHex().c_str());

    uint256 idHash;
    if (parent.IsNull())
    {
        idHash = Hash(idName, idName + strlen(idName));
    }
    else
    {
        idHash = Hash(idName, idName + strlen(idName));
        idHash = Hash(parent.begin(), parent.end(), idHash.begin(), idHash.end());

    }
    return Hash160(idHash.begin(), idHash.end());
}

CIdentityID CIdentity::GetID() const
{
    uint160 Parent = parent;
    return GetID(name, Parent);
}

uint160 CCrossChainRPCData::GetID(std::string name)
{
    uint160 parent;
    //printf("uint160 for name %s: %s\n", name.c_str(), CIdentity::GetID(name, parent).GetHex().c_str());
    return CIdentity::GetID(name, parent);
}

CScript CIdentity::TransparentOutput() const
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({CTxDestination(CIdentityID(GetID()))}), 1);
    return MakeMofNCCScript(ccObj);
}

CScript CIdentity::TransparentOutput(const CIdentityID &destinationID)
{
    CConditionObj<CIdentity> ccObj = CConditionObj<CIdentity>(0, std::vector<CTxDestination>({destinationID}), 1);
    return MakeMofNCCScript(ccObj);
}

CScript CIdentity::IdentityUpdateOutputScript() const
{
    CScript ret;

    if (!IsValid())
    {
        return ret;
    }

    std::vector<CTxDestination> dests1({CTxDestination(CIdentityID(GetID()))});
    CConditionObj<CIdentity> primary(EVAL_IDENTITY_PRIMARY, dests1, 1, this);
    std::vector<CTxDestination> dests2({CTxDestination(CIdentityID(revocationAuthority))});
    CConditionObj<CIdentity> revocation(EVAL_IDENTITY_REVOKE, dests2, 1);
    std::vector<CTxDestination> dests3({CTxDestination(CIdentityID(recoveryAuthority))});
    CConditionObj<CIdentity> recovery(EVAL_IDENTITY_RECOVER, dests3, 1);

    std::vector<CTxDestination> indexDests({CTxDestination(CKeyID(CCrossChainRPCData::GetConditionID(GetID(), EVAL_IDENTITY_PRIMARY))),
                                            IsRevoked() ? CTxDestination(CIdentityID(recoveryAuthority)) : CTxDestination(CIdentityID(revocationAuthority)),
                                            primaryAddresses.size() ? primaryAddresses[0] : CKeyID()});

    ret = MakeMofNCCScript(1, primary, revocation, recovery, &indexDests);
    return ret;
}

