// Copyright (c) 2019 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERUS_PBAASRPC_H
#define VERUS_PBAASRPC_H

#include "amount.h"
#include "uint256.h"
#include "sync.h"
#include <stdint.h>
#include <map>
#include "pbaas/notarization.h"
#include "pbaas/reserves.h"

#include <boost/assign/list_of.hpp>

#include <univalue.h>

bool GetCurrencyDefinition(std::string &name, CCurrencyDefinition &chainDef);
bool GetCurrencyDefinition(uint160 chainID, CCurrencyDefinition &chainDef, int32_t *pDefHeight = NULL);
bool GetNotarizationData(uint160 chainID, uint32_t ecode, CChainNotarizationData &notarizationData, std::vector<std::pair<CTransaction, uint256>> *optionalTxOut = NULL);
bool GetChainTransfers(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, 
                            uint160 chainFilter = uint160(), int start=0, int end=0, uint32_t flags=CReserveTransfer::VALID);
bool GetUnspentChainTransfers(std::multimap<uint160, std::pair<CInputDescriptor, CReserveTransfer>> &inputDescriptors, uint160 chainFilter = uint160());
bool GetUnspentChainExports(uint160 chainID, std::multimap<uint160, std::pair<int, CInputDescriptor>> &exportOutputs);

UniValue getcurrency(const UniValue& params, bool fHelp);
UniValue getnotarizationdata(const UniValue& params, bool fHelp);
UniValue getcrossnotarization(const UniValue& params, bool fHelp);
UniValue definecurrency(const UniValue& params, bool fHelp);
UniValue addmergedblock(const UniValue& params, bool fHelp);

void RegisterPBaaSRPCCommands(CRPCTable &tableRPC);

#endif // VERUS_PBAASRPC_H