/********************************************************************
 * (C) 2020 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This set of outputs and functions provides polls and voting outputs that can be
 * used to authorize transactions. For example, a VotingPoll output defines a poll,
 * which can be referenced by VotingVote outputs that are cast when they are spent.
 * Voting eligibility can be qualified by a small published list, an unpublished list 
 * in the form of a merkle mountain root, or a large list in the form of a merkle 
 * mountain root.
 * 
 * Identities can be verified by spending a VotingVote output and referring to a
 * poll. A VotingVote output may be an authorizing token sent by the poll defining 
 * identity, a spender generated one and spent by spender's/voter's presence on the 
 * small published list, or proof of presence on the unpublished list. One of these
 * is required in the VotingVote output when casting a vote.
 * 
 * A poll output may be spent, to one of N destinations, depending on the result of 
 * its finished poll. Polls may be considered finished if either a block passes, or
 * a condition, which is first number of votes, is satisfied. Votes may be 
 * duplicated on the chain, but are usually assumed to be counted as one per vote.
 */

#ifndef VOTING_H
#define VOTING_H

#include "pbaas/vdxf.h"
#include "pbaas/reserves.h"
#include "pbaas/identity.h"
#include "primitives/transaction.h"

class CTxDestination;

class CVotingBase : public CTokenOutput
{
public:
    enum {
        FLAGS_INVALID,
        AUTH_BYID = 1,                          // authorized by ID
        AUTH_BYVOTEOUTPUT = 2,                  // authorized by spending vote output (not implemented)
        AUTH_CURRENCY_HOLD = 4,                 // authorized by locking up a specific amount of currency when voting
        AUTH_CURRENCY_SPEND = 8,                // authorized by spending a minimum amount of currency when voting
        AUTH_MMRPROOF = 0x10,                   // authorized by proving spending ID presence in list with MMR proof
        AUTH_DOCUMENTHASH = 0x20,               // verify that the document hash is correct
        AUTH_DOCUMENTSIGNER = 0x40,             // verify that the document is signed by publisher for accuracy
        COMPLETION_ATBLOCK = 0x100,             // consider completion after block, regardless of number of votes
        COMPLETION_ATMINVOTERATIO = 0x200,      // consider complete if #votes is >= ratio
        COMPLETION_ATCHOICETHRESHOLD = 0x400,   // consider complete if single choice has >threshold ratio
        COMPLETION_ATMINVALUE = 0x800,          // consider complete if total vote spend is >min value
        COMPLETION_REUSABLE = 0x1000,           // poll can be used on other outputs as well
        COMPLETION_OUTPUTSUMMARY = 0x2000,      // summarize the output
    };
    uint32_t flags;                                                     // authorization and completion flags
    CVotingBase() : flags(FLAGS_INVALID), CTokenOutput() {}
    CVotingBase(uint32_t Flags, CCurrencyValueMap ReserveValues) : flags(Flags), CTokenOutput(ReserveValues) {}
};

// This defines a poll type and governing body. It is referenced in a vote or a voting spend as a txid and output #.
class CGovernance : public CVotingBase
{
public:
    CIdentityID creator;                                                // creator of this poll to ensure unique name
    uint160 vdxfID;                                                     // vdxf ID, which will be present in the ID
    uint160 voteCurrencyID;                                             // currency type used for voting
    CAmount voteCurrencyAmount;                                         // minimum currency required to vote
    std::vector<CIdentityID> authorizedIDs;                             // if not MMR proof, list of IDs that are authorized to vote
    uint256 authMMRRoot;                                                // if MMR proof, used to prove authorization of source ID
    uint32_t authorizedCount;                                           // how many voters authorized in this poll
    uint32_t voteRatio;                                                 // turnout % in Satoshis
    uint32_t winRatio;                                                  // when vote is complete by a win
    uint32_t voteCompletionBlock;                                       // when the vote ends by block
    CCurrencyValueMap voteCurrencyThreshold;                            // when the vote ends by total amount of currency voting
    CCurrencyValueMap votePayoutThreshold;                              // when voters are paid from accrued funds
    std::set<int32_t> options;                                          // valid voting options and IDs for sending cost output

    uint160 updateGovernance;                                           // index of the poll to use to update this poll, null == creator

    CGovernance(uint32_t Flags,
                const CIdentityID &creator,                        // ID of the creator of this
                const CCurrencyValueMap &ReserveValues,            // output on this poll
                uint256 documentHash,                              // hash of the vote description document
                const std::vector<uint160> &AuthorizedList,        // the IDs authorized for this vote
                const uint256 &AuthMMRRoot,                        // MMR root to prove ID in
                uint32_t authVoterCount,                           // total count of authorized voters for min-vote ratio completion
                const CCurrencyValueMap &MinVoteCurrency,          // minimum vote currency to prove when casting a vote
                uint32_t VoteRatio,                                // if turnout precent determines completion
                uint32_t WinRatio,                                 // if any count reaches this value, vote is complete
                uint32_t completionBlock,                          // block after which vote is complete
                const CCurrencyValueMap &currencyThreshold,        // threshold of currency when vote is considered complete
                const std::set<int32_t> &Options)                  // choices for voting, all others are considered invalid
                : CVotingBase(Flags, ReserveValues), options(Options)
    {
    }

    static std::string GovernanceKeyName()
    {
        return "vrsc::system.voting.governance";
    }
    static uint160 GovernanceKey()
    {
        static uint160 nameSpace;
        static uint160 governanceKey = CVDXF::GetDataKey(GovernanceKeyName(), nameSpace);
        return governanceKey;
    }
};

class CNullOutputCondition
{
public:
    CNullOutputCondition() {}
};
typedef std::variant<CNullOutputCondition, CIdentityID, uint256> CVotingOutputCondition;
class CVotingConditionList
{
public:
    enum {
        CONDITION_NONE = 0,             // no requirement on spend
        CONDITION_RECIPIENT = 1,        // output from this spend is sent to this recipient
        CONDITION_SCRIPTPUBKEY = 2,     // output from this spend is put under control of this recipient
    };
    std::map <int32_t, CVotingOutputCondition> conditions;
};

// this is a conditional spend and set of rules, based on the outcome of a vote
// Specific poll ID is the governance ID hashed with the txid and output of this
// transaction and output
class CVotingPoll : public CVotingBase
{
public:
    uint160 governanceID;               // this refers to a set of governance rules and authorized voters, under which voting is held
    bool summaryRequired;               // if true, summary on output required, only allowed on small, explicit lists on Verus or on PBaaS chains
    std::map <int32_t, CVotingOutputCondition> options; // options for conditional spend or modification are not allowed on all poll types

    CVotingPoll() {}

    static std::string CVotingPollKeyName()
    {
        return "vrsc::system.voting.poll";
    }

    static uint160 CVotingPollKey()
    {
        static uint160 nameSpace;
        static uint160 votingPollKey = CVDXF::GetDataKey(CVotingPollKeyName(), nameSpace);
        return votingPollKey;
    }
};

// this is a spend that locks up a certain amount of currency, and is spendable after the
// vote is complete.
class CVotingSpend : public CVotingBase
{
public:
    uint256 txId;               // transaction to explicitly identify what this vote is for
    int32_t voutNum;            // output on that tx for this vote
    std::map <int32_t, CVotingOutputCondition> options;

    CVotingSpend(uint32_t Flags, const CCurrencyValueMap &ReserveValues) : CVotingBase(Flags, ReserveValues) {}

    static std::string CVotingSpendKeyName()
    {
        return "vrsc::system.voting.spend";
    }
    static uint160 CVotingSpendKey()
    {
        static uint160 nameSpace;
        static uint160 votingSpendKey = CVDXF::GetDataKey(CVotingSpendKeyName(), nameSpace);
        return votingSpendKey;
    }
};

// this is a spend that locks up a certain amount of curency, and is spendable after the
// vote is complete.
class CVotingVote : public CVotingBase
{
public:
    uint256 txId;               // transaction to explicitly identify what this vote is for
    int32_t voutNum;            // output on that tx for this vote
    int32_t choice;             // choice that makes it spendable

    CVotingVote(uint32_t Flags, const CCurrencyValueMap &ReserveValues) : CVotingBase(Flags, ReserveValues) {}

    bool operator==(const CVotingVote &operand)
    {
        return (txId == operand.txId && 
                voutNum == operand.voutNum && 
                choice == operand.choice && 
                flags == operand.flags && 
                reserveValues == operand.reserveValues);
    }

    static std::string VotingVoteKeyName()
    {
        return "vrsc::system.voting.vote";
    }
    static uint160 VotingVoteKey()
    {
        static uint160 nameSpace;
        static uint160 votingVoteKey = CVDXF::GetDataKey(VotingVoteKeyName(), nameSpace);
        return votingVoteKey;
    }
};

// Spend of a poll, which finalizes it, may require a summary output on the spending transaction
class CVotingSummary : public CVotingBase
{
public:
    uint160 governanceID;                   // this refers to a set of governance rules and authorized voters, under which voting is held
    uint256 pollTxid;                       // the specific poll txid
    int32_t pollOutNum;                     // the specific poll tx vout
    std::map<int32_t, CAmount> totals;      // votes in the form of votes or currency counts for voting currency

    CVotingSummary(uint32_t Flags, const CCurrencyValueMap &ReserveValues) : CVotingBase(Flags, ReserveValues) {}

    static std::string VotingSummaryKeyName()
    {
        return "vrsc::system.voting.summary";
    }

    static uint160 VotingSummaryKey()
    {
        static uint160 nameSpace;
        static uint160 votingSummaryKey = CVDXF::GetDataKey(VotingSummaryKeyName(), nameSpace);
        return votingSummaryKey;
    }
};

// when this reaches a threshold, it pays out all participants and
// resets to zero
class CVotingPayment : public CVotingBase
{
public:
    uint160 governanceID;                   // this refers to a set of governance rules and authorized voters, under which voting is held
    std::map<CIdentityID, int32_t> voteCounts; // vote counts for all voters

    enum
    {
        PER_BLOCK_RATIO = 1000000
    };
    CVotingPayment() : CVotingBase() {}

    CVotingPayment(const std::vector<unsigned char> &asVector)
    {
        FromVector(asVector, *this);
    }

    CVotingPayment(uint32_t Flags, const CCurrencyValueMap &reserveOut) : CVotingBase(Flags, reserveOut) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CTokenOutput *)this);
    }

    // returns false if fails to get block, otherwise, CFeePool if present
    // invalid CFeePool if not
    static bool GetCoinbaseFeePool(CFeePool &feePool, uint32_t height=0);

    CFeePool OneFeeShare()
    {
        CFeePool retVal;
        for (auto &oneCur : reserveValues.valueMap)
        {
            CAmount share = CCurrencyDefinition::CalculateRatioOfValue(oneCur.second, PER_BLOCK_RATIO);
            if (share)
            {
                retVal.reserveValues.valueMap[oneCur.first] = share;
            }
        }
        return retVal;
    }

    void SetInvalid()
    {
        nVersion = VERSION_INVALID;
    }

    bool IsValid() const
    {
        return CTokenOutput::IsValid() && reserveValues.valueMap.size() == 1;
    }
};

#endif // VOTING_H
