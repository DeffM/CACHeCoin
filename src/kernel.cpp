// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "kernel.h"
#include "db.h"

using namespace std;

extern int nStakeMaxAge;
extern int nPosTargetSpacing;
extern int nStakeTargetSpacing;

extern int64 nSynTimerStart;

extern map<uint256, uint256> mapProofOfStake;
extern map<COutPoint, std::string> mapPreVoutStakeAddress;

// Modifier interval: time to elapse before new modifier is computed
// Set to 6-hour for production network and 20-minute for test network
unsigned int nModifierInterval = MODIFIER_INTERVAL;

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints =
    boost::assign::map_list_of
    ( 0, 0x0e00670b )
    ;

static std::map<int64, unsigned int> mapProtocolSwitchingThresholds =
    boost::assign::map_list_of
    (int64(1587476876), 1)
    (int64(1592699510), 2) // Sun, 21 Jun 2020 00:31:50 GMT
    (int64(9999999999), 3)
    ;

unsigned int nAlreadyActive = 0;
bool ProtocolSwitchingThresholds(uint256 hash, unsigned int& nThresholds)
{
    nThresholds = 0;
    int64 nThresholdsTime = 0;
    CBlockIndex* pindex = pindexBest;
    for (map<int64, unsigned int>::iterator i = mapProtocolSwitchingThresholds.begin(); i != mapProtocolSwitchingThresholds.end(); ++i)
    {
        if ((*i).first > nThresholdsTime && pindex->GetBlockTime() > (*i).first)
        {
            bool fNotUse = false;
            if (((*i).second == 2 || (*i).second == 3) && (*i).second > nAlreadyActive)
            {
                fNotUse = true;
                for (map<COutPoint, std::string>::iterator mi = mapPreVoutStakeAddress.begin(); mi != mapPreVoutStakeAddress.end(); ++mi)
                {
                    if (((*mi).second == "CP7N2wZmkqKkowQsPfUfbJFuXYRBSUxZiG" && (*i).second == 2) ||
                        ((*mi).second == "CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" && (*i).second == 3))
                        nThresholdsTime = (*i).first;
                }
            }

            if (!fNotUse)
                nThresholdsTime = (*i).first;
        }
    }

    if (nThresholdsTime > 0)
    {
        nThresholds = mapProtocolSwitchingThresholds.find(nThresholdsTime)->second;
        nAlreadyActive = nThresholds;
    }

    return true;
}

int nProtocolSwitchingThresholds()
{
    uint256 hash = 0;
    unsigned int nThresholds = 0;
    if (ProtocolSwitchingThresholds(hash, nThresholds))
        nThresholds += 0;

    return nThresholds;
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64& nStakeModifier, int64& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64 GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert (nSection >= 0 && nSection < 64);
    return (nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64 GetStakeModifierSelectionInterval()
{
    if (fTestNet)
        return nStakeMinAge;
    int64 nSelectionInterval = 0;
    for (int nSection=0; nSection<64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(
    vector<pair<int64, uint256> >& vSortedByTimestamp,
    map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64 nSelectionIntervalStop, uint64 nStakeModifierPrev,
    const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*) 0;
    BOOST_FOREACH(const PAIRTYPE(int64, uint256)& item, vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        uint256 hashProof = pindex->IsProofOfStake()? pindex->hashProofOfStake : pindex->GetBlockHash();
        CDataStream ss(SER_GETHASH, 0);
        ss << hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
        else
        if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
    }
    if (fDebug && GetBoolArg("-printstakemodifier"))
        printf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64 nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: prev modifier=0x%016"PRI64x" time=%s\n", nStakeModifier, DateTimeStrFormat(nModifierTime).c_str());
    }
    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
        return true;

    // Sort candidate blocks by timestamp
    vector<pair<int64, uint256> > vSortedByTimestamp;
    if (pindexPrev->GetBlockTime() > nPowForceTimestamp)
        vSortedByTimestamp.reserve(64 * nModifierInterval / nPosTargetSpacing);
    else
        vSortedByTimestamp.reserve(64 * nModifierInterval / nStakeTargetSpacing);

    int64 nSelectionInterval = GetStakeModifierSelectionInterval();
    int64 nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64 nStakeModifierNew = 0;
    int64 nSelectionIntervalStop = nSelectionIntervalStart;
    map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound=0; nRound<min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(make_pair(pindex->GetBlockHash(), pindex));
        if (fDebug && GetBoolArg("-printstakemodifier"))
            printf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n",
                nRound, DateTimeStrFormat(nSelectionIntervalStop).c_str(), pindex->nHeight, pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if (fDebug && GetBoolArg("-printstakemodifier"))
    {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        BOOST_FOREACH(const PAIRTYPE(uint256, const CBlockIndex*)& item, mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake()? "S" : "W");
        }
        printf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: new modifier=0x%016"PRI64x" time=%s\n", nStakeModifierNew, DateTimeStrFormat(pindexPrev->GetBlockTime()).c_str());
    }

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64& nStakeModifier, int& nStakeModifierHeight, int64& nStakeModifierTime,
                            uint256 hash, bool& fWithoutReturnFalse, bool fPrintProofOfStake)
{
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");

    nStakeModifier = 0;
    bool fThresholds = false;
    fWithoutReturnFalse = false;
    unsigned int nThresholds = 0;
    int nCountingStakeModifierHeight = nBestHeight - 1;
    const CBlockIndex* pindexFrom = mapBlockIndex[hashBlockFrom];
    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    if (ProtocolSwitchingThresholds(hash, nThresholds) && nThresholds > 0)
        fThresholds = true;
    int64 nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();
    const CBlockIndex* pindex = pindexFrom;
    const CBlockIndex* pindexSearch = pindexBest;

    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)
    {
        nCountingStakeModifierHeight++;
        while (pindexSearch)
        {
            nCountingStakeModifierHeight--;
            if (pindexSearch && pindexSearch != pindex)
            {
                pindexSearch = pindexSearch->pprev;
            }
            if (pindexSearch && pindexSearch == pindex)
            {
                if (nCountingStakeModifierHeight == mapBlockIndex[hashBlockFrom]->nHeight)
                {
                    if (!pindexSearch->pnext)
                    {
                        if (fThresholds)
                            fWithoutReturnFalse = true;
                        return true;
                    }
                    pindexSearch = pindexSearch->pnext;
                    break;
                }
                else
                    return error("GetKernelStakeModifier() : block inverse mismatch %s at height %d from block %s",
                                 pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, hashBlockFrom.ToString().c_str());
            }
            if (pindexSearch == pindexGenesisBlock)
                return error("GetKernelStakeModifier() : reached genesis block %s at height %d from block %s",
                             pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, hashBlockFrom.ToString().c_str());
        }
        pindex = pindexSearch;

        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;

    return true;
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier:
//       (v0.3) scrambles computation to make it very difficult to precompute
//              future proof-of-stake at the time of the coin's confirmation
//       (v0.2) nBits (deprecated): encodes all past block timestamps
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(unsigned int nBits, uint256 uiBlockHash, unsigned int nTimeBlockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256 hash, bool fPrintProofOfStake, PosMiningStuff *miningStuff)
{
    if (nTimeTx < txPrev.nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");

    if (nTimeBlockFrom + nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash() : min age violation");

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64 nValueIn = txPrev.vout[prevout.n].nValue;

    // v0.3 protocol kernel hash weight starts from 0 at the 30-day min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    int64 nTimeWeight = min((int64)nTimeTx - txPrev.nTime, (int64)nStakeMaxAge) - nStakeMinAge;
    CBigNum bnCoinDayWeight = CBigNum(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64 nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64 nStakeModifierTime = 0;

    bool fWithoutReturnFalse = false;

    if (miningStuff)
    {
        nStakeModifier = miningStuff->nStakeModifier;
        nStakeModifierHeight = miningStuff->nStakeModifierHeight;
        nStakeModifierTime = miningStuff->nStakeModifierTime;
    }
    else
    {
        if ((!GetKernelStakeModifier(uiBlockHash, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, hash, fWithoutReturnFalse, fPrintProofOfStake)) || fWithoutReturnFalse)
            return false;
    }

    ss << nStakeModifier;
    ss << nTimeBlockFrom << nTxPrevOffset << txPrev.nTime << prevout.n << nTimeTx;
    uint256 hashProofOfStake = Hash(ss.begin(), ss.end());

    if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
        mapProofOfStake.insert(make_pair(hash, hashProofOfStake));

    if (fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016"PRI64x" at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[uiBlockHash]->nHeight,
            DateTimeStrFormat(mapBlockIndex[uiBlockHash]->GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : check protocol=%s modifier=0x%016"PRI64x" nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            "10.0",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n, nTimeTx,
            hashProofOfStake.ToString().c_str());
    }

    // Now check if proof-of-stake hash meets target protocol
    if (CBigNum(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay)
        return false;

    if (fDebug && !fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016"PRI64x" at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[uiBlockHash]->nHeight,
            DateTimeStrFormat(mapBlockIndex[uiBlockHash]->GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : pass protocol=%s modifier=0x%016"PRI64x" nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            "10.0",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n, nTimeTx,
            hashProofOfStake.ToString().c_str());
    }
    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256 hash, bool fSkippingChecksRelyingOnCheckPoints)
{
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    // First try finding the previous transaction in database
    CTxIndex txindex;
    CTransaction txPrev;
    uint256 uiBlockHash;
    if (!GetTransaction(txin.prevout.hash, txPrev, uiBlockHash, txindex, false))
    {
        return tx.DoS(1, error("CheckProofOfStake() : INFO: read txPrev failed"));  // previous transaction not in main chain, may occur during initial download
    }
    else
    if (uiBlockHash == 0)
        return fDebug? error("CheckProofOfStake() : read block failed") : false; // unable to read block of previous transaction

    const CBlockIndex* pindex = mapBlockIndex[uiBlockHash];

    // Verify signature
    if ((!fSkippingChecksRelyingOnCheckPoints) && !VerifySignature(txPrev, tx, 0, MANDATORY_SCRIPT_VERIFY_FLAGS, 0))
        return tx.DoS(100, error("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString().c_str()));

    if (!CheckStakeKernelHash(nBits, uiBlockHash, pindex->GetBlockTime(), txindex.pos.nTxPos - txindex.pos.nBlockPos, txPrev, txin.prevout, tx.nTime, hash, fDebug))
        return tx.DoS(1, error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx.GetHash().ToString().c_str(), hash.ToString().c_str())); // may occur during initial download or if behind on block chain sync

    pindex = pindexBest;
    int64 nRewardCoinYearNew = 0;
    const CTxOut &voutNew = txPrev.vout[txin.prevout.n];
    if (!voutNew.IsEmpty() && pindex)
    {
        txPrev.AnalysisProofOfStakeReward(pindex, voutNew, txin.prevout, nRewardCoinYearNew, false);
        if (GetBoolArg("-analysisproofofstakedebug", 0))
            printf(" 'CheckProofOfStake()' - Added Bitcoin Address %s - %s\n", voutNew.ToString().c_str(), txin.prevout.ToString().c_str());
    }

    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64 nTimeBlock, int64 nTimeTx)
{
    // v0.3 protocol
    return (nTimeBlock == nTimeTx);
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert (pindex->pprev || pindex->GetBlockHash() == hashGenesisBlock);
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    uint256 hashChecksum = Hash(ss.begin(), ss.end());
    hashChecksum >>= (256 - 32);
    return hashChecksum.Get64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    if (fTestNet) return true; // Testnet has no checkpoints
    if (mapStakeModifierCheckpoints.count(nHeight))
        return nStakeModifierChecksum == mapStakeModifierCheckpoints[nHeight];
    return true;
}
