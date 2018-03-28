// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);
double GetDifficulty(const CBlockIndex* blockindex, const CBlockIndex* blockindexpow, const CBlockIndex* blockindexpos)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = GetLastBlockIndex(pindexBest, false);
    }
    if (blockindexpow == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindexpow = GetLastBlockIndexPow(pindexBest, false);
    }
    if (blockindexpos == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindexpos = GetLastBlockIndexPos(pindexBest, false);
    }
    unsigned int nBlockBits = blockindex->nBits;
    unsigned int nBlockBitspow = blockindexpow->nBits;
    unsigned int nBlockBitspos = blockindexpos->nBits;
    nBlockBits = GetNextTargetRequired(blockindex,blockindex->IsProofOfStake());
    nBlockBitspow = GetNextTargetRequiredPow(blockindexpow,blockindexpow->IsProofOfWork());
    nBlockBitspos = GetNextTargetRequiredPos(blockindexpos,blockindexpos->IsProofOfStake());
    int nShift = (nBlockBits >> 24) & 0xff;
    int nShiftpow = (nBlockBitspow >> 24) & 0xff;
    int nShiftpos = (nBlockBitspos >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(nBlockBits & 0x00ffffff);
    double dDiffpow =
        (double)0x0000ffff / (double)(nBlockBitspow & 0x00ffffff);
    double dDiffpos =
        (double)0x0000ffff / (double)(nBlockBitspos & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }
    while (nShiftpow < 29)
    {
        dDiffpow *= 256.0;
        nShiftpow++;
    }
    while (nShiftpow > 29)
    {
        dDiffpow /= 256.0;
        nShiftpow--;
    }
    while (nShiftpos < 29)
    {
        dDiffpos *= 256.0;
        nShiftpos++;
    }
    while (nShiftpos > 29)
    {
        dDiffpos /= 256.0;
        nShiftpos--;
    }

    if(pindexBest->GetBlockTime() > nPowForceTimestamp + nPowForceTimestamp && blockindex->IsProofOfWork())          //  fulldiffbits /disabled/
       return dDiffpow;
       else if(pindexBest->GetBlockTime() > nPowForceTimestamp + nPowForceTimestamp && blockindex->IsProofOfStake()) //  fulldiffbits /disabled/
               return dDiffpos;
               else
                   return dDiff;
}

Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(Pair("proofhash", blockindex->IsProofOfStake()? blockindex->hashProofOfStake.GetHex() : blockindex->GetBlockHash().GetHex()));
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016"PRI64x, blockindex->nStakeModifier)));
    result.push_back(Pair("modifierchecksum", strprintf("%08x", blockindex->nStakeModifierChecksum)));
    Array txinfo;
    BOOST_FOREACH (const CTransaction& tx, block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            Object entry;

            entry.push_back(Pair("txid", tx.GetHash().GetHex()));
            TxToJSON(tx, 0, entry);

            txinfo.push_back(entry);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));
    result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));

    return result;
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}


Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    Object obj;
    if(pindexBest->GetBlockTime() > 1388949883 && pindexBest->GetBlockTime() < nPowForceTimestamp)
    {
    obj.push_back(Pair("proof-of-work",                             GetDifficulty()));
    obj.push_back(Pair("proof-of-stake",                            GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval",                          (int)nLastCoinStakeSearchInterval));
    }
    else
    {
    obj.push_back(Pair("proof - of - work",                         GetDifficulty()));
    obj.push_back(Pair("search-interval-powblock",                 (int)nLastCoinPowSearchInterval));
    obj.push_back(Pair("search-twointerval-powblock",              (int)nLastCoinPowFiveInterval));
    obj.push_back(Pair("search-full-result-powblock",              (int)nActualTimeIntervalXUXLpow));
    obj.push_back(Pair("pow-target-spacing-variable",              (int)nPowTargetSpacingVar));
    obj.push_back(Pair("UpperLower-pow",                           (int)powUpperLower));
    obj.push_back(Pair("XUpper-pow",                               (int)XUpperPow));
    obj.push_back(Pair("XLower-pow",                               (int)XLowerPow));
    obj.push_back(Pair("proof - of - stake",                        GetDifficulty(GetLastBlockIndexPos(pindexBest, true))));
    obj.push_back(Pair("search-interval-posblock",                 (int)nLastCoinPosSearchInterval));
    obj.push_back(Pair("search-twointerval-posblock",              (int)nLastCoinPosTwoInterval));
    obj.push_back(Pair("search-full-result-posblock",              (int)nActualTimeIntervalXUXLpos));
    obj.push_back(Pair("pos-target-spacing-variable",              (int)nPosTargetSpacingVar));
    obj.push_back(Pair("UpperLower-pos",                           (int)posUpperLower));
    obj.push_back(Pair("XUpper-pos",                               (int)XUpperPos));
    obj.push_back(Pair("XLower-pos",                               (int)XLowerPos));
    obj.push_back(Pair("search-interval-without pow block",        (int)nLastCoinWithoutPowSearchInterval));
    obj.push_back(Pair("search-interval-without pos block",        (int)nLastCoinWithoutPosSearchInterval));
    }
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.01");

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / CENT) * CENT;  // round to cent

    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->GetHash().GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <number> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-number.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = pblockindex->GetHash();

    pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

// ppcoin: get information of sync-checkpoint
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    Object result;
    CBlockIndex* pindexCheckpoint;

    result.push_back(Pair("synccheckpoint", Checkpoints::hashSyncCheckpoint.ToString().c_str()));
    pindexCheckpoint = mapBlockIndex[Checkpoints::hashSyncCheckpoint];
    result.push_back(Pair("height", pindexCheckpoint->nHeight));
    result.push_back(Pair("timestamp", DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));
    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}
