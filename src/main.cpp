// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include "kernel.h"
#include "scrypt_mine.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#define POWFIX_DATE 1401530000

using namespace std;
using namespace boost;

//
// Global state
//
const int SCRYPT_SCRATCHPAD_SIZE = 131072 + 63;

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;
uint256 hashGenesisBlock = hashGenesisBlockOfficial;
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);
static CBigNum bnProofOfStakeLimit(~uint256(0) >> 24);
static CBigNum bnProofOfStakeHardLimit(~uint256(0) >> 30);
static CBigNum bnInitialHashTarget(~uint256(0) >> 20);
unsigned int nStakeMinAge = 60 * 60 * 24 * 7; // minimum age for coin age
unsigned int nStakeMaxAge = 60 * 60 * 24 * 30; // stake age of full weight
unsigned int nStakeTargetSpacing = 1 * 60 * 15; // DIFF: 15-minute block spacing
unsigned int nPowTargetSpacing = 1 * 60 * 15; // DIFF: 15-minute block spacing
unsigned int nPosTargetSpacing = 1 * 60 * 10; // DIFF: 10-minute block spacing
unsigned int NTest = 176500;
int64 nSetMetFull = 0;
int64 nSpamHashControl = 30; // % from (nPos)nPowTargetSpacing
int64 nChainStartTime = 1388949883;
int64 nNewTimeBlock = 0;
int64 nUnixCachChainTime = 0;
int64 PowPindexPrevTime = 0;
int64 PosPindexPrevTime = 0;
int64 PosPindexPrevPrevTime = 0;
int64 PosPindexPrevPrevPrevTime = 0;
int64 PosPindexPrevPrevPrevPrevTime = 0;
int64 nLastCoinPowSearchInterval = 0;
int64 nLastCoinPowFiveInterval = 0;
int64 nLastCoinWithoutPowSearchInterval = 0;
int64 nLastCoinPosSearchInterval = 0;
int64 nLastCoinPosSearchIntervalPrev = 0;
int64 nLastCoinPosSearchIntervalPrevPrev = 0;
int64 nLastCoinPosTwoInterval = 0;
int64 nLastCoinWithoutPosSearchInterval = 0;
double nActualTimeIntervalXUXLpow = 0;
double nActualTimeIntervalXUXLpos = 0;
double nPowTargetSpacingVar = 0;
double nPosTargetSpacingVar = 0;
double powUpperLower = 0;
double posUpperLower = 0;
double XUpperPow = 0;
double XLowerPow = 0;
double XUpperPos = 0;
double XLowerPos = 0;
double study = 0;
double studys = 0;
int nCoinbaseMaturity = 500;
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
int64 nBestHeightTime = 0;   // WM - Keep track of timestamp of block at best height.
uint256 nBestChainTrust = 0;
uint256 nBestInvalidTrust = 0;
CBigNum bnBestChainTrust = 0;
CBigNum bnBestInvalidTrust = 0;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
int64 nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fStoreTxMemory = false;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;
map<uint256, uint256> mapProofOfStake;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "'CACHE'Project Signed Message:\n";

double dHashesPerSec = 0;
int64 nHPSTimerStart = 0;
uint256 hashSingleStakeBlock;

// Settings
int64 nTransactionFee = MIN_TX_FEE;
bool fStakeUsePooledKeys = false;

// HardForkControlFunction
int64 nHardForkControlAddressStartTime = 9999999999;
std::string WatchOnlyAddress = "";
std::string HardForkControlAddress = "";
std::string ScriptPubKeyHardForkOP_CHECKSIG = "";
std::string ScriptPubKeyAddressOP_CHECKSIG = "";
std::string ScriptPubKeyHardForkOP_HASH160 = "";
std::string ScriptPubKeyAddressOP_HASH160 = "";
int64 nWatchOnlyAddressCalc = 0;
bool IsWatchOnlyAddressVtx = false;
bool IsWatchOnlyAddressTx = false;
int  nHardForkOneValue = 15 * COIN;
int  nHardForkTwoValue = 10 * COIN;
int  nHardForkThreeValue = 5 * COIN;
bool fHardForkOne = false;
bool fHardForkTwo = false;
bool fHardForkThree = false;





//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }
    CValidationState state;
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    {
        pwallet->AddToWalletWatchOnlyAddress(state, tx, pblock, fUpdate);
    }
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}





//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    printf("stored orphan tx %s (mapsz %"PRIszu")\n", hash.ToString().substr(0,10).c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}





//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::IsStandardCach(string& strReason) const
{
    if (nVersion > CTransaction::CURRENT_VERSION)
    {
        strReason = "version";
        return false;
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (txin.scriptSig.size() > 1650)
        {
            strReason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly())
        {
            strReason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes())
        {
            strReason = "txin-scriptsig-not-canonicalpushes";
            return false;
        }
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (!::IsStandardCach(txout.scriptPubKey, whichType))
        {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else
        {
            if (txout.nValue == 0)
            {
                strReason = "txout-value=0";
                return false;
            }
            if (!txout.scriptPubKey.HasCanonicalPushes())
            {
                strReason = "txout-scriptsig-not-canonicalpushes";
                return false;
            }
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1)
    {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(const MapPrevTx& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    if (!IsCoinBase())
    {
        // Coinbase scriptsigs are never executed, so there is 
        //    no sense in calculation of sigops.
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            nSigOps += txin.scriptSig.GetSigOpCount(false);
        }
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    const CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}

bool CTransaction::HardForkControl(CValidationState &state, const MapPrevTx& mapInputs) const
{
    CScript scriptWatchOnlyAddress;
    scriptWatchOnlyAddress.SetDestination(CBitcoinAddress(WatchOnlyAddress).Get());

    bool fIn = false;
    bool fOut = false;
    bool fInOut = false;
    int64 nFee = 0.01 * COIN;
    if (true)
    {
        IsWatchOnlyAddressTx = false;
        int64 nCreditWatchAddress = 0;
        for (unsigned int i = 0; i < vout.size(); i++)
        {
             CTxDestination address;
             const CTxOut &txout = vout[i];
             if (ExtractDestination(txout.scriptPubKey, address))
              {
                 if (CBitcoinAddress(address).ToString() == WatchOnlyAddress)
                 {
                     fIn = true;
                     fOut = false;
                     fInOut = true;
                     IsWatchOnlyAddressTx = true;
                     nCreditWatchAddress += txout.nValue;
                     printf(" 'Tx' - Input transaction to IsWatchOnlyAddress %s\n", txout.ToString().c_str());
                 }
                    else if (CBitcoinAddress(address).ToString() == HardForkControlAddress)
                    {
                             if (fHardForkOne && pindexBest->GetBlockTime() > nHardForkControlAddressStartTime)
                                 return DoS(10, error(" 'Tx' -  Attempt to send transaction to HardForkControlAddress"));
                             printf(" 'Tx' - Input transaction to HardForkControlAddress %s\n", txout.ToString().c_str());
                    }
              }
        }

        int64 nDebitWatchAddress = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
             CTxDB txdb;
             CTransaction prev;
             COutPoint prevout = vin[i].prevout;
             if(txdb.ReadDiskTx(prevout.hash, prev))
                if (prevout.n < prev.vout.size())
                {
                    CTxDestination address;
                    const CTxOut &vout = prev.vout[prevout.n];
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        if (CBitcoinAddress(address).ToString() == WatchOnlyAddress && fInOut)
                        {
                            fIn = false;
                            fOut = false;
                            fInOut = true;
                            nDebitWatchAddress -= vout.nValue;
                            printf(" 'Tx' - Output transaction from IsWatchOnlyAddress(in its address) %s\n", vout.ToString().c_str());
                        }
                            else if (CBitcoinAddress(address).ToString() == WatchOnlyAddress && !fInOut)
                            {
                                     fIn = false;
                                     fOut = true;
                                     fInOut = false;
                                     IsWatchOnlyAddressTx = true;
                                     nDebitWatchAddress -= vout.nValue;
                                     printf(" 'Tx' - Output transaction from IsWatchOnlyAddress(to a different address) %s\n", vout.ToString().c_str());
                            }
                    }
                }
        }

        for (unsigned int i = 0; i < vout.size(); i++)
        {
             CTxDestination address;
             const CTxOut &txout = vout[i];
             if (ExtractDestination(txout.scriptPubKey, address))
             {
                 if (!fIn && fOut && !fInOut)
                 {
                     nDebitWatchAddress = 0;
                     nDebitWatchAddress -= txout.nValue;
                     printf(" 'Tx' - Output transaction from IsWatchOnlyAddress(to a different address(in)) %s\n", txout.ToString().c_str());
                 }
             }
        }
        nWatchOnlyAddressCalc = 0;

        if (!IsCoinBase() || !IsCoinStake())
        {
            if (fIn && !fOut && fInOut)
            {
                nWatchOnlyAddressCalc = nCreditWatchAddress;
            }
            if (!fIn && fOut && !fInOut)
            {
                nWatchOnlyAddressCalc = nDebitWatchAddress - nFee;
            }
            if (!fIn && !fOut && fInOut)
            {
                nWatchOnlyAddressCalc -= nFee;
            }
        }
    }
    return true;
}

int64 CTransaction::GetMinFee(unsigned int nBlockSize, bool fAllowFree,
                              enum GetMinFee_mode mode, unsigned int nBytes) const
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    int64 nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

    if (fAllowFree)
    {
        if (nBlockSize == 1)
        {
            // Transactions under 10K are free
            // (about 4500 BTC if made of 50 BTC inputs)
            if (nBytes < 10000)
                nMinFee = 0;
        }
        else
        {
            // Free transaction area
            if (nNewBlockSize < 27000)
                nMinFee = 0;
        }
    }

    // To limit dust spam, require additional MIN_TX_FEE/MIN_RELAY_TX_FEE for
    //    each non empty output which is less than 0.01
    //
    // It's safe to ignore empty outputs here, because these inputs are allowed
    //     only for coinbase and coinstake transactions.
    BOOST_FOREACH(const CTxOut& txout, vout)
        if (txout.nValue < CENT && !txout.IsEmpty())
            nMinFee += nBaseFee;

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

bool CTransaction::ThreadAnalyzerHandlerToMemoryPool(CValidationState &state, CTxDB& txdb, bool fCheckInputs,
                                                     bool fLimitFree, bool* pfMissingInputs)
{
    try
    {
        return mempool.ThreadAnalyzerHandler(state, txdb, *this, fCheckInputs, fLimitFree, pfMissingInputs);
    }
    catch(std::runtime_error &e)
    {
        return state.Abort(_("System error: ") + e.what());
    }
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
             mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}

bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (fRecursive)
        {
            for (unsigned int i = 0; i < tx.vout.size(); i++)
            {
                std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                if (it != mapNextTx.end())
                    remove(*it->second.ptx, true);
            }
        }
        if (mapTx.count(hash))
        {
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end())
        {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
         vtxid.push_back((*mi).first);
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(0, (nCoinbaseMaturity+20) - GetDepthInMainChain());
}

bool CMerkleTx::ThreadAnalyzerHandlerToMemoryPool(CValidationState& state, CTxDB& txdb, bool fCheckInputs, bool fLimitFree)
{
    return CTransaction::ThreadAnalyzerHandlerToMemoryPool(state, txdb, fCheckInputs, fLimitFree);
}

bool CWalletTx::AcceptWalletTransaction(CValidationState& state, CTxDB& txdb, bool fCheckInputs)
{
    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.ThreadAnalyzerHandlerToMemoryPool(state, txdb, fCheckInputs, false);
            }
        }
        return ThreadAnalyzerHandlerToMemoryPool(state, txdb, fCheckInputs);
    }
    return false;
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                tx = mempool.lookup(hash);
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}





//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
           pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
           pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
           pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
           pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];

    return pblockOrphan->hashPrevBlock;
}

// cacheproject: increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = 30;

unsigned char GetNfactor(int64 nTimestamp)
{
    int l = 0;
    int64 s = 0;
    if(nTimestamp <= nChainStartTime || fTestNet)
       return 4;
    if(nTimestamp > nPowForceTimestamp && nTimestamp < nPowForceTimestamp + NTest)
    {
       s = nTimestamp - nPowForceTimestamp;
       return 6;
    }
       else
           s = nTimestamp - nChainStartTime;

    while((s >> 1) > 3)
    {
           l += 1;
           s >>= 1;
    }

    s &= 3;

    int n = (l * 170 + s * 25 - 2320) / 100;

    if (n < 0) n = 0;

    if (n > 255)
        printf( "GetNfactor(%lld) - something wrong(n == %d)\n", nTimestamp, n );

    unsigned char N = (unsigned char) n;

    return min(max(N, minNfactor), maxNfactor);
}

static const int64 nTargetSpacingWorkMax = 12 * nStakeTargetSpacing;
static const int64 nTargetTimespan = 7 * 24 * 60 * 60;  // one week

static const int64 nTargetSpacingWorkMaxPow = 12 * nPowTargetSpacing; // 14400
static const int64 nTargetSpacingWorkMaxPos = 12 * nPosTargetSpacing; // 7200
static const int64 nTargetTimespanPow = nTargetSpacingWorkMaxPow * 6 * 12; // 1036800  matrix
static const int64 nTargetTimespanPos = nTargetSpacingWorkMaxPos * 6 * 12; // 518400   matrix

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
           pindex = pindex->pprev;
    return pindex;
}
const CBlockIndex* GetLastBlockIndexPow(const CBlockIndex* powpindex, bool fProofOfWork)
{
    while (powpindex && powpindex->pprev && (powpindex->IsProofOfWork() == fProofOfWork))
           powpindex = powpindex->pprev;
    return powpindex;
}
const CBlockIndex* GetLastBlockIndexPos(const CBlockIndex* pospindex, bool fProofOfStake)
{
    while (pospindex && pospindex->pprev && (pospindex->IsProofOfStake() != fProofOfStake))
           pospindex = pospindex->pprev;
    return pospindex;
}

unsigned int GetNextTargetRequiredPow(const CBlockIndex* powpindexLast, bool fProofOfWork)
{
    CBigNum bnTargetLimitPow = bnProofOfWorkLimit;

    if (powpindexLast == NULL)
        return bnTargetLimitPow.GetCompact(); // last block
    const CBlockIndex* powpindexPrev = GetLastBlockIndexPow(powpindexLast, fProofOfWork);
    if (powpindexPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // first block
    const CBlockIndex* powpindexPrevPrev = GetLastBlockIndexPow(powpindexPrev->pprev, fProofOfWork);
    if (powpindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 1
    const CBlockIndex* powpindexPrevPrevPrev = GetLastBlockIndexPow(powpindexPrevPrev->pprev, fProofOfWork);
    if (powpindexPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 2
    const CBlockIndex* powpindexPrevPrevPrevPrev = GetLastBlockIndexPow(powpindexPrevPrevPrev->pprev, fProofOfWork);
    if (powpindexPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 3
    const CBlockIndex* powpindexPrevPrevPrevPrevPrev = GetLastBlockIndexPow(powpindexPrevPrevPrevPrev->pprev, fProofOfWork);
    if (powpindexPrevPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 4
    const CBlockIndex* powpindexPrevPrevPrevPrevPrevPrev = GetLastBlockIndexPow(powpindexPrevPrevPrevPrevPrev->pprev, fProofOfWork);
    if (powpindexPrevPrevPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 5

    double nPowTargetSpacingTest = 0;
    if(powpindexPrev->GetBlockTime() > nPowForceTimestamp && powpindexPrev->GetBlockTime() < nPowForceTimestamp + NTest)
       nPowTargetSpacingTest = nPowTargetSpacing / nPowTargetSpacing * 900;
       else
           nPowTargetSpacingTest = nPowTargetSpacing;
    int64 nActualTimeIntervalLongPowVeryFirst = powpindexPrev->GetBlockTime() - powpindexPrevPrev->GetBlockTime();
    if(nActualTimeIntervalLongPowVeryFirst < 0)
       nActualTimeIntervalLongPowVeryFirst = nPowTargetSpacingTest / 100 * nSpamHashControl;
    int64 nActualTimeIntervalLongPowFirst = powpindexPrevPrev->GetBlockTime() - powpindexPrevPrevPrev->GetBlockTime();
    if(nActualTimeIntervalLongPowFirst < 0)
       nActualTimeIntervalLongPowFirst = nPowTargetSpacingTest / 100 * nSpamHashControl;
    int64 nActualTimeIntervalLongPowSecond = powpindexPrevPrevPrev->GetBlockTime() - powpindexPrevPrevPrevPrev->GetBlockTime();
    if(nActualTimeIntervalLongPowSecond < 0)
       nActualTimeIntervalLongPowSecond = nPowTargetSpacingTest / 100 * nSpamHashControl;
    double nActualSpacingTotalsPow = ( nActualTimeIntervalLongPowVeryFirst + nActualTimeIntervalLongPowFirst ) / 2;
    double nActualTimeIntervalNvar = nActualTimeIntervalLongPowVeryFirst; // ( nActualSpacingTotalsPow + nActualTimeIntervalLongPowSecond ) / 2;

    // cacheproject retarget
    // VALM-Cache /logical analysis - mathematically variable/
    int64 nActualSpacingPow = 0;
    double nVar = nPowTargetSpacingTest / 3;
    int64 nNonAccelerating = 0; // sec +0-
          PowPindexPrevTime = powpindexPrev->GetBlockTime();
          nLastCoinPowSearchInterval = nActualTimeIntervalLongPowVeryFirst;
          nLastCoinPowFiveInterval = nActualSpacingTotalsPow;
          nActualSpacingPow = ( nActualSpacingTotalsPow + nActualTimeIntervalLongPowSecond ) / 2; // nActualTimeIntervalLongPowVeryFirst;
    if(nActualTimeIntervalNvar >= nNonAccelerating && nActualTimeIntervalNvar < nPowTargetSpacingTest - nNonAccelerating)
       nPowTargetSpacingVar = (( nPowTargetSpacingTest - 1 + nVar ) - ( nActualTimeIntervalNvar * nVar / nPowTargetSpacingTest ));
       else if
              (nActualTimeIntervalNvar > nPowTargetSpacingTest + nNonAccelerating && nActualTimeIntervalNvar <= nPowTargetSpacingTest * 2)
               nPowTargetSpacingVar = (( nPowTargetSpacingTest + 1 + nVar ) - ( nActualTimeIntervalNvar * nVar / nPowTargetSpacingTest ));
               else if
                      (nActualTimeIntervalNvar > nPowTargetSpacingTest * 2)
                       nPowTargetSpacingVar = nPowTargetSpacingTest - nVar + 1;
                       else
                           nPowTargetSpacingVar = nPowTargetSpacingTest;
    double nPTSp = nPowTargetSpacingTest; // 1200 sec
    int64 powUppermin = 0;
    double powUppermax = nPTSp - nNonAccelerating; // 1199 sec
    double powLowermin = nPTSp + nNonAccelerating; // 1201 sec
    int64 powLowermax = nTargetSpacingWorkMaxPow;  // 14400 sec
    if(nActualTimeIntervalLongPowVeryFirst > powLowermin && nActualSpacingTotalsPow < powUppermax)
       nActualTimeIntervalXUXLpow = nActualTimeIntervalLongPowVeryFirst;
       else if(nActualTimeIntervalLongPowVeryFirst > powLowermin && nActualSpacingTotalsPow > powLowermin)
               nActualTimeIntervalXUXLpow = min((double) nActualTimeIntervalLongPowVeryFirst, (double) nActualSpacingTotalsPow);
       else if(nActualTimeIntervalLongPowVeryFirst < powUppermax && nActualSpacingTotalsPow < powUppermax)
               nActualTimeIntervalXUXLpow = max((double) nActualTimeIntervalLongPowVeryFirst, (double) nActualSpacingTotalsPow);
       else if(nActualSpacingTotalsPow < powUppermax && nActualSpacingTotalsPow > nActualSpacingPow)
               nActualTimeIntervalXUXLpow = nActualSpacingTotalsPow;
       else if(nActualSpacingTotalsPow > powLowermin && nActualSpacingTotalsPow < nActualSpacingPow)
               nActualTimeIntervalXUXLpow = nActualSpacingTotalsPow;
               else
                   nActualTimeIntervalXUXLpow = nActualSpacingPow;
    double nNix = nPTSp / 100 * 70; // 714
    double nReverseEffectPow = 0;
    if(nActualTimeIntervalXUXLpow < nNix)
       nReverseEffectPow = nActualTimeIntervalXUXLpow / nNix;
       else if(nActualTimeIntervalXUXLpow > nPTSp && nActualTimeIntervalXUXLpow <= nPTSp + ( nPTSp - nNix))
               nReverseEffectPow = ( nPTSp / nPTSp ) / 2;
       else if(nActualTimeIntervalXUXLpow > nPTSp + ( nPTSp - nNix) && nActualTimeIntervalXUXLpow < powLowermax)
               nReverseEffectPow = (( nPTSp + ( nPTSp - nNix )) / nActualTimeIntervalXUXLpow ) / 2;
               else
                   nReverseEffectPow = 1;
       powUpperLower = ( nPTSp / 2 ) * nReverseEffectPow; // interval sampling 2:1 variable
    if(nActualSpacingTotalsPow < nNix / 1.30 && nActualTimeIntervalLongPowVeryFirst < powUppermax)
       powUpperLower = powUpperLower * (( nNix / 1.30 ) / nActualSpacingTotalsPow );
    double XUXL = nPowTargetSpacingTest / 100 * 4;
    double U = 0;
    double L = 0;
    double XU = XUXL + ( powUppermax * powUpperLower / nPTSp ); // 100.9166 +%
    double XL = XUXL + ( nPTSp * powUpperLower / powLowermin ); // 100.9167 +%
    double nBalance = 1.0;
    double nN = XUXL - ( XUXL / nBalance );
    int64 nTargetTimespanMin = nTargetTimespanPow / XL - 1; // min
    int64 nActualTimeIntervalXU = nActualTimeIntervalXUXLpow;
    int64 nActualTimeIntervalXL = nActualTimeIntervalXUXLpow;
    if(nActualTimeIntervalXU >= powUppermin && nActualTimeIntervalXU < powUppermax)
       U = nN + (( XU - ( nActualTimeIntervalXU * powUpperLower / nPTSp )) / nBalance );
       else U = 1;
    if(nActualTimeIntervalXL > powLowermin && nActualTimeIntervalXL < powLowermax)
       L = XL - ( nPTSp * powUpperLower / nActualTimeIntervalXL );
       else if(nActualTimeIntervalXL >= powLowermax)
               L = XL / 2;
               else L = 1;
    int64 nTargetTimespanControlu = nTargetTimespanPow / U; // min
    int64 nTargetTimespanControll = nTargetTimespanPow / L; // min
    if(nTargetTimespanControlu >= nTargetTimespanMin)
       XUpperPow = U;
       else if(nTargetTimespanControlu < nTargetTimespanMin)
               XUpperPow = XU;
               else
                   XUpperPow = 1;
    if(nTargetTimespanControll >= nTargetTimespanMin)
       XLowerPow = L;
       else if(nTargetTimespanControll < nTargetTimespanMin)
               XLowerPow = XL;
               else
                   XLowerPow = 1;
    CBigNum bnNewPow;
    bnNewPow.SetCompact(powpindexPrev->nBits);
    double nTargetTimespanBn = nTargetTimespanPow / max( XUpperPow, XLowerPow );
    double nInterval = nTargetTimespanBn / nPowTargetSpacingTest;
    if(powpindexPrev->GetBlockTime() > nPowForceTimestamp)
    {
       if(powpindexPrev->GetBlockTime() > nPowForceTimestamp && powpindexPrev->IsProofOfWork())

       bnNewPow *= (( (int64) nInterval - 1) * (int64) nPowTargetSpacingVar + (int64) nActualTimeIntervalXUXLpow + (int64) nActualTimeIntervalXUXLpow);
       bnNewPow /= (( (int64) nInterval + 1) * (int64) nPowTargetSpacingVar);

       if(bnNewPow > bnTargetLimitPow)
          bnNewPow = bnTargetLimitPow;
       if(bnNewPow < bnTargetLimitPow && powpindexPrev->GetBlockTime() > nPowForceTimestamp &&
                                         powpindexPrev->GetBlockTime() < nPowForceTimestamp + NTest)
          bnNewPow = bnTargetLimitPow;
     }
    return bnNewPow.GetCompact();
}

unsigned int GetNextTargetRequiredPos(const CBlockIndex* pospindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimitPos = bnProofOfStakeHardLimit;

    if (pospindexLast == NULL)
        return bnTargetLimitPos.GetCompact(); // last block
    const CBlockIndex* pospindexPrev = GetLastBlockIndexPos(pospindexLast, fProofOfStake);
    if (pospindexPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // first block
    const CBlockIndex* pospindexPrevPrev = GetLastBlockIndexPos(pospindexPrev->pprev, fProofOfStake);
    if (pospindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 1
    const CBlockIndex* pospindexPrevPrevPrev = GetLastBlockIndexPos(pospindexPrevPrev->pprev, fProofOfStake);
    if (pospindexPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 2
    const CBlockIndex* pospindexPrevPrevPrevPrev = GetLastBlockIndexPos(pospindexPrevPrevPrev->pprev, fProofOfStake);
    if (pospindexPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 3
    const CBlockIndex* pospindexPrevPrevPrevPrevPrev = GetLastBlockIndexPos(pospindexPrevPrevPrevPrev->pprev, fProofOfStake);
    if (pospindexPrevPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 4
    const CBlockIndex* pospindexPrevPrevPrevPrevPrevPrev = GetLastBlockIndexPos(pospindexPrevPrevPrevPrevPrev->pprev, fProofOfStake);
    if (pospindexPrevPrevPrevPrevPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block 5

    int64 nLastCoinSearchTime = GetAdjustedTime();

    if(pospindexPrev->IsProofOfStake() && pospindexPrevPrev->IsProofOfStake() &&
       pospindexPrevPrevPrev->IsProofOfStake() && pospindexPrevPrevPrevPrev->IsProofOfStake())
    {
    nLastCoinPosSearchInterval = ( nLastCoinSearchTime - PosPindexPrevPrevTime ) - ( nLastCoinSearchTime - PosPindexPrevTime );
    nLastCoinPosSearchIntervalPrev = ( nLastCoinSearchTime - PosPindexPrevPrevPrevTime ) - ( nLastCoinSearchTime - PosPindexPrevPrevTime );
    nLastCoinPosSearchIntervalPrevPrev = ( nLastCoinSearchTime - PosPindexPrevPrevPrevPrevTime ) - ( nLastCoinSearchTime - PosPindexPrevPrevPrevTime );
    }

    nUnixCachChainTime = nLastCoinSearchTime - 1 + nNewTimeBlock;

    double nPosTargetSpacingTest = 0;
    if(pospindexPrev->GetBlockTime() > nPowForceTimestamp && pospindexPrev->GetBlockTime() < nPowForceTimestamp + NTest)
       nPosTargetSpacingTest = nPosTargetSpacing / nPosTargetSpacing * 600;
       else
           nPosTargetSpacingTest = nPosTargetSpacing;
    int64 nActualTimeIntervalLongPosVeryFirst = nLastCoinPosSearchInterval;
    if(nActualTimeIntervalLongPosVeryFirst < 0)
       nActualTimeIntervalLongPosVeryFirst = nPosTargetSpacingTest / 100 * nSpamHashControl;
    int64 nActualTimeIntervalLongPosFirst = nLastCoinPosSearchIntervalPrev;
    if(nActualTimeIntervalLongPosFirst < 0)
       nActualTimeIntervalLongPosFirst = nPosTargetSpacingTest / 100 * nSpamHashControl;
    int64 nActualTimeIntervalLongPosSecond = nLastCoinPosSearchIntervalPrevPrev;
    if(nActualTimeIntervalLongPosSecond < 0)
       nActualTimeIntervalLongPosSecond = nPosTargetSpacingTest / 100 * nSpamHashControl;
    double nActualSpacingTotalsPos = ( nActualTimeIntervalLongPosVeryFirst + nActualTimeIntervalLongPosFirst ) / 2;
    double nActualTimeIntervalNvar = nActualTimeIntervalLongPosVeryFirst; // ( nActualSpacingTotalsPos + nActualTimeIntervalLongPosSecond ) / 2;

    // cacheproject retarget
    // VALM-Cache /logical analysis - mathematically variable/
    int64 nActualSpacingPos = 0;
    double nVar = nPosTargetSpacingTest / 3;
    int64 nNonAccelerating = 0; // sec +0-
          PosPindexPrevTime = pospindexPrev->GetBlockTime();
          PosPindexPrevPrevTime = pospindexPrevPrev->GetBlockTime();
          PosPindexPrevPrevPrevTime = pospindexPrevPrevPrev->GetBlockTime();
          PosPindexPrevPrevPrevPrevTime = pospindexPrevPrevPrevPrev->GetBlockTime();
          nLastCoinPosTwoInterval = nActualSpacingTotalsPos;
          nActualSpacingPos = ( nActualSpacingTotalsPos + nActualTimeIntervalLongPosSecond ) / 2; // nActualTimeIntervalLongPosVeryFirst;
    if(nActualTimeIntervalNvar >= nNonAccelerating && nActualTimeIntervalNvar < nPosTargetSpacingTest - nNonAccelerating)
       nPosTargetSpacingVar = (( nPosTargetSpacingTest - 1 + nVar ) - ( nActualTimeIntervalNvar * nVar / nPosTargetSpacingTest ));
       else if
              (nActualTimeIntervalNvar > nPosTargetSpacingTest + nNonAccelerating && nActualTimeIntervalNvar <= nPosTargetSpacingTest * 2)
               nPosTargetSpacingVar = (( nPosTargetSpacingTest + 1 + nVar ) - ( nActualTimeIntervalNvar * nVar / nPosTargetSpacingTest ));
               else if
                      (nActualTimeIntervalNvar > nPosTargetSpacingTest * 2)
                       nPosTargetSpacingVar = nPosTargetSpacingTest - nVar + 1;
                       else
                           nPosTargetSpacingVar = nPosTargetSpacingTest;
    double nSTSp = nPosTargetSpacingTest; // 1200 sec
    int64 posUppermin = 0;
    double posUppermax = nSTSp - nNonAccelerating; // 1199 sec
    double posLowermin = nSTSp + nNonAccelerating; // 1201 sec
    int64 posLowermax = nTargetSpacingWorkMaxPos;  // 2400 sec
    if(nActualTimeIntervalLongPosVeryFirst > posLowermin && nActualSpacingTotalsPos < posUppermax)
       nActualTimeIntervalXUXLpos = nActualTimeIntervalLongPosVeryFirst;
       else if(nActualTimeIntervalLongPosVeryFirst > posLowermin && nActualSpacingTotalsPos > posLowermin)
               nActualTimeIntervalXUXLpos = min((double) nActualTimeIntervalLongPosVeryFirst, (double) nActualSpacingTotalsPos);
       else if(nActualTimeIntervalLongPosVeryFirst < posUppermax && nActualSpacingTotalsPos < posUppermax)
               nActualTimeIntervalXUXLpos = max((double) nActualTimeIntervalLongPosVeryFirst, (double) nActualSpacingTotalsPos);
       else if(nActualSpacingTotalsPos < posUppermax && nActualSpacingTotalsPos > nActualSpacingPos)
               nActualTimeIntervalXUXLpos = nActualSpacingTotalsPos;
       else if(nActualSpacingTotalsPos > posLowermin && nActualSpacingTotalsPos < nActualSpacingPos)
               nActualTimeIntervalXUXLpos = nActualSpacingTotalsPos;
               else
                   nActualTimeIntervalXUXLpos = nActualSpacingPos;
    double nNix = nSTSp / 100 * 70;
    double nReverseEffectPos = 0;
    if(nActualTimeIntervalXUXLpos < nNix)
       nReverseEffectPos = nActualTimeIntervalXUXLpos / nNix;
       else if(nActualTimeIntervalXUXLpos > nSTSp && nActualTimeIntervalXUXLpos <= nSTSp + ( nSTSp - nNix))
               nReverseEffectPos = ( nSTSp / nSTSp ) / 2;
       else if(nActualTimeIntervalXUXLpos > nSTSp + ( nSTSp - nNix) && nActualTimeIntervalXUXLpos < posLowermax)
               nReverseEffectPos = (( nSTSp + ( nSTSp - nNix )) / nActualTimeIntervalXUXLpos ) / 2;
               else
                   nReverseEffectPos = 1;
       posUpperLower = ( nSTSp / 2 ) * nReverseEffectPos; // interval sampling 2:1 variable
    if(nActualSpacingTotalsPos < nNix / 1.30 && nActualTimeIntervalLongPosVeryFirst < posUppermax)
       posUpperLower = posUpperLower * (( nNix / 1.30 ) / nActualSpacingTotalsPos );
    double XUXL = nPosTargetSpacingTest / 100 * 4;
    double U = 0;
    double L = 0;
    double XU = XUXL + ( posUppermax * posUpperLower / nSTSp ); // 100.9166 +%
    double XL = XUXL + ( nSTSp * posUpperLower / posLowermin ); // 100.9167 +%
    double nBalance = 1.0;
    double nN = XUXL - ( XUXL / nBalance );
    int64 nTargetTimespanMin = nTargetTimespanPos / XL - 1; // min
    int64 nActualTimeIntervalXU = nActualTimeIntervalXUXLpos;
    int64 nActualTimeIntervalXL = nActualTimeIntervalXUXLpos;
    if(nActualTimeIntervalXU >= posUppermin && nActualTimeIntervalXU < posUppermax)
       U = nN + (( XU - ( nActualTimeIntervalXU * posUpperLower / nSTSp )) / nBalance );
       else U = 1;
    if(nActualTimeIntervalXL > posLowermin && nActualTimeIntervalXL < posLowermax)
       L = XL - ( nSTSp * posUpperLower / nActualTimeIntervalXL );
       else if(nActualTimeIntervalXL >= posLowermax)
               L = XL / 2;
               else L = 1;
    int64 nTargetTimespanControlu = nTargetTimespanPos / U; // min
    int64 nTargetTimespanControll = nTargetTimespanPos / L; // min
    if(nTargetTimespanControlu >= nTargetTimespanMin)
       XUpperPos = U;
       else if(nTargetTimespanControlu < nTargetTimespanMin)
               XUpperPos = XU;
               else
                   XUpperPos = 1;
    if(nTargetTimespanControll >= nTargetTimespanMin)
       XLowerPos = L;
       else if(nTargetTimespanControll < nTargetTimespanMin)
               XLowerPos = XL;
               else
                   XLowerPos = 1;
    CBigNum bnNewPos;
    bnNewPos.SetCompact(pospindexPrev->nBits);
    double nTargetTimespanBn = nTargetTimespanPos / max( XUpperPos, XLowerPos );
    double nInterval = nTargetTimespanBn / nPosTargetSpacingTest;
    if(pospindexPrev->GetBlockTime() > nPowForceTimestamp)
    {
       if(pospindexPrev->GetBlockTime() > nPowForceTimestamp && pospindexPrev->IsProofOfStake())

       bnNewPos *= (( (int64) nInterval - 1) * (int64) nPosTargetSpacingVar + (int64) nActualTimeIntervalXUXLpos + (int64) nActualTimeIntervalXUXLpos);
       bnNewPos /= (( (int64) nInterval + 1) * (int64) nPosTargetSpacingVar);

       if(bnNewPos > bnTargetLimitPos)
          bnNewPos = bnTargetLimitPos;
       //if(bnNewPos < bnTargetLimitPos + bnTargetLimitPos)
          //bnNewPos = bnTargetLimitPos;
     }
    return bnNewPos.GetCompact();
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = bnProofOfWorkLimit;
     if(fProofOfStake)
     {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        if(fTestNet)
            bnTargetLimit = bnProofOfStakeHardLimit;
            else
             {
                bnTargetLimit = bnProofOfStakeHardLimit;
             }
    }
    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block

    int64 nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64 nTargetSpacing;
    if(pindexPrev->GetBlockTime() > 1388949883 && pindexPrev->GetBlockTime() < nPowForceTimestamp)
    {
       if(pindexPrev->GetBlockTime() < 1391046000)
          nTargetSpacing = fProofOfStake? nStakeTargetSpacing : min(nTargetSpacingWorkMax, (int64) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
          else if(pindexPrev->GetBlockTime() < POWFIX_DATE)
                  nTargetSpacing = fProofOfStake? nStakeTargetSpacing : min((int64) nStakeTargetSpacing * 2, (int64) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
                  else if(nActualSpacing > nStakeTargetSpacing * 6)
                  {
                          int factor = (nActualSpacing / nStakeTargetSpacing);
                              factor /= 3;
                              factor--;
                              bnNew *= factor;
                           if(bnNew > bnTargetLimit)
                              bnNew = bnTargetLimit;
                           return bnNew.GetCompact();
                  }
                  else
                  {
                       nTargetSpacing = fProofOfStake? nStakeTargetSpacing : min(nTargetSpacingWorkMax, (int64) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
                  }

           int64 nInterval = nTargetTimespan / nTargetSpacing;
           bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
           bnNew /= ((nInterval + 1) * nTargetSpacing);

         if (bnNew > bnTargetLimit)
             bnNew = bnTargetLimit;
    }
    return bnNew.GetCompact();
}

int64 GetProofOfWorkReward(unsigned int nBits)
{
    CBigNum bnMinSubsidyLimit = 0;
    if  (PowPindexPrevTime > nPowForceTimestamp + NTest)
         bnMinSubsidyLimit = MIN_MINT_PROOF_OF_WORK;
    else bnMinSubsidyLimit = MINT_PROOF_OF_WORK;
    CBigNum bnMaxSubsidyLimit = MAX_MINT_PROOF_OF_WORK;
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnTargetLimit = bnProofOfWorkLimit;
    bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

    // cacheproject subsidy
    CBigNum bnLowerBound = CENT;
    CBigNum bnUpperBound = bnMinSubsidyLimit;
    while (bnLowerBound + CENT <= bnUpperBound)
    {
        CBigNum bnMidValue = (bnLowerBound + bnUpperBound) / 2;
        if (fDebug && GetBoolArg("-printcreation"))
            printf("GetProofOfWorkReward() : lower=%"PRI64d" upper=%"PRI64d" mid=%"PRI64d"\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnTargetLimit > bnMinSubsidyLimit * bnMinSubsidyLimit * bnMinSubsidyLimit * bnMinSubsidyLimit * bnMinSubsidyLimit * bnMinSubsidyLimit * bnTarget)
            bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }
    if(PowPindexPrevTime > nPowForceTimestamp + NTest)
    {
    bnUpperBound = bnMaxSubsidyLimit - bnUpperBound;
    bnLowerBound = bnMaxSubsidyLimit - bnLowerBound;
    }
    int64 nSubsidy = bnUpperBound.getuint64();
    nSubsidy = (nSubsidy / CENT) * CENT;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfWorkReward() : create=%s nBits=0x%08x nSubsidy=%"PRI64d"\n", FormatMoney(nSubsidy).c_str(), nBits, nSubsidy);

    if  (PowPindexPrevTime > nPowForceTimestamp + NTest)
         return max(nSubsidy, MIN_MINT_PROOF_OF_WORK);
    else return min(nSubsidy, MINT_PROOF_OF_WORK);
}

// ppcoin: miner's coin stake is rewarded based on coin age spent (coin-days)
int64 GetProofOfStakeReward(int64 nCoinAge)
{
    static int64 nRewardCoinYear = 5 * CENT;  // creation amount per coin-year
    int64 nSubsidy;
    if(fTestNet)
       nSubsidy = nCoinAge * 33 * nRewardCoinYear / (365 * 33 + 8);
       else if(pindexBest->GetBlockTime() >= 1393140000)
               nSubsidy = nCoinAge * 33 * nRewardCoinYear / (365 * 33 + 8);
               else
                   nSubsidy = nCoinAge * 33 / (365 * 33 + 8) * nRewardCoinYear;

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%"PRI64d"\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    return nSubsidy;
}

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime)
{
    CBigNum bnTargetLimit = bnProofOfWorkLimit;

    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
           // Maximum 200% adjustment per day...
           bnResult *= 2;
           nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

void ThreadAnalyzerHandler()
{
    int64 nPrevTimeCount = 0;
    int64 nPrevTimeCount2 = 0;
    int64 nThresholdPow = 0;
    int64 nThresholdPos = 0;

    loop
    {
       int64 nTimeCount = GetTime() + nNewTimeBlock;
       int64 nTimeCount2 = GetTime() + nNewTimeBlock;
             nThresholdPow = nPowTargetSpacing / 100 * nSpamHashControl;
             nThresholdPos = nPosTargetSpacing / 100 * nSpamHashControl;
       int64 nPowPrevTime = (GetLastBlockIndexPow(pindexBest, false)->GetBlockTime());
       int64 nPosPrevTime = pindexBest->GetBlockTime();
       if (pindexBest->nHeight > 2018)
       {
           if (nTimeCount != nPrevTimeCount)
           {
               nPrevTimeCount = nTimeCount;
               uiInterface.NotifySpamHashControlPowChanged(nTimeCount - nPowPrevTime, nThresholdPow);
               nLastCoinWithoutPowSearchInterval = nTimeCount - nPowPrevTime;
           }
           if (nTimeCount2 != nPrevTimeCount2)
           {
               if (pindexBest->IsProofOfStake())
               {
                   nPrevTimeCount2 = nTimeCount2;
                   uiInterface.NotifySpamHashControlPosChanged(nTimeCount2 - nPosPrevTime, nThresholdPos);
                   nLastCoinWithoutPosSearchInterval = nTimeCount2 - nPosPrevTime;
               }
               if (pindexBest->IsProofOfWork())
               {
                   nPrevTimeCount2 = nTimeCount2;
                   uiInterface.NotifySpamHashControlPosChanged(nTimeCount2 - pindexBest->pprev->GetBlockTime(), nThresholdPos);
                   nLastCoinWithoutPosSearchInterval = nTimeCount2 - pindexBest->pprev->GetBlockTime();
               }
           }
       }
       Sleep(3000);
    }
}

bool CTxMemPool::ThreadAnalyzerHandler(CValidationState &state, CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool fLimitFree,
                                       bool* pfMissingInputs)
{
    MapPrevTx mapInputs;
    bool fInvalid = false;
    bool fScriptChecks = true;
    map<uint256, CTxIndex> mapUnused;
    std::vector<CScriptCheck> vChecks;

    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.ThreadAnalyzerHandler(state, txdb, mapUnused, 0, false, false, false, mapInputs, fInvalid,
                                  fScriptChecks, nScriptCheckThreads ? &vChecks : NULL,
                                  STRICT_FLAGS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
        return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : CheckTransaction failed");

    if (!tx.HardForkControl(state, mapInputs))
        return error("'CTxMemPool - Accept' - Attempt to send transaction to HardForkControlAddress");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : coinbase as individual tx"));
    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.DoS(100, error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
        return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    string strNonStd;
    if (!fTestNet && !tx.IsStandardCach(strNonStd))
        return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : nonstandard transaction (%s)", strNonStd.c_str());

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        CTxDB txdb;
        MapPrevTx mapInputs;
        bool fInvalid = false;
        bool fScriptChecks = true;
        map<uint256, CTxIndex> mapUnused;
        std::vector<CScriptCheck> vChecks;
        if (!tx.ThreadAnalyzerHandler(state, txdb, mapUnused, 0, false, false, false, mapInputs, fInvalid,
                                      fScriptChecks, nScriptCheckThreads ? &vChecks : NULL, STRICT_FLAGS |
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
        {
            if (fInvalid)
                return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : Inputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
            return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64 txMinFee = tx.GetMinFee(1000, false, GMF_RELAY);
        if (nFees < txMinFee)
            return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : not enough fees %s, %" PRI64d" < %" PRI64d,
                         hash.ToString().c_str(), nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
        {
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            LOCK(cs);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000 && !IsFromMe(tx))
                return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : free transaction rejected by rate limiter");
            if (fDebug)
                printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.ThreadAnalyzerHandler(state, txdb, mapUnused, 0, false, false, false, mapInputs, fInvalid,
                                      fScriptChecks, nScriptCheckThreads ? &vChecks : NULL, STRICT_FLAGS |
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
        {
            return error("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : ConnectInputs failed %s", hash.ToString().c_str());
        }
    }

    // Store transaction in memory
    if (fStoreTxMemory)
    {
      {
        LOCK(cs);
        if (ptxOld)
        {
            printf("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
      }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());
    SyncWithWallets(tx, NULL, true, true);
    printf("'CTxMemPool - Accept' - ThreadAnalyzerHandler() : accepted %s (poolsz %"PRIszu")\n", hash.ToString().substr(0,10).c_str(), mapTx.size());
   }
    return true;
}

std::string waitTxSpam = " Spam is missing now";
const unsigned int nNumberOfLines = 100;
unsigned int nLinesSource = nNumberOfLines - 1;
unsigned int nLinesReceiver = nNumberOfLines;
char nSpamHashList[nNumberOfLines + 1][21];

unsigned char SpamHashList()
{
    bool fWriting = true;

    unsigned int nSearched = 0;
    for (; nSearched <= nNumberOfLines; nSearched++)
    {
         if (strcmp(nSpamHashList[nSearched], waitTxSpam.substr(0,20).c_str()) == 0)
         {
         fWriting = false;
         printf("'SpamHashList' - previously saved spam-hash %s\n", nSpamHashList[nSearched]);
         }
         //printf("'SpamHashList' - all saved spam-hash %s\n", nSpamHashList[nSearched]);
    }

    if (fWriting)
    {
        unsigned int nWriting = 0;
        for (; nWriting <= nNumberOfLines; nWriting++)
        {

            {
            if (nLinesReceiver - nWriting != 0)
            strcpy(nSpamHashList[nLinesReceiver - nWriting], nSpamHashList[nLinesSource - nWriting]);
            }
            strcpy(nSpamHashList[0], waitTxSpam.substr(0,20).c_str());
        }
    }
    return false;
}

bool CTransaction::ThreadAnalyzerHandler(CValidationState &state, CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                                         const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fTxOnly, MapPrevTx& inputsRet,
                                         bool& fInvalid, bool fScriptChecks, std::vector<CScriptCheck> *pvChecks,
                                         unsigned int flags) const
{
     // Basic checks that don't depend on any context
    if (vin.empty())
    {
        waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
        return state.DoS(10, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : vin empty"));
    }

    if (vout.empty())
    {
        waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
        return state.DoS(10, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : vout empty"));
    }

    // Time (prevent mempool memory exhaustion attack)
    if (nTime > GetAdjustedTime() + nMaxClockDrift)
    {
        waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
        return state.DoS(10, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : timestamp is too far into the future"));
    }

    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
    {
        waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
        return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : size limits failed"));
    }

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (txout.IsEmpty() && (!IsCoinBase()) && (!IsCoinStake()))
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : txout empty for user transaction"));
        }
        if (txout.nValue < 0)
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : txout.nValue is negative"));
        }
        // ppcoin: enforce minimum output amount
        if ((!txout.IsEmpty()) && txout.nValue < MIN_TXOUT_AMOUNT)
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : txout.nValue below minimum"));
        }
        if (txout.nValue > MAX_MONEY)
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : txout.nValue too high"));
        }
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : txout total out of range"));
        }
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : duplicate inputs"));
        }
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return state.DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : coinbase script size"));
        }
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(10, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : prevout is null"));
            }
    }
    if (fTxOnly)
        return true;

    fInvalid = false;

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if (mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound)
        {
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        }

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            {
                LOCK(mempool.cs);
                if (!mempool.exists(prevout.hash))
                {
                    waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                    return error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
                }
                    txPrev = mempool.lookup(prevout.hash);
            }
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
            }
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const COutPoint prevout = vin[i].prevout;
        assert(inputsRet.count(prevout.hash) != 0);
        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
            return DoS(100, error("'Transaction - CheckTransaction' - ThreadAnalyzerHandler() : %s prevout.n out of range %d %"PRIszu" %"PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    if (!IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(vin.size());

        // While checking, GetBestBlock() refers to the parent block.
        // This is also true for mempool checks.
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            const COutPoint &prevout = vin[i].prevout;
            assert(inputsRet.count(prevout.hash) > 0);
            const CTxIndex& txindexcoins = inputsRet[prevout.hash].first;
            const CTransaction &txcoins = inputsRet[prevout.hash].second;

            if (prevout.n >= txcoins.vout.size() || prevout.n >= txindexcoins.vSpent.size())
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return DoS(100, error("'Transaction - CheckInputs' : %s prevout.n out of range %d %"PRIszu" %"PRIszu" prev tx %s\n%s",
                GetHash().ToString().substr(0,10).c_str(), prevout.n, txcoins.vout.size(), txindexcoins.vSpent.size(),
                prevout.hash.ToString().substr(0,10).c_str(), txcoins.ToString().c_str()));
            }

            // If prev is coinbase or coinstake, check that it's matured
            if (txcoins.IsCoinBase() || txcoins.IsCoinStake())
                for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < nCoinbaseMaturity; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindexcoins.pos.nBlockPos && pindex->nFile == txindexcoins.pos.nFile)
                    {
                        waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                        return error("'Transaction - CheckInputs' : tried to spend %s at depth %d", txcoins.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);
                    }

            // ppcoin: check transaction timestamp
            if (txcoins.nTime > nTime)
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : transaction timestamp earlier than input transaction"));
            }

            // Check for negative or overflow input values
            nValueIn += txcoins.vout[prevout.n].nValue;
            if (!MoneyRange(txcoins.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : txin values out of range"));
            }
        }

        if (IsCoinStake())
        {
            // ppcoin: coin stake tx earns reward instead of paying fee
            uint64 nCoinAge;
            if (!GetCoinAge(txdb, nCoinAge))
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return error("'Transaction - CheckInputs' : %s unable to get coin age for coinstake", GetHash().ToString().c_str());
            }

            int64 nStakeReward = GetValueOut() - nValueIn;
            if (nStakeReward > GetProofOfStakeReward(nCoinAge) - GetMinFee() + MIN_TX_FEE)
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : %s stake reward exceeded", GetHash().ToString().c_str()));
            }
        }
        else
        {
            if (nValueIn < GetValueOut())
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : %s value in < value out", GetHash().ToString().c_str()));
            }

            // Tally transaction fees
            int64 nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : %s nTxFee < 0", GetHash().ToString().c_str()));
            }
            // ppcoin: enforce transaction fees for every block
            if (nTxFee < GetMinFee())
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : %s not paying required fee=%s, paid=%s", GetHash().ToString().c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str()));
            }
            nFees += nTxFee;
            if (!MoneyRange(nFees))
            {
                waitTxSpam = (GetHash().ToString().substr(0,20).c_str());
                return state.DoS(100, error("'Transaction - CheckInputs' : nFees out of range"));
            }
        }

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks)
        {
            for (unsigned int i = 0; i < vin.size(); i++)
            {
                const COutPoint &prevout = vin[i].prevout;
                const CTransaction &txcoins = inputsRet[prevout.hash].second;

                // Verify signature
                CScriptCheck check(txcoins, *this, i, flags, 0);
                if (pvChecks)
                {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                }
                else if (!check())
                {
                    if (flags & SCRIPT_VERIFY_STRICTENC)
                    {
                        // For now, check whether the failure was caused by non-canonical
                        // encodings or not; if so, don't trigger DoS protection.
                        CScriptCheck check(txcoins, *this, i, flags & (~SCRIPT_VERIFY_STRICTENC), 0);
                        if (check())
                            return state.Invalid();
                    }
                    return state.DoS(100,false);
                }
            }
        }
    }
    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    int64 nCurrentTime = GetTime();
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = nCurrentTime;
    }
    return (nCurrentTime - nLastUpdate < 10 &&
            pindexBest->GetBlockTime() < nCurrentTime - 24 * 60 * 60);
}

void static InvalidChainFoundCach(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
        uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=% date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString().c_str(), (uint32_t)nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=% date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      CBigNum(pindexBest->nChainTrust).ToString().c_str(),
      (uint32_t)nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.n];
}

int64 CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64 nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

bool CScriptCheck::operator()() const {
     const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
     if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, true, nHashType))
         return error("CScriptCheck() : %s VerifySignature failed", ptxTo->GetHash().ToString().substr(0,10).c_str());
     return true;
}

bool VerifySignatureCach(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
     return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::CheckInputsLevelTwo(CValidationState &state, CTxDB& txdb, MapPrevTx inputs, map<uint256,
                                       CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
                                       const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks,
                                       unsigned int flags, std::vector<CScriptCheck> *pvChecks,
                                       bool fStrictPayToScriptHash)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    if (!IsCoinBase())
    {
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return DoS(100, error("ConnectInputs() : %s prevout.n out of range %d %"PRIszu" %"PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
                for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < nCoinbaseMaturity; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("ConnectInputs() : txin values out of range"));

        }

        if (pvChecks)
            pvChecks->reserve(vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            COutPoint prevout = vin[i].prevout;
            assert(inputs.count(prevout.hash) > 0);
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (fScriptChecks)
            {
                // Verify signature
                CScriptCheck check(txPrev, *this, i, flags, 0);
                if (pvChecks)
                {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                }
                else if (!check())
                {
                    if (flags & STRICT_FLAGS)
                    {
                        // Don't trigger DoS code in case of STRICT_FLAGS caused failure.
                        CScriptCheck check(txPrev, *this, i, flags & ~STRICT_FLAGS, 0);
                        if (check())
                            return error("ConnectInputs() : %s strict VerifySignature failed", GetHash().ToString().substr(0,10).c_str());
                    }
                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (!(fBlock && (nBestHeight < Checkpoints::GetTotalBlocksEstimate())))
            {
                // Verify signature
                if (!VerifySignature(txPrev, *this, i, fStrictPayToScriptHash, 0))
                {
                    // only during transition phase for P2SH: do not invoke anti-DoS code for
                    // potentially old clients relaying bad P2SH transactions
                    if (fStrictPayToScriptHash && VerifySignature(txPrev, *this, i, false, 0))
                        return error("ConnectInputs() : %s P2SH VerifySignature failed", GetHash().ToString().substr(0,10).c_str());

                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
        }

        if (IsCoinStake())
        {
            // ppcoin: coin stake tx earns reward instead of paying fee
            uint64 nCoinAge;
            if (!GetCoinAge(txdb, nCoinAge))
                return error("ConnectInputs() : %s unable to get coin age for coinstake", GetHash().ToString().substr(0,10).c_str());
            int64 nStakeReward = GetValueOut() - nValueIn;
            if (nStakeReward > GetProofOfStakeReward(nCoinAge) - GetMinFee() + MIN_TX_FEE)
                return DoS(100, error("ConnectInputs() : %s stake reward exceeded", GetHash().ToString().substr(0,10).c_str()));
        }
        else
        {
            if (nValueIn < GetValueOut())
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            int64 nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
                return DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));
            // ppcoin: enforce transaction fees for every block
            if (nTxFee < GetMinFee())
                return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", GetHash().ToString().substr(0,10).c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str())) : false;

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}

bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    {
        LOCK(mempool.cs);
        int64 nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mempool.exists(prevout.hash))
                return false;
            CTransaction& txPrev = mempool.lookup(prevout.hash);

            if (prevout.n >= txPrev.vout.size())
                return false;

            // Verify signature Cach
            if (!VerifySignatureCach(txPrev, *this, i, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, 0))
                return error("ClientConnectInputs() : VerifySignature failed");

            // Verify signature
            if (!VerifySignature(txPrev, *this, i, true, 0))
                return error("ConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mempool.mapNextTx stuff,
            ///// not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.n].nValue;

            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return error("ClientConnectInputs() : txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck(void*)
{
    vnThreadsRunning[THREAD_SCRIPTCHECK]++;
    RenameThread("cachecoin-scriptch");
    scriptcheckqueue.Thread();
    vnThreadsRunning[THREAD_SCRIPTCHECK]--;
}

void ThreadScriptCheckQuit()
{
    scriptcheckqueue.Quit();
}

bool CBlock::ConnectBlock(CValidationState &state, CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(state, !fJustCheck, !fJustCheck, false))
        return false;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.
    bool fEnforceBIP30 = true; // Always active in NovaCoin
    bool fStrictPayToScriptHash = true; // Always active in NovaCoin
    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);
    int64 nFees = 0;
    int64 nValueIn = 0;
    int64 nValueOut = 0;
    unsigned int nSigOps = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        if (fEnforceBIP30)
        {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld))
            {
                BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                    if (pos.IsNull())
                        return false;
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        std::vector<CScriptCheck> vChecks;

        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            bool fInvalid;
            if (!tx.ThreadAnalyzerHandler(state, txdb, mapQueuedChanges, 0, true, false, false, mapInputs, fInvalid,
                                          fScriptChecks, nScriptCheckThreads ? &vChecks : NULL, STRICT_FLAGS |
                                          SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
                return false;

            if (fStrictPayToScriptHash)
            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += tx.GetP2SHSigOpCount(mapInputs);
                if (nSigOps > MAX_BLOCK_SIGOPS)
                    return DoS(100, error("ConnectBlock() : too many sigops"));
            }

            int64 nTxValueIn = tx.GetValueIn(mapInputs);
            int64 nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            std::vector<CScriptCheck> vChecks;
            if (!tx.CheckInputsLevelTwo(state, txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fScriptChecks, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, nScriptCheckThreads ? &vChecks : NULL))
                return false;
            control.Add(vChecks);

            if (!tx.CheckInputsLevelTwo(state, txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash))
                return false;
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteBlockIndex for pindex failed");

    // ppcoin: fees are not collected by miners as in bitcoin
    // ppcoin: fees are destroyed to compensate the entire network
    if (fDebug && GetBoolArg("-printcreation"))
        printf("ConnectBlock() : destroy=%s nFees=%"PRI64d"\n", FormatMoney(nFees).c_str(), nFees);

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}

bool static Reorganize(CValidationState &state, CTxDB& txdb, CBlockIndex* pindexNew)
{
    printf("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    printf("REORGANIZE: Disconnect %"PRIszu" blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    printf("REORGANIZE: Connect %"PRIszu" blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(state, txdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.ThreadAnalyzerHandlerToMemoryPool(state, txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
    {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
        printf("     Delete redundant memory transactions that are in the connected branch\n");
    }

    printf("REORGANIZE: done\n");

    return true;
}

// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CValidationState &state, CTxDB& txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(state, txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFoundCach(pindexNew);
        return false;
    }

    //if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    //{
    //    txdb.TxnAbort();
    //    InvalidChainFound(pindexNew);
    //    return false;
    //}

    if (!txdb.TxnCommit())
        return error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
        printf("     Delete redundant memory transactions\n");
    }
    return true;
}

bool CBlock::SetBestChain(CValidationState &state, CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
    {
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(state, txdb, pindexNew))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->bnChainTrust > pindexBest->bnChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            printf("Postponing %"PRIszu" reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (!Reorganize(state, txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFoundCach(pindexNew);
            return error("SetBestChain() : Reorganize failed");
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                printf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                printf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(state, txdb, pindex))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestHeightTime = pindexBest->GetBlockTime();   // WM - Record timestamp of new best block.
    bnBestChainTrust = pindexNew->bnChainTrust;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    printf("SetBestChain: new best=%s  height=%d  trust=%s  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, bnBestChainTrust.ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;
    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;
        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%"PRI64d" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64 nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%"PRI64d"\n", nCoinAge);
    return true;
}

bool CBlock::AddToBlockIndex(CValidationState &state, unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;

    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    // ppcoin: compute chain trust score
    pindexNew->bnChainTrust = (pindexNew->pprev ? pindexNew->pprev->bnChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight)))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
            return error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->hashProofOfStake = mapProofOfStake[hash];
    }

    // ppcoin: compute stake modifier
    uint64 nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
    if (!CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum))
        return error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016"PRI64x, pindexNew->nHeight, nStakeModifier);

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
        return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    // New best
    if (pindexNew->bnChainTrust > bnBestChainTrust)
        if (!SetBestChain(state, txdb, pindexNew))
            return false;

    txdb.Close();

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    static int8_t counter = 0;
    if( (++counter & 0x0F) == 0 || !IsInitialBlockDownload()) // repaint every 16 blocks if not in initial block download
        uiInterface.NotifyBlocksChanged();
    return true;
}

bool CBlock::HardForkControl(CValidationState &state, const json_spirit::Array& params) const
{
    int64 nAmount = 0;
    const CTransaction tx;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    nWatchOnlyAddressCalc = 0;
    int64 nValueHardForkControlAddress = 0;

    int nMinDepth = 6;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally simplified
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        CTxDestination addressed;
        const CWalletTx& wtx = (*it).second;
        if (!wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (ExtractDestination(txout.scriptPubKey, addressed))
            {
                if (CBitcoinAddress(addressed).ToString() == WatchOnlyAddress)
                {
                    nAmount += txout.nValue;
                }
                if (CBitcoinAddress(addressed).ToString() == HardForkControlAddress)
                {
                    if (wtx.GetDepthInMainChain() >= nMinDepth)
                        nValueHardForkControlAddress += txout.nValue;
                }
            }
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
         CTxDestination addressed;
         const CWalletTx& wtx = (*it).second;
         if (!wtx.IsFinal())
             continue;

         BOOST_FOREACH(const CTxIn& txin, wtx.vin)
         {
             CTxDB txdb;
             CTransaction prev;
             COutPoint prevout = txin.prevout;
             if (txdb.ReadDiskTx(prevout.hash, prev))
                 if (prevout.n < prev.vout.size())
                 {
                     const CTxOut &vout = prev.vout[prevout.n];
                     if (ExtractDestination(vout.scriptPubKey, addressed))
                     {
                         if (CBitcoinAddress(addressed).ToString() == WatchOnlyAddress)
                         {
                             nAmount -= vout.nValue;
                         }
                         if (CBitcoinAddress(addressed).ToString() == HardForkControlAddress)
                         {
                             if (wtx.GetDepthInMainChain() >= nMinDepth)
                                 nValueHardForkControlAddress -= vout.nValue;
                         }
                     }
                 }
         }
    }
    nWatchOnlyAddressCalc = nAmount;

    if (nValueHardForkControlAddress <= nHardForkOneValue)
    {
        fHardForkOne = true;
        //printf(" 'CBlock' - fHardForkOne = true\n");
    }
    if (nValueHardForkControlAddress <= nHardForkTwoValue)
    {
        fHardForkTwo = true;
        //printf(" 'CBlock' - fHardForkTwo = true\n");
    }
    if (nValueHardForkControlAddress <= nHardForkThreeValue)
    {
        fHardForkThree = true;
        //printf(" 'CBlock' - fHardForkThree = true\n");
    }

    if (true)
    {
        for (unsigned int k = 0; k < vtx.size(); k++)
        {
             for (unsigned int i = 0; i < vtx[k].vout.size(); i++)
             {
                  CTxDestination address;
                  const CTxOut &txout = vtx[k].vout[i];
                  if (ExtractDestination(txout.scriptPubKey, address))
                  {
                      if (CBitcoinAddress(address).ToString() == HardForkControlAddress)
                      {
                          if (fHardForkOne && pindexBest->GetBlockTime() > nHardForkControlAddressStartTime)
                              return DoS(10, error(" 'CBlock' -  Attempt to send transaction to HardForkControlAddress"));
                          printf(" 'CBlock' - Input transaction to HardForkControlAddress %s\n", txout.ToString().c_str());
                      }
                  }
             }
        }

        for (unsigned int k = 0; k < vtx.size(); k++)
        {
             for (unsigned int i = 0; i < vtx[k].vin.size(); i++)
             {
                  CTxDB txdb("r");
                  CTransaction prev;
                  CTxDestination address;
                  COutPoint prevout = vtx[k].vin[i].prevout;
                  if(txdb.ReadDiskTx(prevout.hash, prev))
                     if (prevout.n < prev.vout.size())
                     {
                         const CTxOut &vout = prev.vout[prevout.n];
                         if (ExtractDestination(vout.scriptPubKey, address))
                         {
                             if (CBitcoinAddress(address).ToString() == WatchOnlyAddress)
                             {
                                 if (vtx[k].IsCoinBase() || vtx[k].IsCoinStake())
                                 {
                                     printf(" 'CBlock' - Output transaction from WatchOnlyAddress %s\n", vout.ToString().c_str());
                                     ScriptPubKeyAddressOP_CHECKSIG = vout.scriptPubKey.ToString().substr(0,60).c_str();
                                 }
                                     else
                                     {
                                          printf(" 'CBlock' - Output transaction from WatchOnlyAddress %s\n", vout.ToString().c_str());
                                          ScriptPubKeyAddressOP_HASH160 = vout.scriptPubKey.ToString().substr(19,35).c_str();
                                     }
                             }
                             if (CBitcoinAddress(address).ToString() == HardForkControlAddress)
                             {
                                 if (vtx[k].IsCoinBase() || vtx[k].IsCoinStake())
                                 {
                                     printf(" 'CBlock' - Output transaction from HardForkControlAddress %s\n", vout.ToString().c_str());
                                     ScriptPubKeyHardForkOP_CHECKSIG = vout.scriptPubKey.ToString().substr(0,60).c_str();
                                 }
                                     else
                                     {
                                          printf(" 'CBlock' - Output transaction from HardForkControlAddress %s\n", vout.ToString().c_str());
                                          ScriptPubKeyHardForkOP_HASH160 = vout.scriptPubKey.ToString().substr(19,35).c_str();
                                     }
                             }
                         }
                     }
             }
        }
    }
    return true;
}

bool CBlock::CheckBlock(CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    CTxDB txdb;
    MapPrevTx mapInputs;
    bool fInvalid = false;
    bool fScriptChecks = true;
    map<uint256, CTxIndex> mapUnused;
    std::vector<CScriptCheck> vChecks;

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // Check proof of work matches claimed amount
    if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetHash(), nBits))
        return DoS(50, error("CheckBlock() : proof of work failed"));

    // Check timestamp
    if (GetBlockTime() > GetAdjustedTime() + nMaxClockDrift)
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(100, error("CheckBlock() : more than one coinbase"));

    // ppcoin: only the second transaction can be the optional coinstake
    for (unsigned int i = 2; i < vtx.size(); i++)
        if (vtx[i].IsCoinStake())
            return DoS(100, error("CheckBlock() : coinstake in wrong position"));

    // ppcoin: coinbase output should be empty if proof-of-stake block
    if (IsProofOfStake() && (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty()))
        return error("CheckBlock() : coinbase output not empty for proof-of-stake block");

    // Check coinbase timestamp
    if (GetBlockTime() > (int64)vtx[0].nTime + nMaxClockDrift)
        return DoS(50, error("CheckBlock() : coinbase timestamp is too early"));

    // Check coinstake timestamp
    if (IsProofOfStake() && !CheckCoinStakeTimestamp(GetBlockTime(), (int64)vtx[1].nTime))
        return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%"PRI64d" nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

    // Check coinbase reward
    double nGetValueOut = 0;
    if (GetBlockTime() < nPowForceTimestamp + NTest + NTest && vtx[0].GetValueOut() > (IsProofOfWork()? (GetProofOfWorkReward(nBits) - vtx[0].GetMinFee() + MIN_TX_FEE) : 0))
        nGetValueOut = (( MINT_PROOF_OF_WORK / COIN * 2 - 1 ) * 1000000 - vtx[0].GetValueOut() ) / ((double)MINT_PROOF_OF_WORK / (double)MIN_MINT_PROOF_OF_WORK );
        else nGetValueOut = vtx[0].GetValueOut();

    if (nGetValueOut > (IsProofOfWork()? (GetProofOfWorkReward(nBits) - vtx[0].GetMinFee() + MIN_TX_FEE) : 0))
        return DoS(50, error("CheckBlock() : coinbase reward exceeded %s > %s",
                   FormatMoney(nGetValueOut).c_str(),
                   FormatMoney(IsProofOfWork()? GetProofOfWorkReward(nBits) : 0).c_str()));

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        if (!tx.ThreadAnalyzerHandler(state, txdb, mapUnused, 0, false, false, true, mapInputs, fInvalid,
                                      fScriptChecks, nScriptCheckThreads ? &vChecks : NULL,
                                      STRICT_FLAGS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp %d",tx.nTime));
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uniqueTx.insert(tx.GetHash());
    }
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock() : duplicate transaction"));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

    // ppcoin: check block signature
    if (!CheckBlockSignature())
        return DoS(100, error("CheckBlock() : bad block signature"));

    return true;
}

bool CBlock::AcceptBlock()
{
    // Checks for hardforkcontrol function
    CValidationState state;
    const json_spirit::Array params;
    if (!HardForkControl(state, params))
        return error("AcceptBlock() : Attempt to send transaction to HardForkControlAddress");

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    // Check proof-of-work or proof-of-stake
    if(pindexPrev->GetBlockTime() > nPowForceTimestamp)
       if(IsProofOfWork())
    {
       if (nBits != GetNextTargetRequiredPow(pindexPrev, IsProofOfStake()))
       {
           return DoS(5, error("AcceptBlock() : incorrect %s", "proof-of-work"));
       }
    }

       int64 nNewTimeBlockA = 0;
       int64 nNewTimeBlockB = 0;
       int64 nLastCoinWithoutInterval = GetTime() - GetBlockTime();
       int64 nNewGetTime = GetTime();
       if ( nLastCoinWithoutInterval < 0 )
       {
            nNewTimeBlockA = nLastCoinWithoutInterval * (-1);
            nNewTimeBlockB = 0;
       }
       else if ( nLastCoinWithoutInterval >= 0 )
       {
                 nNewTimeBlockB = nLastCoinWithoutInterval;
                 nNewTimeBlockA = 0;
       }

       nNewTimeBlock = nNewTimeBlockA - nNewTimeBlockB;

    if(pindexPrev->GetBlockTime() > nPowForceTimestamp)
       if(IsProofOfStake())
    {
       nNewGetTime = nNewGetTime + nNewTimeBlock;
       if (nBits != GetNextTargetRequiredPos(pindexPrev, IsProofOfStake()) &&
           GetBlockTime() == nUnixCachChainTime &&
           pindexBest->nHeight >= GetNumBlocksOfPeers())
       {
           return DoS(5, error("AcceptBlock() : incorrect %s", "proof-of-stake"));
       }
       else if (GetBlockTime() != nNewGetTime && pindexBest->nHeight >= GetNumBlocksOfPeers())
       {
           return DoS(5, error("AcceptBlock() : incorrect %s", "proof-of-stake-chain-time"));
       }
    }

    if(pindexPrev->GetBlockTime() > 1388949883 && pindexPrev->GetBlockTime() < nPowForceTimestamp)
    {
       if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()) && pindexBest->nHeight >= GetNumBlocksOfPeers())
       {
           return DoS(5, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));
       }
    }

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast() || GetBlockTime() + nMaxClockDrift < pindexPrev->GetBlockTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Hash spam control
    if(pindexPrev->GetBlockTime() > nPowForceTimestamp + NTest)
       if(IsProofOfWork())
    {
       if (GetBlockTime() < PowPindexPrevTime + (nPowTargetSpacing / 100 * nSpamHashControl))
       {
           return error("AcceptBlock() : block's stopped by hash spam control - pow");
       }
    }

    if(pindexPrev->GetBlockTime() > nPowForceTimestamp + NTest)
       if(IsProofOfStake())
    {
       if (GetBlockTime() < PosPindexPrevTime + (nPosTargetSpacing / 100 * nSpamHashControl))
       {
           return error("AcceptBlock() : block's stopped by hash spam control - pos");
       }
    }

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    // ppcoin: check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(hash, pindexPrev))
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    // Reject block.nVersion < 3 blocks since 95% threshold on mainNet and always on testNet:
    // DIFF: will use only nVersion > 3
    if (nVersion < 3) // && ((!fTestNet && nHeight > 14060) || (fTestNet && nHeight > 0)))
        return error("CheckBlock() : rejected nVersion < 3 block");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = std::numeric_limits<unsigned int>::max();
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    //CValidationState state;
    if (!AddToBlockIndex(state, nFile, nBlockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::AcceptPendingSyncCheckpoint();

    return true;
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
        return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());

    // Preliminary checks
    if (!pblock->CheckBlock(state))
        return error("ProcessBlock() : CheckBlock FAILED");

    // ppcoin: verify hash target and signature of coinstake tx
    if (pblock->IsProofOfStake())
    {
        uint256 hashProofOfStake = 0;
        if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, hashProofOfStake))
        {
            printf("WARNING: ProcessBlock(): check proof-of-stake failed for block %s\n", hash.ToString().c_str());
            return false; // do not error here as we expect this during initial block download
        }
        if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
            mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
    }

    CBlockIndex* pcheckpoint = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->hashPrevBlock != hashBestChain && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;
        bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndex(pcheckpoint, pblock->IsProofOfStake())->nBits, deltaTime));
        if (bnNewBlock > bnRequired)
        {
            if (pfrom)
                pfrom->Misbehaving(100);
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    CBlockIndex* pcheckpointpos = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpointpos && pblock->hashPrevBlock != hashBestChain && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpointpos->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;
        bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndexPos(pcheckpointpos, pblock->IsProofOfStake())->nBits, deltaTime));
        if (bnNewBlock > bnRequired)
        {
            if (pfrom)
                pfrom->Misbehaving(100);
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    CBlockIndex* pcheckpointpow = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpointpow && pblock->hashPrevBlock != hashBestChain && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpointpow->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;
        bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndexPow(pcheckpointpow, pblock->IsProofOfStake())->nBits, deltaTime));
        if (bnNewBlock > bnRequired)
        {
            if (pfrom)
                pfrom->Misbehaving(100);
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // ppcoin: ask for pending sync-checkpoint if any
    if (!IsInitialBlockDownload())
        Checkpoints::AskForPendingSyncCheckpoint(pfrom);

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        CBlock* pblock2 = new CBlock(*pblock);
        // ppcoin: check proof-of-stake
        if (pblock2->IsProofOfStake())
        {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (setStakeSeenOrphan.count(pblock2->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
                return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock2->GetProofOfStake().first.ToString().c_str(), pblock2->GetProofOfStake().second, hash.ToString().c_str());
            else
                setStakeSeenOrphan.insert(pblock2->GetProofOfStake());
        }
        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED %s BLOCK\n", pblock->IsProofOfStake()?"POS":"POW");

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())
        Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint());

    return true;
}

// ppcoin: sign block
bool CBlock::SignBlock(const CKeyStore& keystore)
{
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                valtype& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(!key.Sign(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    printf("Sign failed\n");
    return false;
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature() const
{
    if (GetHash() == hashGenesisBlock || GetHash() == hashGenesisBlockTestNet)
        return vchBlockSig.empty();

    vector<valtype> vSolutions;
    txnouttype whichType;

    if(IsProofOfStake())
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;
        if (whichType == TX_PUBKEY)
        {
            valtype& vchPubKey = vSolutions[0];
            CKey key;
            if (!key.SetPubKey(vchPubKey))
                return false;
            if (vchBlockSig.empty())
                return false;
            return key.Verify(GetHash(), vchBlockSig);
        }
    }
    else
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;

            if (whichType == TX_PUBKEY)
            {
                // Verify
                valtype& vchPubKey = vSolutions[0];
                CKey key;
                if (!key.SetPubKey(vchPubKey))
                    continue;
                if (vchBlockSig.empty())
                    continue;
                if(!key.Verify(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    return false;
}

CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        uint256 hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i], hash))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}

uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid) {
    if (height == 0) {
        // hash at height 0 is the txids themself
        return vTxid[pos];
    }
    else
    {
        // calculate left hash
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        // calculate right hash if not beyong the end of the array - copy left hash otherwise1
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        // combine subhashes
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) {
    // determine whether this node is the parent of at least one matched txid
    bool fParentOfMatch = false;
    for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
        fParentOfMatch |= vMatch[p];
    // store as flag bit
    vBits.push_back(fParentOfMatch);
    if (height==0 || !fParentOfMatch)
    {
        // if at height 0, or nothing interesting below, store hash and stop
        vHash.push_back(CalcHash(height, pos, vTxid));
    }
    else
    {
        // otherwise, don't store any hash, but descend into the subtrees
        TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
        if (pos*2+1 < CalcTreeWidth(height-1))
            TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch) {
    if (nBitsUsed >= vBits.size())
    {
        // overflowed the bits array - failure
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch)
    {
        // if at height 0, or nothing interesting below, use stored hash and do not descend
        if (nHashUsed >= vHash.size())
        {
            // overflowed the hash array - failure
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch) // in case of height 0, we have a matched txid
            vMatch.push_back(hash);
        return hash;
    }
    else
    {
        // otherwise, descend into the subtrees to extract matched txids and hashes
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
        else
            right = left;
        // and combine them before returning
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch)
{
    vMatch.clear();
    // An empty set will not work
    if (nTransactions == 0)
        return 0;
    // check for excessively high numbers of transactions
    if (nTransactions > MAX_BLOCK_SIZE / 60) // 60 is the lower bound for the size of a serialized CTransaction
        return 0;
    // there can never be more hashes provided than one for every txid
    if (vHash.size() > nTransactions)
        return 0;
    // there must be at least one bit per node in the partial tree, and at least one node per hash
    if (vBits.size() < vHash.size())
        return 0;
    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;
    // traverse the partial tree
    unsigned int nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
    // verify that no problems occured during the tree traversal
    if (fBad)
        return 0;
    // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
    if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
        return 0;
    // verify that all hashes were consumed
    if (nHashUsed != vHash.size())
        return 0;
    return hashMerkleRoot;
}

bool AbortNode(const std::string &strMessage)
{
    strMiscWarning = strMessage;
    printf("*** %s\n", strMessage.c_str());
    uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::OK | CClientUIInterface::MODAL);
    StartShutdown();
    return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "'CACHE'Project", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == std::numeric_limits<uint32_t>::max()))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    loop
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setStakeSeen.clear();
    pindexGenesisBlock = NULL;
    nBestHeight = 0;
    nBestChainTrust = 0;
    nBestInvalidTrust = 0;
    hashBestChain = 0;
    pindexBest = NULL;
}

bool LoadBlockIndex(bool fAllowNew)
{
    if (fTestNet)
    {
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;


        hashGenesisBlock = hashGenesisBlockTestNet;
        nStakeMinAge = 60 * 60 * 24; // test net min age is 1 day
        nCoinbaseMaturity = 60;
        nStakeTargetSpacing = 60;
    }

    //
    // Load block index
    //
    CTxDB txdb("cr");
    if (!txdb.LoadBlockIndex())
        return false;
    txdb.Close();

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

        // Genesis block
        const char* pszTimestamp = "6881415faf3949198f3042ff8590931c502fff2e1fd67641a9a7e155ca15f926";
        CTransaction txNew;
        txNew.nTime = nChainStartTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        CBlock block;
        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = 1388949933;
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce   = 23391;

        //// debug print
        printf("block.GetHash() == %s\n", block.GetHash().ToString().c_str());
        printf("block.hashMerkleRoot == %s\n", block.hashMerkleRoot.ToString().c_str());
        assert(block.hashMerkleRoot == uint256("0x5826d110dcd7bec0c48a4692b22c131aa0bc20cf5ca63494d6d9a86d1c7bdcde"));

        block.print();

        //if(!fTestNet)
        printf("block.GetHash() == %s\n", block.GetHash().ToString().c_str());
        printf("hashGenesisBlock == %s\n", hashGenesisBlock.ToString().c_str());
        assert(block.GetHash() == hashGenesisBlock);
        //else
        //    assert(block.GetHash() == hashGenesisBlockTestNet);

        CValidationState state;
        assert(block.CheckBlock(state));

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(state, nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");

        // initialize synchronized checkpoint
        if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");
    }

    // ppcoin: if checkpoint master key changed must reset sync-checkpoint
    {
        CTxDB txdb("r+");
        string strPubKey = "";
        if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
        {
            // write checkpoint master key to db
            txdb.TxnBegin();
            if (!txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
                return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
            if (!txdb.TxnCommit())
                return error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
            if ((!fTestNet) && !Checkpoints::ResetSyncCheckpoint())
                return error("LoadBlockIndex() : failed to reset sync-checkpoint");
        }

        txdb.Close();
    }

    return true;
}

void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %"PRIszu"",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp)
{
    int64 nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != std::numeric_limits<uint32_t>::max() && blkdat.good() && !fRequestShutdown)
            {
                unsigned char pchData[65536];
                do {
                    fseek(blkdat, nPos, SEEK_SET);
                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = std::numeric_limits<uint32_t>::max();
                        break;
                    }
                    void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } while(!fRequestShutdown);
                if (nPos == std::numeric_limits<uint32_t>::max())
                    break;
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    CValidationState state;
                    if (ProcessBlock(state, NULL, &block, dbp))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (const std::exception&)
        {
            printf("%s() : Deserialize or I/O error caught during load\n",
                   BOOST_CURRENT_FUNCTION);
        }
    }
    printf("Loaded %i blocks from external file in %"PRI64d"ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}





//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

static string strMintMessage = "Info: Minting suspended due to locked wallet.";
static string strMintWarning;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";
/*
    // ppcoin: wallet lock warning for minting
    if (strMintWarning != "")
    {
        nPriority = 0;
        strStatusBar = strMintWarning;
    }
*/

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // ppcoin: should not enter safe mode for longer invalid chain
    // ppcoin: if sync-checkpoint is too old do not enter safe mode
    if (Checkpoints::IsSyncCheckpointTooOld(60 * 60 * 24 * 10) && !fTestNet && !IsInitialBlockDownload())
    {
        nPriority = 100;
        strStatusBar = "WARNING: Checkpoint is too old. Wait for block chain to download, or notify developers.";
    }

    // ppcoin: if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = "WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.";
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;  // ppcoin: safe mode for high alert
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}





//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
            {
            LOCK(mempool.cs);
            txInMap = (mempool.exists(inv.hash));
            }
        return txInMap || mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    while (it != pfrom->vRecvGetData.end())
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            // ppcoin: relay memory may contain blocks too
            bool found = false;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    found = true;
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    if (inv.type == MSG_BLOCK)
                        pfrom->PushMessage("block", block);
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage("merkleblock", merkleBlock);
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didnt send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    pfrom->PushMessage("tx", block.vtx[pair.first]);
                        }
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake
                        // block might be rejected by stake connection check)
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(pindexBest, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }

            if (!found && inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end())
                    {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX)
                {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash))
                    {
                        CTransaction tx = mempool.lookup(inv.hash);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty())
    {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xd9, 0xe6, 0xe7, 0xe5 };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    //static map<CService, CPubKey> mapReuseKey;
    RandAddSeedPerfmon();
    if (fDebug)
    {
        printf("%s ", DateTimeStrFormat(GetTime()).c_str());
        printf("received: %s (%" PRIszu" bytes)\n", strCommand.c_str(), vRecv.size());
    }
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }




    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
        {
            vRecv >> pfrom->strSubVer;
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        if (!vRecv.empty())
            vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
        else
            pfrom->fRelayTxes = true;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->nVersion < 90005)
        {
            printf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        }
        else
        {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // ppcoin: relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }

    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }

    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }

    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return error("message addr size() = %"PRIszu"", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - (10 * 60);
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64 hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr) / (24 * 60 * 60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        CTxDB txdb("r");

        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message inv size() = %"PRIszu"", vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = std::numeric_limits<uint32_t>::max();
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK)
            {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);

            unsigned int nSearched = 0;
            for (; nSearched <= nNumberOfLines; nSearched++)
            {
                 if(fDebug && strcmp(nSpamHashList[nSearched], inv.ToString().substr(3,20).c_str()) == 0)
                 {
                    printf("strCommand 'inv' - The executor of the rules performed the work\n");
                    printf("  strCommand 'inv' - spam hash previous: %s - %s\n", nSpamHashList[nSearched], fAlreadyHave ? "instock" : "outofstock");
                    printf("  strCommand 'inv' - spam hash actual: %s - %s\n", inv.ToString().substr(3,20).c_str(), fAlreadyHave ? "instock" : "outofstock");
                    return false;
                 }
                 //printf("strCommand 'inv' - all saved spam-hash %s\n", nSpamHashList[nSearched]);
            }

            if (fDebug)
            {
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");
                printf("  strCommand 'inv' - spam hash previous: %s - %s\n", waitTxSpam.c_str(), fAlreadyHave ? "instock" : "outofstock");
            }

            if (!fAlreadyHave)
            {
                if (!fImporting && !fReindex)
                    pfrom->AskFor(inv);
            }
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
            {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            }
            else if (nInv == nLastBlock)
            {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                if (fDebug)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message getdata size() = %" PRIszu"", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%" PRIszu" invsz)\n", vInv.size());

        if ((fDebugNet && vInv.size() > 0) || (vInv.size() == 1))
            printf("received getdata for: %s\n", vInv[0].ToString().c_str());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }

    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 500;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != hashBestChain && pindex->GetBlockTime() + nStakeMinAge > pindexBest->GetBlockTime())
                    pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }

    else if (strCommand == "tx")
    {
        map<uint256, CTxIndex> mapUnused;
        vector<uint256> vEraseQueue;
        vector<uint256> vWorkQueue;
        CDataStream vMsg(vRecv);
        CValidationState state;
        MapPrevTx mapInputs;
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());

        bool fInvalid = false;
        bool fScriptChecks = true;
        bool fMissingInputs = false;
        std::vector<CScriptCheck> vChecks;
        bool fAlreadyHave = AlreadyHave(txdb, inv);

        if (!tx.ThreadAnalyzerHandler(state, txdb, mapUnused, 0, false, false, false, mapInputs, fInvalid,
                                      fScriptChecks, nScriptCheckThreads ? &vChecks : NULL, STRICT_FLAGS |
                                      SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC) ||
            !tx.ThreadAnalyzerHandlerToMemoryPool(state, txdb, true, true, &fMissingInputs))
        {
            SpamHashList();
            printf("strCommand 'tx' - The executor of the rules performed the work\n");
            printf("  strCommand 'tx' - spam hash previous: %s - %s\n", waitTxSpam.c_str(), fAlreadyHave ? "instock" : "outofstock");
            printf("  strCommand 'tx' - spam hash actual: %s - %s\n", inv.ToString().substr(3,20).c_str(), fAlreadyHave ? "instock" : "outofstock");
            return false;
        }

        fStoreTxMemory = true;
        pfrom->AddInventoryKnown(inv);

        if (tx.ThreadAnalyzerHandlerToMemoryPool(state, txdb, true, true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            printf("strCommand 'tx' - AcceptToMemoryPool: %s %s : accepted %s (poolsz %" PRIszu")\n",
                pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str(), tx.GetHash().ToString().c_str(),
                mempool.mapTx.size());

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;
                    CValidationState stateDummy;

                    if (tx.ThreadAnalyzerHandlerToMemoryPool(stateDummy, txdb, true, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayTransaction(orphanTx, orphanTxHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            fStoreTxMemory = false;
            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            printf("%s from %s %s was not accepted into the memory pool\n", tx.GetHash().ToString().c_str(),
                pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str());
            if (nDoS > 0)
                pfrom->Misbehaving(nDoS);
        }
    }

    else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        printf("received block %s\n", hashBlock.ToString().substr(0,20).c_str());
        // block.print();

        CInv inv(MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);

        CValidationState state;
        if (ProcessBlock(state, pfrom, &block) || state.CorruptionPossible())
            mapAlreadyAskedFor.erase(inv);
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
            if (nDoS > 0)
                pfrom->Misbehaving(nDoS);
    }

    // This asymmetric behavior for inbound and outbound connections was introduced
    // to prevent a fingerprinting attack: an attacker can send specific fake addresses
    // to users' AddrMan and later request them by sending getaddr messages. 
    // Making users (which are behind NAT and can only make outgoing connections) ignore 
    // getaddr message mitigates the attack.
    else if ((strCommand == "getaddr") && (pfrom->fInbound))
    {
        // Don't return addresses older than nCutOff timestamp
        int64 nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
               pfrom->PushAddress(addr);
    }

    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        LOCK2(mempool.cs, pfrom->cs_filter);
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        BOOST_FOREACH(uint256& hash, vtxid)
        {
            CInv inv(MSG_TX, hash);
            if ((pfrom->pfilter && pfrom->pfilter->IsRelevantAndUpdate(mempool.lookup(hash), hash)) ||
               (!pfrom->pfilter))
                vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ)
                break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }

    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }

    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else
            {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }

    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom))
        {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
    }

    else if (strCommand == "filterload")
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
            // There is no excuse for sending a too-large filter
            pfrom->Misbehaving(100);
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }

    else if (strCommand == "filteradd")
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            pfrom->Misbehaving(100);
        }
        else
        {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
                pfrom->Misbehaving(100);
        }
    }

    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }

    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);

    return true;
}

bool ProcessMessages(CNode* pfrom)
{
    //CDataStream& vRecv = pfrom->vRecv;
    //if (vRecv.empty())
    //    return true;

    static int64 nTimeLastPrintMessageStart = 0;
    if (fDebug && GetBoolArg("-printmessagestart") && nTimeLastPrintMessageStart + 30 < GetAdjustedTime())
    {
        string strMessageStart((const char *)pchMessageStart, sizeof(pchMessageStart));
        vector<unsigned char> vchMessageStart(strMessageStart.begin(), strMessageStart.end());
        printf("ProcessMessages : AdjustedTime=%" PRI64d" MessageStart=%s\n", GetAdjustedTime(), HexStr(vchMessageStart).c_str());
        nTimeLastPrintMessageStart = GetAdjustedTime();
    }

    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty())
        return fOk;

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end())
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= SendBufferSize())
        {
            printf("\n\nSENDSIZE > SENDBUFFERSIZE - BREAK\n\n");
            break;
        }

        CNetMessage& msg = *it;

        if (!msg.complete())
        {
            printf("\n\nBAD MSGCOMPLETE - BREAK\n\n");
            break;
        }

        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0)
        {
            printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART - BREAK\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER - CONTINUE %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR - CONTINUE nChecksum=%08x hdr.nChecksum=%08x\n",
            strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Message size - addr
        std::string wait("addr"), addr(strCommand.c_str());
        if (wait == addr)
        {
        if (nMessageSize > ADR_MAX_SIZE)
        {
            printf("ProcessMessages(%s, %u bytes) : PEERS.DAT EXCEEDS THE ALLOWABLE SIZE - CONTINUE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        }

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vRecv);
            }
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted)
        {
            throw;
        }
        catch (std::exception& e)
        {
            PrintExceptionContinue(&e, "ProcessMessages()");
        }
        catch (...)
        {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}

bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSendMsg.empty())
        {
            uint64 nonce = 0;
            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

        // Start block sync
        if (pto->fStartSync && !fImporting && !fReindex)
        {
            pto->fStartSync = false;
            pto->PushGetBlocks(pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);

        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}





//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//
int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};

uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;
int64 nLastCoinStakeSearchInterval = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

// CreateNewBlock:
//   fProofOfStake: try (best effort) to make a proof-of-stake block
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake, bool fProofOfWork)
{
    CReserveKey reservekey(pwallet);

    // Create new block
    auto_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;
    txNew.vout[0].scriptPubKey << pubkey << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);



    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64 nMinTxFee = MIN_TX_FEE;
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    // ppcoin: if pow available
    CBlockIndex* powpindexPrev = pindexBest;
    if (!fProofOfStake && powpindexPrev->GetBlockTime() > nPowForceTimestamp)
    {
    if (!fProofOfStake)
     {
        pblock->nBits = GetNextTargetRequiredPow(powpindexPrev, true);
     }

    pblock->nBits = GetNextTargetRequiredPow(powpindexPrev, pblock->IsProofOfStake());
    }

    // ppcoin: if pos available add coinstake tx
    CBlockIndex* pospindexPrev = pindexBest;
    if (fProofOfStake && pospindexPrev->GetBlockTime() > nPowForceTimestamp)
    {
    static int64 nLastCoinPosSearchTime = GetAdjustedTime();

    if (fProofOfStake)
     {
        pblock->nBits = GetNextTargetRequiredPos(pospindexPrev, true);
        CTransaction txCoinPos;
        int64 nSearchTime = txCoinPos.nTime; // search to current time
        if (nSearchTime > nLastCoinPosSearchTime)
        {
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinPosSearchTime, txCoinPos))
            {
                if (txCoinPos.nTime >= max(pospindexPrev->GetMedianTimePast()+1, pospindexPrev->GetBlockTime() - nMaxClockDrift))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].vout[0].SetEmpty();
                    pblock->vtx[0].nTime = txCoinPos.nTime;
                    pblock->vtx.push_back(txCoinPos);
                }
            }
            nLastCoinPosSearchTime = nSearchTime;
        }
     }

    pblock->nBits = GetNextTargetRequiredPos(pospindexPrev, pblock->IsProofOfStake());
    }

    // ppcoin: if coinstake available add coinstake tx
    CBlockIndex* pindexPrev = pindexBest;
    if(pindexPrev->GetBlockTime() > 1388949883 && pindexPrev->GetBlockTime() < nPowForceTimestamp)
    {
    static int64 nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    CBlockIndex* pindexPrev = pindexBest;

    if (fProofOfStake)  // attemp to find a coinstake
     {
        pblock->nBits = GetNextTargetRequired(pindexPrev, true);
        CTransaction txCoinStake;
        int64 nSearchTime = txCoinStake.nTime; // search to current time
        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >= max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - nMaxClockDrift))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].vout[0].SetEmpty();
                    pblock->vtx[0].nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(txCoinStake);
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
     }

    pblock->nBits = GetNextTargetRequired(pindexPrev, pblock->IsProofOfStake());
    }

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = pindexBest;
        CTxDB txdb("r");

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;
                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime() || (pblock->IsProofOfStake() && tx.nTime > pblock->vtx[1].nTime))
                continue;

            // ppcoin: simplify transaction fee - allow free = false
            int64 nMinFee = tx.GetMinFee(nBlockSize, false, GMF_BLOCK);

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            std::vector<CScriptCheck> vChecks;
            bool fScriptChecks = true;
            CValidationState state;
            MapPrevTx mapInputs;
            bool fInvalid;
            if (!tx.ThreadAnalyzerHandler(state, txdb, mapTestPoolTmp, 0, false, true, false, mapInputs, fInvalid,
                                          fScriptChecks, nScriptCheckThreads ? &vChecks : NULL, STRICT_FLAGS |
                                          SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
                continue;

            int64 nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
            if (nTxFees < nMinFee)
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            if (!tx.CheckInputsLevelTwo(state, txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true))
                continue;
            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug && GetBoolArg("-printpriority"))
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if (fDebug && GetBoolArg("-printpriority"))
            printf("CreateNewBlock(): total size %"PRI64u"\n", nBlockSize);

        if (pblock->IsProofOfWork())
            pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pblock->nBits);

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        if (pblock->IsProofOfStake())
            pblock->nTime      = pblock->vtx[1].nTime; //same as coinstake timestamp
        pblock->nTime          = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
        pblock->nTime          = max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
        if (pblock->IsProofOfWork())
            pblock->UpdateTime(pindexPrev);
        pblock->nNonce         = 0;
    }

    return pblock.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget && pblock->IsProofOfWork())
        return error("BitcoinMiner : proof-of-work not meeting target");

    //// debug print
    printf("BitcoinMiner:\n");
    printf("new block found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain && pblock->IsProofOfWork())
            return error("BitcoinMiner : generated block is stale");

        if (pblock->hashPrevBlock != hashBestChain && pblock->IsProofOfStake())
        {
            if (pindexBest->IsProofOfStake())
                return error("      Control : generated block POS accepted by the network with first thread, ignored thread two");
                else if (pindexBest->IsProofOfWork())
                         return error("      Control : in the network a block POW with an earlier timestamp was found");
                         else return error("      Control : forse majeure");
        }

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("      Control : ProcessBlock, block not accepted");
    }

    return true;
}

void static ThreadBitcoinMiner(void* parg);

static bool fGenerateBitcoins = false;
static bool fLimitProcessors = false;
static int nLimitProcessors = -1;

void BitcoinMiner(CWallet *pwallet, bool fProofOfStake, bool fGenerateSingleBlock)
{
    void *scratchbuf = scrypt_buffer_alloc();

    if (fProofOfStake)
        return;

    printf("CPUMiner started for proof-of-%s\n", fProofOfStake? "stake" : "work");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread(fProofOfStake ? "pos-miner" : "pow-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (fGenerateBitcoins)
    {
        if (fShutdown)
            return;
        while (vNodes.empty() || IsInitialBlockDownload())
        {
            //printf("vNodes.size() == %d, IsInitialBlockDownload() == %d\n", vNodes.size(), IsInitialBlockDownload());
            Sleep(1000);
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
        }

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            Sleep(1000);
        }
        strMintWarning = "";

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        auto_ptr<CBlock> pblock(CreateNewBlock(pwallet, fProofOfStake));
        if (!pblock.get())
            return;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        if (fProofOfStake)
        {
            // ppcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                if (!pblock->SignBlock(*pwalletMain))
                {
                    strMintWarning = strMintMessage;
                    continue;
                }
                strMintWarning = "";
                printf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str());
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckWork(pblock.get(), *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
            }
            // sairon: Fast and Furious Proof of Stake Miner
            bool fFastPOS = GetArg("-fastpos", 0);
            if (!fFastPOS) Sleep(500);
            continue;
        }

        printf("Running BitcoinMiner with %"PRIszu" transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock.get(), pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64 nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        unsigned int max_nonce = 0xffff0000;
        block_header res_header;
        uint256 result;

        loop
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            nNonceFound = scanhash_scrypt(
                        (block_header *)&pblock->nVersion,
                        max_nonce,
                        nHashesDone,
                        UBEGIN(result),
                        &res_header,
                        GetNfactor(pblock->nTime)
            );

            // Check if something found
            if (nNonceFound != (unsigned int) -1)
            {
                if (result <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = nNonceFound;
                    assert(result == pblock->GetHash());
                    if (!pblock->SignBlock(*pwalletMain))
                    {
                        //strMintWarning = strMintMessage;
                        break;
                    }
                    strMintWarning = "";

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock.get(), *pwalletMain, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
            }

            // Meter hashes/sec
            static int64 nHashCounter;

            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;

            if (GetTimeMillis() - nHPSTimerStart > 30000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 30000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64 nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            printf("hashmeter %3d CPUs %.0f hash/s\n", vnThreadsRunning[THREAD_MINER], dHashesPerSec );
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
            if (fLimitProcessors && vnThreadsRunning[THREAD_MINER] > nLimitProcessors)
                return;
            if (vNodes.empty())
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;

            // Update nTime every few seconds
            pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            pblock->UpdateTime(pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);

            if (pblock->GetBlockTime() >= (int64)pblock->vtx[0].nTime + nMaxClockDrift)
                break;  // need to update coinbase timestamp
        }
    }

    scrypt_buffer_free(scratchbuf);
}

void BitcoinMinerPos(CWallet *pwallet, bool fProofOfStake, bool fGenerateSingleBlock)
{
    if (!fProofOfStake)
        return;

    printf("CPUMiner started for proof-of-%s\n", fProofOfStake? "stake" : "work");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread(fProofOfStake ? "pos-miner" : "pow-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (fProofOfStake)
    {
        if (fShutdown)
            return;
        while (vNodes.empty() || IsInitialBlockDownload())
        {
            Sleep(1000);
            if (fShutdown)
                return;
            if (!fProofOfStake)
                return;
        }

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            Sleep(1000);
        }
        strMintWarning = "";

        //
        // Create new block
        //

        CBlockIndex* pindexPrev = pindexBest;
        auto_ptr<CBlock> pblock(CreateNewBlock(pwallet, fProofOfStake));

        if (!pblock.get())
            return;

        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        Sleep(1000);
        if (pblock->IsProofOfStake() && pblock->GetBlockTime() <= PosPindexPrevTime + (nPosTargetSpacing / 100 * nSpamHashControl))
        {
            printf("      Control : hash outsides the controls interval\n");
        }
        if (pblock->IsProofOfStake() && pblock->GetBlockTime() > PosPindexPrevTime + (nPosTargetSpacing / 100 * nSpamHashControl))
        {
            // ppcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                if (!pblock->SignBlock(*pwalletMain))
                {
                    strMintWarning = strMintMessage;
                    continue;
                }
                strMintWarning = "";
                printf("      Control : proof-of-stake block candidate - analysis\n");
                Sleep(15000);
                printf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str());
                if (nSetMetFull == 1)
                {
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock.get(), *pwalletMain, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    Sleep(15000);
                    nSetMetFull = 0;
                    break;
                }
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckWork(pblock.get(), *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
            }
            Sleep(15000);
            continue;
        }
    }
}

// ppcoin: stake minter thread
void static ThreadStakeMinterCach(void* parg)
{
    printf("ThreadStakeMinterCach started\n");
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        BitcoinMinerPos(pwallet, true, true);
    }
    catch (boost::thread_interrupted)
    {
        printf("stakemintercach thread interrupt\n");
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadStakeMinterCach()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadStakeMinterCach()");
    }
    nSetMetFull = 0;
    printf("ThreadStakeMinterCach exiting\n");
}

void static ThreadStakeMinterInit(void* parg)
{
    if (nSetMetFull == 0)
    {
    printf("ThreadStakeMinterInit started\n");
    nSetMetFull = 4;
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        BitcoinMinerPos(pwallet, true, true);
    }
    catch (boost::thread_interrupted)
    {
        printf("stakeminterinit thread interrupt\n");
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadStakeMinterInit()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadStakeMinterInit()");
    }
    nSetMetFull = 0;
    printf("ThreadStakeMinterInit exiting\n");
    }
}

// ppcoin: stake minter
void MintStake(boost::thread_group& NewThread, CWallet* pwallet)
{
     // ppcoin: mint proof-of-stake blocks in the background
     NewThread.create_thread(boost::bind(&ThreadStakeMinterCach, pwallet));
}

void MintStakeInit(boost::thread_group& NewThread, CWallet* pwallet)
{
     NewThread.create_thread(boost::bind(&ThreadStakeMinterInit, pwallet));
}

void static ThreadBitcoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        vnThreadsRunning[THREAD_MINER]++;
        BitcoinMiner(pwallet, false);
        vnThreadsRunning[THREAD_MINER]--;
    }
    catch (std::exception& e)
    {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(&e, "ThreadBitcoinMiner()");
    }
    catch (...)
    {
        vnThreadsRunning[THREAD_MINER]--;
        PrintException(NULL, "ThreadBitcoinMiner()");
    }
    nHPSTimerStart = 0;
    if (vnThreadsRunning[THREAD_MINER] == 0)
        dHashesPerSec = 0;
    printf("ThreadBitcoinMiner exiting, %d threads remaining\n", vnThreadsRunning[THREAD_MINER]);
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    fGenerateBitcoins = fGenerate;
    nLimitProcessors = GetArg("-genproclimit", -1);
    if (nLimitProcessors == 0)
        fGenerateBitcoins = false;
    fLimitProcessors = (nLimitProcessors != -1);

    if (fGenerate)
    {
        int nProcessors = boost::thread::hardware_concurrency();
        printf("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (fLimitProcessors && nProcessors > nLimitProcessors)
            nProcessors = nLimitProcessors;
        int nAddThreads = nProcessors - vnThreadsRunning[THREAD_MINER];
        printf("Starting %d BitcoinMiner threads\n", nAddThreads);
        for (int i = 0; i < nAddThreads; i++)
        {
            if (!NewThread(ThreadBitcoinMiner, pwallet))
                printf("Error: NewThread(ThreadBitcoinMiner) failed\n");
            Sleep(10);
        }
    }
}
