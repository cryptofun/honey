// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"
#include "chainparams.h"
#include "main.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "miner.h"
#include "kernel.h"

#include <boost/assign/list_of.hpp>


// Key used by getwork/getblocktemplate miners.
// Allocated in InitRPCMining, free'd in ShutdownRPCMining
static CReserveKey* pMiningKey = NULL;

void InitRPCMining()
{
    if (!pwalletMain)
        return;

    // getwork/getblocktemplate mining rewards paid here:
    pMiningKey = new CReserveKey(pwalletMain);
}

void ShutdownRPCMining()
{
    if (!pMiningKey)
        return;

    delete pMiningKey; pMiningKey = NULL;
}

json_spirit::Value getsubsidy(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    return (uint64_t)GetProofOfWorkReward(0);
}

json_spirit::Value getstakesubsidy(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getstakesubsidy <hex string>\n"
            "Returns proof-of-stake subsidy value for the specified coinstake.");

    RPCTypeCheck(params, boost::assign::list_of(json_spirit::str_type));

    std::vector<unsigned char> txData(ParseHex(params[0].get_str()));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    uint64_t nCoinAge;
    CTxDB txdb("r");
    if (!tx.GetCoinAge(txdb, pindexBest, nCoinAge))
        throw JSONRPCError(RPC_MISC_ERROR, "GetCoinAge failed");

    return (uint64_t)GetProofOfStakeReward(pindexBest, nCoinAge, 0);
}

json_spirit::Value getmininginfo(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    uint64_t nWeight = 0;
    if (pwalletMain)
        nWeight = pwalletMain->GetStakeWeight();

    json_spirit::Object obj, diff, weight;
    obj.push_back(json_spirit::Pair("blocks",        (int)nBestHeight));
    obj.push_back(json_spirit::Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(json_spirit::Pair("currentblocktx",(uint64_t)nLastBlockTx));

    diff.push_back(json_spirit::Pair("proof-of-work",        GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    diff.push_back(json_spirit::Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    obj.push_back(json_spirit::Pair("difficulty",    diff));

    obj.push_back(json_spirit::Pair("blockvalue",    (uint64_t)GetProofOfWorkReward(0)));
    obj.push_back(json_spirit::Pair("netmhashps",     GetPoWMHashPS()));
    obj.push_back(json_spirit::Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(json_spirit::Pair("errors",        GetWarnings("statusbar")));
    obj.push_back(json_spirit::Pair("pooledtx",      (uint64_t)mempool.size()));

    weight.push_back(json_spirit::Pair("minimum",    (uint64_t)nWeight));
    weight.push_back(json_spirit::Pair("maximum",    (uint64_t)0));
    weight.push_back(json_spirit::Pair("combined",  (uint64_t)nWeight));
    obj.push_back(json_spirit::Pair("stakeweight", weight));

    obj.push_back(json_spirit::Pair("testnet",       TestNet()));
    return obj;
}

json_spirit::Value getstakinginfo(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getstakinginfo\n"
            "Returns an object containing staking-related information.");

    uint64_t nWeight = 0;
    if (pwalletMain)
        nWeight = pwalletMain->GetStakeWeight();

    uint64_t nNetworkWeight = GetPoSKernelPS();
    bool staking = nLastCoinStakeSearchInterval && nWeight;
    uint64_t nExpectedTime = staking ? (GetTargetSpacing(nBestHeight) * nNetworkWeight / nWeight) : 0;

    json_spirit::Object obj;

    obj.push_back(json_spirit::Pair("enabled", GetBoolArg("-staking", true)));
    obj.push_back(json_spirit::Pair("staking", staking));
    obj.push_back(json_spirit::Pair("errors", GetWarnings("statusbar")));

    obj.push_back(json_spirit::Pair("currentblocksize", (uint64_t)nLastBlockSize));
    obj.push_back(json_spirit::Pair("currentblocktx", (uint64_t)nLastBlockTx));
    obj.push_back(json_spirit::Pair("pooledtx", (uint64_t)mempool.size()));

    obj.push_back(json_spirit::Pair("difficulty", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(json_spirit::Pair("search-interval", (int)nLastCoinStakeSearchInterval));

    obj.push_back(json_spirit::Pair("weight", (uint64_t)nWeight));
    obj.push_back(json_spirit::Pair("netstakeweight", (uint64_t)nNetworkWeight));

    obj.push_back(json_spirit::Pair("expectedtime", nExpectedTime));

    return obj;
}

json_spirit::Value checkkernel(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "checkkernel [{\"txid\":txid,\"vout\":n},...] [createblocktemplate=false]\n"
            "Check if one of given inputs is a kernel input at the moment.\n"
        );

    RPCTypeCheck(params, boost::assign::list_of(json_spirit::array_type)(json_spirit::bool_type));

    json_spirit::Array inputs = params[0].get_array();
    bool fCreateBlockTemplate = params.size() > 1 ? params[1].get_bool() : false;

    if (vNodes.empty())
        throw JSONRPCError(-9, "Honey is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Honey is downloading blocks...");

    COutPoint kernel;
    CBlockIndex* pindexPrev = pindexBest;
    unsigned int nBits = GetNextTargetRequired(pindexPrev, true);
    int64_t nTime = GetAdjustedTime();
    nTime &= ~STAKE_TIMESTAMP_MASK;

    BOOST_FOREACH(json_spirit::Value& input, inputs)
    {
        const json_spirit::Object& o = input.get_obj();

        const json_spirit::Value& txid_v = json_spirit::find_value(o, "txid");
        if (txid_v.type() != json_spirit::str_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing txid key");
        std::string txid = txid_v.get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        const json_spirit::Value& vout_v = json_spirit::find_value(o, "vout");
        if (vout_v.type() != json_spirit::int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint cInput(uint256(txid), nOutput);
        if (CheckKernel(pindexPrev, nBits, nTime, cInput))
        {
            kernel = cInput;
            break;
        }
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("found", !kernel.IsNull()));

    if (kernel.IsNull())
        return result;

    json_spirit::Object oKernel;
    oKernel.push_back(json_spirit::Pair("txid", kernel.hash.GetHex()));
    oKernel.push_back(json_spirit::Pair("vout", (int64_t)kernel.n));
    oKernel.push_back(json_spirit::Pair("time", nTime));
    result.push_back(json_spirit::Pair("kernel", oKernel));

    if (!fCreateBlockTemplate)
        return result;

    int64_t nFees;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(*pMiningKey, true, &nFees));

    pblock->nTime = pblock->vtx[0].nTime = nTime;

    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << *pblock;

    result.push_back(json_spirit::Pair("blocktemplate", HexStr(ss.begin(), ss.end())));
    result.push_back(json_spirit::Pair("blocktemplatefees", nFees));

    CPubKey pubkey;
    if (!pMiningKey->GetReservedKey(pubkey))
        throw JSONRPCError(RPC_MISC_ERROR, "GetReservedKey failed");

    result.push_back(json_spirit::Pair("blocktemplatesignkey", HexStr(pubkey)));

    return result;
}

json_spirit::Value getworkex(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );

    if (vNodes.empty())
        throw JSONRPCError(-9, "Honey is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Honey is downloading blocks...");

    if (pindexBest->nHeight >= Params().LastPOWBlock())
        throw JSONRPCError(RPC_MISC_ERROR, "No more PoW blocks");

    typedef std::map<uint256, std::pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static std::vector<CBlock*> vNewBlock;

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            pindexPrev = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(*pMiningKey);
            if (!pblock)
                throw JSONRPCError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->nTime = std::max(pindexPrev->GetPastTimeLimit()+1, GetAdjustedTime());
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = std::make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = uint256().SetCompact(pblock->nBits);

        CTransaction coinbaseTx = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        json_spirit::Object result;
        result.push_back(json_spirit::Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result.push_back(json_spirit::Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

        json_spirit::Array merkle_arr;

        BOOST_FOREACH(uint256 merkleh, merkle) {
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result.push_back(json_spirit::Pair("merkle", merkle_arr));


        return result;
    }
    else
    {
        // Parse parameters
        std::vector<unsigned char> vchData = ParseHex(params[0].get_str());
        std::vector<unsigned char> coinbase;

        if(params.size() == 2)
            coinbase = ParseHex(params[1].get_str());

        if (vchData.size() != 128)
            throw JSONRPCError(-8, "Invalid parameter");

        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;

        if(coinbase.size() == 0)
            pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        else
            CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION) >> pblock->vtx[0]; // FIXME - HACK!

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        assert(pwalletMain != NULL);
        return CheckWork(pblock, *pwalletMain, *pMiningKey);
    }
}


json_spirit::Value getwork(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Honey is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Honey is downloading blocks...");

    if (pindexBest->nHeight >= Params().LastPOWBlock())
        throw JSONRPCError(RPC_MISC_ERROR, "No more PoW blocks");

    typedef std::map<uint256, std::pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static std::vector<CBlock*> vNewBlock;

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(*pMiningKey);
            if (!pblock)
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlock.push_back(pblock);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = std::make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = uint256().SetCompact(pblock->nBits);

        json_spirit::Object result;
        result.push_back(json_spirit::Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(json_spirit::Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(json_spirit::Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(json_spirit::Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    }
    else
    {
        // Parse parameters
        std::vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 128)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        assert(pwalletMain != NULL);
        return CheckWork(pblock, *pwalletMain, *pMiningKey);
    }
}


json_spirit::Value getblocktemplate(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.size() > 0)
    {
        const json_spirit::Object& oparam = params[0].get_obj();
        const json_spirit::Value& modeval = json_spirit::find_value(oparam, "mode");
        if (modeval.type() == json_spirit::str_type)
            strMode = modeval.get_str();
        else if (modeval.type() == json_spirit::null_type)
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Honey is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Honey is downloading blocks...");

    if (pindexBest->nHeight >= Params().LastPOWBlock())
        throw JSONRPCError(RPC_MISC_ERROR, "No more PoW blocks");

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlock* pblock;
    if (pindexPrev != pindexBest ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblock)
        {
            delete pblock;
            pblock = NULL;
        }
        pblock = CreateNewBlock(*pMiningKey);
        if (!pblock)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    json_spirit::Array transactions;
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    BOOST_FOREACH (CTransaction& tx, pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        json_spirit::Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(json_spirit::Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(json_spirit::Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(json_spirit::Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            json_spirit::Array deps;
            BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
            {
                if (setTxIndex.count(inp.first))
                    deps.push_back(setTxIndex[inp.first]);
            }
            entry.push_back(json_spirit::Pair("depends", deps));

            int64_t nSigOps = GetLegacySigOpCount(tx);
            nSigOps += GetP2SHSigOpCount(tx, mapInputs);
            entry.push_back(json_spirit::Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
    }

    json_spirit::Object aux;
    aux.push_back(json_spirit::Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = uint256().SetCompact(pblock->nBits);

    static json_spirit::Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    json_spirit::Object result;
    result.push_back(json_spirit::Pair("version", pblock->nVersion));
    result.push_back(json_spirit::Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(json_spirit::Pair("transactions", transactions));
    result.push_back(json_spirit::Pair("coinbaseaux", aux));
    result.push_back(json_spirit::Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(json_spirit::Pair("target", hashTarget.GetHex()));
    result.push_back(json_spirit::Pair("mintime", (int64_t)pindexPrev->GetPastTimeLimit()+1));
    result.push_back(json_spirit::Pair("mutable", aMutable));
    result.push_back(json_spirit::Pair("noncerange", "00000000ffffffff"));
    result.push_back(json_spirit::Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(json_spirit::Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(json_spirit::Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(json_spirit::Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(json_spirit::Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
}

json_spirit::Value submitblock(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::vector<unsigned char> blockData(ParseHex(params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    try {
        ssBlock >> block;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (params.size() > 1)
    {
        const json_spirit::Object& oparam = params[1].get_obj();

        const json_spirit::Value& coinstake_v = json_spirit::find_value(oparam, "coinstake");
        if (coinstake_v.type() == json_spirit::str_type)
        {
            std::vector<unsigned char> txData(ParseHex(coinstake_v.get_str()));
            CDataStream ssTx(txData, SER_NETWORK, PROTOCOL_VERSION);
            CTransaction txCoinStake;
            try {
                ssTx >> txCoinStake;
            }
            catch (std::exception &e) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Coinstake decode failed");
            }

            block.vtx.insert(block.vtx.begin() + 1, txCoinStake);
            block.hashMerkleRoot = block.BuildMerkleTree();

            CPubKey pubkey;
            if (!pMiningKey->GetReservedKey(pubkey))
                throw JSONRPCError(RPC_MISC_ERROR, "GetReservedKey failed");

            CKey key;
            if (!pwalletMain->GetKey(pubkey.GetID(), key))
                throw JSONRPCError(RPC_MISC_ERROR, "GetKey failed");

            if (!key.Sign(block.GetHash(), block.vchBlockSig))
                throw JSONRPCError(RPC_MISC_ERROR, "Sign failed");
        }
    }

    bool fAccepted = ProcessBlock(NULL, &block);
    if (!fAccepted)
        return "rejected";

    return json_spirit::Value::null;
}
