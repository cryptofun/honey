// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 500;

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
         ( 0,      uint256("0x000000a70d759b452f04f26c30ab96b90d5b56e736c60e3551d1e00df1280549") )
         ( 10,     uint256("0x0000005990b69097e29df4d26bad6ac45efebaa3cfc1be2ec0009334265ec36e") )
         ( 100,    uint256("0xcbaa196e12b87623b3dec3a8c3ca85e8735165318ea833c267e2f7f0c6be9705") )
         ( 1000,   uint256("0x0000000000cd4014b8bfbeb1e1b52a6bab1e0ba3759359da8ba61e3d9b04e800") )
         ( 2500,   uint256("0x0000000001023fa817fb21e85972cbfc40db889a912b7622ce6dca57bc3c733d") )
         ( 6000,   uint256("0x00000000018df8aa7cfc89d08736654436b8ced501f1042123e8d73ec70ad4ee") )
         ( 10000,  uint256("0x0053513275ed148713c6cb6948eb8d7d16c8c667546cfb25aacbce15487352ff") )
         ( 17000,  uint256("0x000000000051ddfc7be4084f5cb1e2aede4ddce148230b502cb0ddda3389a500") )
         ( 20700,  uint256("0x000000000004b0ec85840045d51c0235df72d5a1a8d3f61228e73765b90fbec5") )
         ( 21153,  uint256("0x0000000000009dafcaa8338d3ee32aa2f5bde2e8cc98e911ed521f9585941bfb") )
         ( 21350,  uint256("0x00000000004243c22fb6ceab0e391b31d9eba661959233df300ecc1f48b5fab7") )
         ( 27030,  uint256("0x000000000026a3b09a4fea2244a56e1a2f613bbaab26fd99bd782f5cf3ea7aa1") )
         ( 27041,  uint256("0x000000000036f5073680c339791358a80ab2ad73b67af4429aad9b427fbd756e") )
         ( 158309, uint256("0x0000000001a4fa12e78a5b49f5e97dc0dd5e285d86a9441b59bab5df831197b6") );
         ( 172078, uint256("0x000000000006fc9ccb1aa79828ddc10683096071d3b9005476a5dbb41e3de613") );

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
            return 0;
        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();

        if (nHeight <= pindexSync->nHeight)
            return false;
        return true;
    }
}
