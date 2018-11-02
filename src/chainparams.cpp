// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// Thanks and Credits for Technologies found in Bdcc: Bitcoin, Novacoin, Blackcoin, Bitmessage, Shadowcoin, Cryptonote
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"


// miner's coin base reward
int64_t CChainParams::GetProofOfWorkReward(int nHeight, int64_t nFees) const
{
    
    int64_t nSubsidy = 0 * COIN;
 
    if(pindexBest->nHeight == 1)
    {
        nSubsidy = 680000000 * COIN;   //680M Premine
    }
        else
    {
        nSubsidy = 0 * COIN;
    }
    
    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(nSubsidy).c_str(), nSubsidy);
    
    return nSubsidy + nFees;
};

// miner's coin stake reward based on coin age spent (coin-days)
int64_t CChainParams::GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees) const
{
    
    int64_t nSubsidy = nCoinAge * COIN_YEAR_REWARD * 33 / (365 * 33 + 8);  //10% interest
	

    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    
    return nSubsidy + nFees;
}

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Convert the pnSeeds6 array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, unsigned int *data, unsigned int count, int port)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in_addr ip;
        memcpy(&ip, &pnSeed[i], sizeof(ip));
        CAddress addr(CService(ip, Params().GetDefaultPort()));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe4;
        pchMessageStart[2] = 0xc3;
        pchMessageStart[3] = 0x12;
        
        vAlertPubKey = ParseHex("");
        nDefaultPort = 40580;
        nRPCPort = 40570;
        
        nFirstPosv2Block = 2000;
        
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20); // "standard" scrypt target limit for proof of work, results with 0,000244140625 proof-of-work difficulty
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 20);
        bnProofOfStakeLimitV2 = CBigNum(~uint256(0) >> 48);
        
        const char* pszTimestamp = "BDC-Currency Blockchain - The Beginning 9/17";
        CTransaction txNew;
        txNew.nTime = GENESIS_BLOCK_TIME;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = GENESIS_BLOCK_TIME;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 204611;

        hashGenesisBlock = genesis.GetHash();
        
        assert(hashGenesisBlock == uint256("0x0000099f0d0835bace97f7913f3f7ad2b60c6835c0ba51c85e08179d8c8430ef"));
        assert(genesis.hashMerkleRoot == uint256("0x2ecb9b9f866f29aeec0c87a04ef1483847cd0bd179912466fccd17bfaeba6d96"));
        
        vSeeds.push_back(CDNSSeedData("seed1", "195.181.240.110"));
        vSeeds.push_back(CDNSSeedData("seed2", "80.209.226.140"));
        vSeeds.push_back(CDNSSeedData("seed3", "80.209.237.232"));
        vSeeds.push_back(CDNSSeedData("seed4", "80.209.237.220"));
        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(26)                    .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5)                   .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = list_of(155)                   .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);
        
        nLastPOWBlock = 5000;
        //nLastFairLaunchBlock = 0;
        //nDistributionFund = 0;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const std::vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    std::vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;

//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xed;
        pchMessageStart[1] = 0xc6;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0x20;
        
        nFirstPosv2Block = 200;
        
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 20);
        bnProofOfStakeLimitV2 = CBigNum(~uint256(0) >> 16);
        
        vAlertPubKey = ParseHex("");
        nDefaultPort = 40581;
        nRPCPort = 40571;
        strDataDir = "testnet";

        //genesis.nBits  = bnProofOfWorkLimit.GetCompact();
		genesis.nBits  = 0x1e0fffff; //504365055 Decimal Number
		genesis.nTime    = GENESIS_BLOCK_TIME;
        genesis.nNonce = 204611;
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000099f0d0835bace97f7913f3f7ad2b60c6835c0ba51c85e08179d8c8430ef"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(85)                   .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196)                   .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = list_of(239)                   .convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        
        //convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;




static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

const CChainParams &TestNetParams() {
    return testNetParams;
}

const CChainParams &MainNetParams() {
    return mainParams;
}

void SelectParams(CChainParams::Network network)
{
    switch (network)
    {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        
        default:
            assert(false && "Unimplemented network");
            return;
    };
};

bool SelectParamsFromCommandLine()
{
    bool fTestNet = GetBoolArg("-testnet", false);

    
    if (fTestNet)
    {
        SelectParams(CChainParams::TESTNET);
    } else
    {
        SelectParams(CChainParams::MAIN);
    };
    
    return true;
}
