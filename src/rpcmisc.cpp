// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <init.h>
#include <main.h>
#include <net.h>
#include <netbase.h>
#include <rpcserver.h>
#include <timedata.h>
#include <util.h>
#ifdef ENABLE_WALLET
#include <wallet.h>
#include <walletdb.h>
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/variant.hpp>

#include <json/json_spirit_utils.h>
#include <json/json_spirit_value.h>


json_spirit::Value getinfo(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    json_spirit::Object obj, diff;
    obj.push_back(json_spirit::Pair("version",       FormatFullVersion()));
    obj.push_back(json_spirit::Pair("protocolversion",(int)PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(json_spirit::Pair("walletversion", pwalletMain->GetVersion()));
        obj.push_back(json_spirit::Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
        obj.push_back(json_spirit::Pair("newmint",       ValueFromAmount(pwalletMain->GetNewMint())));
        obj.push_back(json_spirit::Pair("stake",         ValueFromAmount(pwalletMain->GetStake())));
    }
#endif
    obj.push_back(json_spirit::Pair("blocks",        (int)nBestHeight));
    obj.push_back(json_spirit::Pair("timeoffset",    (int64_t)GetTimeOffset()));
    obj.push_back(json_spirit::Pair("moneysupply",   ValueFromAmount(pindexBest->nMoneySupply)));
    obj.push_back(json_spirit::Pair("connections",   (int)vNodes.size()));
    obj.push_back(json_spirit::Pair("proxy",         (proxy.IsValid() ? proxy.ToStringIPPort() : std::string())));
    obj.push_back(json_spirit::Pair("ip",            GetLocalAddress(NULL).ToStringIP()));

    diff.push_back(json_spirit::Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(json_spirit::Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(json_spirit::Pair("difficulty",    diff));

    obj.push_back(json_spirit::Pair("testnet",       TestNet()));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(json_spirit::Pair("keypoololdest", (int64_t)pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(json_spirit::Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    obj.push_back(json_spirit::Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    obj.push_back(json_spirit::Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(json_spirit::Pair("unlocked_until", (int64_t)nWalletUnlockTime));
#endif
    obj.push_back(json_spirit::Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<json_spirit::Object>
{
public:
    json_spirit::Object operator()(const CNoDestination &dest) const { return json_spirit::Object(); }

    json_spirit::Object operator()(const CKeyID &keyID) const {
        json_spirit::Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(json_spirit::Pair("isscript", false));
        obj.push_back(json_spirit::Pair("pubkey", HexStr(vchPubKey)));
        obj.push_back(json_spirit::Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }

    json_spirit::Object operator()(const CScriptID &scriptID) const {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("isscript", true));
        CScript subscript;
        pwalletMain->GetCScript(scriptID, subscript);
        std::vector<CTxDestination> addresses;
        txnouttype whichType;
        int nRequired;
        ExtractDestinations(subscript, whichType, addresses, nRequired);
        obj.push_back(json_spirit::Pair("script", GetTxnOutputType(whichType)));
        obj.push_back(json_spirit::Pair("hex", HexStr(subscript.begin(), subscript.end())));
        json_spirit::Array a;
        BOOST_FOREACH(const CTxDestination& addr, addresses)
            a.push_back(CHoneyAddress(addr).ToString());
        obj.push_back(json_spirit::Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(json_spirit::Pair("sigsrequired", nRequired));
        return obj;
    }
};
#endif

json_spirit::Value validateaddress(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "validateaddress <honeyaddress>\n"
            "Return information about <honeyaddress>.");

    CHoneyAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    json_spirit::Object ret;
    ret.push_back(json_spirit::Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        std::string currentAddress = address.ToString();
        ret.push_back(json_spirit::Pair("address", currentAddress));
#ifdef ENABLE_WALLET
        bool fMine = pwalletMain ? IsMine(*pwalletMain, dest) : false;
        ret.push_back(json_spirit::Pair("ismine", fMine));
        if (fMine) {
            json_spirit::Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(json_spirit::Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
    }
    return ret;
}

json_spirit::Value validatepubkey(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || !params.size() || params.size() > 2)
        throw std::runtime_error(
            "validatepubkey <honeypubkey>\n"
            "Return information about <honeypubkey>.");

    std::vector<unsigned char> vchPubKey = ParseHex(params[0].get_str());
    CPubKey pubKey(vchPubKey);

    bool isValid = pubKey.IsValid();
    bool isCompressed = pubKey.IsCompressed();
    CKeyID keyID = pubKey.GetID();

    CHoneyAddress address;
    address.Set(keyID);

    json_spirit::Object ret;
    ret.push_back(json_spirit::Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        std::string currentAddress = address.ToString();
        ret.push_back(json_spirit::Pair("address", currentAddress));
        ret.push_back(json_spirit::Pair("iscompressed", isCompressed));
#ifdef ENABLE_WALLET
        bool fMine = pwalletMain ? IsMine(*pwalletMain, dest) : false;
        ret.push_back(json_spirit::Pair("ismine", fMine));
        if (fMine) {
            json_spirit::Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(json_spirit::Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
    }
    return ret;
}

json_spirit::Value verifymessage(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "verifymessage <honeyaddress> <signature> <message>\n"
            "Verify a signed message");

    std::string strAddress  = params[0].get_str();
    std::string strSign     = params[1].get_str();
    std::string strMessage  = params[2].get_str();

    CHoneyAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}
