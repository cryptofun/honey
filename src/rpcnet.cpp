// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpcserver.h>

#include <main.h>
#include <net.h>
#include <netbase.h>
#include <protocol.h>
#include <sync.h>
#include <timedata.h>
#include <util.h>

#include <boost/foreach.hpp>
#include <json/json_spirit_value.h>


json_spirit::Value getconnectioncount(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");

    LOCK(cs_vNodes);
    return (int)vNodes.size();
}

json_spirit::Value ping(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "ping\n"
            "Requests that a ping be sent to all other nodes, to measure ping time.\n"
            "Results provided in getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
            "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.");

    // Request that each node send a ping during next message processing pass
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pNode, vNodes) {
        pNode->fPingQueued = true;
    }

    return json_spirit::Value::null;
}

static void CopyNodeStats(std::vector<CNodeStats>& vstats)
{
    vstats.clear();

    LOCK(cs_vNodes);
    vstats.reserve(vNodes.size());
    BOOST_FOREACH(CNode* pnode, vNodes) {
        CNodeStats stats;
        pnode->copyStats(stats);
        vstats.push_back(stats);
    }
}

json_spirit::Value getpeerinfo(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getpeerinfo\n"
            "Returns data about each connected network node.");

    std::vector<CNodeStats> vstats;
    CopyNodeStats(vstats);

    json_spirit::Array ret;

    BOOST_FOREACH(const CNodeStats& stats, vstats) {
        json_spirit::Object obj;

        obj.push_back(json_spirit::Pair("addr", stats.addrName));
        if (!(stats.addrLocal.empty()))
            obj.push_back(json_spirit::Pair("addrlocal", stats.addrLocal));
        obj.push_back(json_spirit::Pair("services", strprintf("%08x", stats.nServices)));
        obj.push_back(json_spirit::Pair("lastsend", (int64_t)stats.nLastSend));
        obj.push_back(json_spirit::Pair("lastrecv", (int64_t)stats.nLastRecv));
        obj.push_back(json_spirit::Pair("bytessent", (int64_t)stats.nSendBytes));
        obj.push_back(json_spirit::Pair("bytesrecv", (int64_t)stats.nRecvBytes));
        obj.push_back(json_spirit::Pair("conntime", (int64_t)stats.nTimeConnected));
        obj.push_back(json_spirit::Pair("timeoffset", stats.nTimeOffset));
        obj.push_back(json_spirit::Pair("pingtime", stats.dPingTime));
        if (stats.dPingWait > 0.0)
            obj.push_back(json_spirit::Pair("pingwait", stats.dPingWait));
        obj.push_back(json_spirit::Pair("version", stats.nVersion));
        obj.push_back(json_spirit::Pair("subver", stats.strSubVer));
        obj.push_back(json_spirit::Pair("inbound", stats.fInbound));
        obj.push_back(json_spirit::Pair("startingheight", stats.nStartingHeight));
        obj.push_back(json_spirit::Pair("banscore", stats.nMisbehavior));
        obj.push_back(json_spirit::Pair("syncnode", stats.fSyncNode));

        ret.push_back(obj);
    }

    return ret;
}

json_spirit::Value addnode(const json_spirit::Array& params, bool fHelp)
{
    std::string strCommand;
    if (params.size() == 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw std::runtime_error(
            "addnode <node> <add|remove|onetry>\n"
            "Attempts add or remove <node> from the addnode list or try a connection to <node> once.");

    std::string strNode = params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        ConnectNode(addr, strNode.c_str());
        return json_spirit::Value::null;
    }

    LOCK(cs_vAddedNodes);
    std::vector<std::string>::iterator it = vAddedNodes.begin();
    for(; it != vAddedNodes.end(); it++)
        if (strNode == *it)
            break;

    if (strCommand == "add")
    {
        if (it != vAddedNodes.end())
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
        vAddedNodes.push_back(strNode);
    }
    else if(strCommand == "remove")
    {
        if (it == vAddedNodes.end())
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        vAddedNodes.erase(it);
    }

    return json_spirit::Value::null;
}

json_spirit::Value getaddednodeinfo(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getaddednodeinfo <dns> [node]\n"
            "Returns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "If dns is false, only a list of added nodes will be provided,\n"
            "otherwise connected information will also be available.");

    bool fDns = params[0].get_bool();

    std::list<std::string> laddedNodes(0);
    if (params.size() == 1)
    {
        LOCK(cs_vAddedNodes);
        BOOST_FOREACH(std::string& strAddNode, vAddedNodes)
            laddedNodes.push_back(strAddNode);
    }
    else
    {
        std::string strNode = params[1].get_str();
        LOCK(cs_vAddedNodes);
        BOOST_FOREACH(std::string& strAddNode, vAddedNodes)
            if (strAddNode == strNode)
            {
                laddedNodes.push_back(strAddNode);
                break;
            }
        if (laddedNodes.size() == 0)
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    if (!fDns)
    {
        json_spirit::Object ret;
        BOOST_FOREACH(std::string& strAddNode, laddedNodes)
            ret.push_back(json_spirit::Pair("addednode", strAddNode));
        return ret;
    }

    json_spirit::Array ret;

    std::list<std::pair<std::string, std::vector<CService> > > laddedAddreses(0);
    BOOST_FOREACH(std::string& strAddNode, laddedNodes)
    {
        std::vector<CService> vservNode(0);
        if(Lookup(strAddNode.c_str(), vservNode, Params().GetDefaultPort(), fNameLookup, 0))
            laddedAddreses.push_back(std::make_pair(strAddNode, vservNode));
        else
        {
            json_spirit::Object obj;
            obj.push_back(json_spirit::Pair("addednode", strAddNode));
            obj.push_back(json_spirit::Pair("connected", false));
            json_spirit::Array addresses;
            obj.push_back(json_spirit::Pair("addresses", addresses));
        }
    }

    LOCK(cs_vNodes);
    for (std::list<std::pair<std::string, std::vector<CService> > >::iterator it = laddedAddreses.begin(); it != laddedAddreses.end(); it++)
    {
        json_spirit::Object obj;
        obj.push_back(json_spirit::Pair("addednode", it->first));

        json_spirit::Array addresses;
        bool fConnected = false;
        BOOST_FOREACH(CService& addrNode, it->second)
        {
            bool fFound = false;
            json_spirit::Object node;
            node.push_back(json_spirit::Pair("address", addrNode.ToString()));
            BOOST_FOREACH(CNode* pnode, vNodes)
                if (pnode->addr == addrNode)
                {
                    fFound = true;
                    fConnected = true;
                    node.push_back(json_spirit::Pair("connected", pnode->fInbound ? "inbound" : "outbound"));
                    break;
                }
            if (!fFound)
                node.push_back(json_spirit::Pair("connected", "false"));
            addresses.push_back(node);
        }
        obj.push_back(json_spirit::Pair("connected", fConnected));
        obj.push_back(json_spirit::Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

json_spirit::Value getnettotals(const json_spirit::Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "getnettotals\n"
            "Returns information about network traffic, including bytes in, bytes out,\n"
            "and current time.");

    json_spirit::Object obj;
    obj.push_back(json_spirit::Pair("totalbytesrecv", CNode::GetTotalBytesRecv()));
    obj.push_back(json_spirit::Pair("totalbytessent", CNode::GetTotalBytesSent()));
    obj.push_back(json_spirit::Pair("timemillis", GetTimeMillis()));
    return obj;
}
