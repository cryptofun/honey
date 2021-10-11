// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcprotocol.h"
#include "util.h"

#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

#include "json/json_spirit_writer_template.h"
#include <fstream>


//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

std::string HTTPPost(const std::string& strMsg, const std::map<std::string,std::string>& mapRequestHeaders)
{
    std::ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: honey-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(std::string, std::string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

static std::string rfc1123Time()
{
    return DateTimeStrFormat("%a, %d %b %Y %H:%M:%S +0000", GetTime());
}

std::string HTTPReply(int nStatus, const std::string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: honey-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time(), FormatFullVersion());
    const char *cStatus;
         if (nStatus == HTTP_OK) cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN) cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND) cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %u\r\n"
            "Content-Type: application/json\r\n"
            "Server: honey-json-rpc/%s\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        FormatFullVersion(),
        strMsg);
}

bool ReadHTTPRequestLine(std::basic_istream<char>& stream, int &proto,
                         std::string& http_method, std::string& http_uri)
{
    std::string str;
    getline(stream, str);

    // HTTP request line is space-delimited
    std::vector<std::string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return false;

    // HTTP methods permitted: GET, POST
    http_method = vWords[0];
    if (http_method != "GET" && http_method != "POST")
        return false;

    // HTTP URI must be an absolute path, relative to current host
    http_uri = vWords[1];
    if (http_uri.size() == 0 || http_uri[0] != '/')
        return false;

    // parse proto, if present
    std::string strProto = "";
    if (vWords.size() > 2)
        strProto = vWords[2];

    proto = 0;
    const char *ver = strstr(strProto.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);

    return true;
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    std::string str;
    getline(stream, str);
    std::vector<std::string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeaders(std::basic_istream<char>& stream, std::map<std::string, std::string>& mapHeadersRet)
{
    int nLen = 0;
    while (true)
    {
        std::string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        std::string::size_type nColon = str.find(":");
        if (nColon != std::string::npos)
        {
            std::string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            std::string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}


int ReadHTTPMessage(std::basic_istream<char>& stream, std::map<std::string,
                    std::string>& mapHeadersRet, std::string& strMessageRet,
                    int nProto)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read header
    int nLen = ReadHTTPHeaders(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0)
    {
        std::vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = std::string(vch.begin(), vch.end());
    }

    std::string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return HTTP_OK;
}

//
// JSON-RPC protocol.  Honey speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

std::string JSONRPCRequest(const std::string& strMethod, const json_spirit::Array& params, const json_spirit::Value& id)
{
    json_spirit::Object request;
    request.push_back(json_spirit::Pair("method", strMethod));
    request.push_back(json_spirit::Pair("params", params));
    request.push_back(json_spirit::Pair("id", id));
    return json_spirit::write_string(json_spirit::Value(request), false) + "\n";
}

json_spirit::Object JSONRPCReplyObj(const json_spirit::Value& result, const json_spirit::Value& error, const json_spirit::Value& id)
{
    json_spirit::Object reply;
    if (error.type() != json_spirit::null_type)
        reply.push_back(json_spirit::Pair("result", json_spirit::Value::null));
    else
        reply.push_back(json_spirit::Pair("result", result));
    reply.push_back(json_spirit::Pair("error", error));
    reply.push_back(json_spirit::Pair("id", id));
    return reply;
}

std::string JSONRPCReply(const json_spirit::Value& result, const json_spirit::Value& error, const json_spirit::Value& id)
{
    json_spirit::Object reply = JSONRPCReplyObj(result, error, id);
    return json_spirit::write_string(json_spirit::Value(reply), false) + "\n";
}

json_spirit::Object JSONRPCError(int code, const std::string& message)
{
    json_spirit::Object error;
    error.push_back(json_spirit::Pair("code", code));
    error.push_back(json_spirit::Pair("message", message));
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
  * recognizability in debugging/logging purposes)
  */
 static const std::string COOKIEAUTH_USER = "__cookie__";
 /** Default name for auth cookie file */
 static const std::string COOKIEAUTH_FILE = "cookie";

 boost::filesystem::path GetAuthCookieFile()
 {
     boost::filesystem::path path(GetArg("-rpccookiefile", COOKIEAUTH_FILE));
     if (!path.is_complete()) path = GetDataDir() / path;
     return path;
 }

 bool GenerateAuthCookie(std::string *cookie_out)
 {
     unsigned char rand_pwd[32];
     RAND_bytes(rand_pwd, 32);
     std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32);

      /* these are set to 077 in init.cpp unless overridden with -sysperms.
      */
     std::ofstream file;
     boost::filesystem::path filepath = GetAuthCookieFile();
     file.open(filepath.string().c_str());
     if (!file.is_open()) {
         LogPrintf("Unable to open cookie authentication file %s for writing\n", filepath.string());
         return false;
     }
     file << cookie;
     file.close();
     LogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

     if (cookie_out)
         *cookie_out = cookie;
     return true;
 }

 bool GetAuthCookie(std::string *cookie_out)
 {
     std::ifstream file;
     std::string cookie;
     boost::filesystem::path filepath = GetAuthCookieFile();
     file.open(filepath.string().c_str());
     if (!file.is_open())
         return false;
     std::getline(file, cookie);
     file.close();

     if (cookie_out)
         *cookie_out = cookie;
     return true;
 }

 void DeleteAuthCookie()
 {
     try {
         boost::filesystem::remove(GetAuthCookieFile());
     } catch (const boost::filesystem::filesystem_error& e) {
         LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, e.what());
     }
 }
