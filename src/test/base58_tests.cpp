#include <boost/test/unit_test.hpp>
#include <boost/variant.hpp>

#include <json/json_spirit_reader_template.h>
#include <json/json_spirit_writer_template.h>
#include <json/json_spirit_utils.h>

#include <base58.h>
#include <util.h>

extern json_spirit::Array read_json(const std::string& filename);

BOOST_AUTO_TEST_SUITE(base58_tests)

// Goal: test low-level base58 encoding functionality
BOOST_AUTO_TEST_CASE(base58_EncodeBase58)
{
    json_spirit::Array tests = read_json("base58_encode_decode.json");

    BOOST_FOREACH(json_spirit::Value& tv, tests)
    {
        json_spirit::Array test = tv.get_array();
        std::string strTest = json_spirit::write_string(tv, false);
        if (test.size() < 2) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::vector<unsigned char> sourcedata = ParseHex(test[0].get_str());
        std::string base58string = test[1].get_str();
        BOOST_CHECK_MESSAGE(
                    EncodeBase58(&sourcedata[0], &sourcedata[sourcedata.size()]) == base58string,
                    strTest);
    }
}

// Goal: test low-level base58 decoding functionality
BOOST_AUTO_TEST_CASE(base58_DecodeBase58)
{
    json_spirit::Array tests = read_json("base58_encode_decode.json");
    std::vector<unsigned char> result;

    BOOST_FOREACH(json_spirit::Value& tv, tests)
    {
        json_spirit::Array test = tv.get_array();
        std::string strTest = json_spirit::write_string(tv, false);
        if (test.size() < 2) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::vector<unsigned char> expected = ParseHex(test[0].get_str());
        std::string base58string = test[1].get_str();
        BOOST_CHECK_MESSAGE(DecodeBase58(base58string, result), strTest);
        BOOST_CHECK_MESSAGE(result.size() == expected.size() && std::equal(result.begin(), result.end(), expected.begin()), strTest);
    }

    BOOST_CHECK(!DecodeBase58("invalid", result));
}

// Visitor to check address type
class TestAddrTypeVisitor : public boost::static_visitor<bool>
{
private:
    std::string exp_addrType;
public:
    TestAddrTypeVisitor(const std::string &exp_addrType) : exp_addrType(exp_addrType) { }
    bool operator()(const CKeyID &id) const
    {
        return (exp_addrType == "pubkey");
    }
    bool operator()(const CScriptID &id) const
    {
        return (exp_addrType == "script");
    }
    bool operator()(const CNoDestination &no) const
    {
        return (exp_addrType == "none");
    }
};

// Visitor to check address payload
class TestPayloadVisitor : public boost::static_visitor<bool>
{
private:
    std::vector<unsigned char> exp_payload;
public:
    TestPayloadVisitor(std::vector<unsigned char> &exp_payload) : exp_payload(exp_payload) { }
    bool operator()(const CKeyID &id) const
    {
        uint160 exp_key(exp_payload);
        return exp_key == id;
    }
    bool operator()(const CScriptID &id) const
    {
        uint160 exp_key(exp_payload);
        return exp_key == id;
    }
    bool operator()(const CNoDestination &no) const
    {
        return exp_payload.size() == 0;
    }
};

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(base58_keys_valid_parse)
{
    json_spirit::Array tests = read_json("base58_keys_valid.json");
    std::vector<unsigned char> result;
    CHoneySecret secret;
    CHoneyAddress addr;

    BOOST_FOREACH(json_spirit::Value& tv, tests)
    {
        json_spirit::Array test = tv.get_array();
        std::string strTest = json_spirit::write_string(tv, false);
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const json_spirit::Object &metadata = test[2].get_obj();
        bool isPrivkey = json_spirit::find_value(metadata, "isPrivkey").get_bool();
        bool isTestnet = json_spirit::find_value(metadata, "isTestnet").get_bool();
        if (isTestnet)
            SelectParams(CChainParams::TESTNET);
        else
            SelectParams(CChainParams::MAIN);
        if(isPrivkey)
        {
            bool isCompressed = json_spirit::find_value(metadata, "isCompressed").get_bool();
            // Must be valid private key
            // Note: CHoneySecret::SetString tests isValid, whereas CHoneyAddress does not!
            BOOST_CHECK_MESSAGE(secret.SetString(exp_base58string), "!SetString:"+ strTest);
            BOOST_CHECK_MESSAGE(secret.IsValid(), "!IsValid:" + strTest);
            CKey privkey = secret.GetKey();
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.size() == exp_payload.size() && std::equal(privkey.begin(), privkey.end(), exp_payload.begin()), "key mismatch:" + strTest);

            // Private key must be invalid public key
            addr.SetString(exp_base58string);
            BOOST_CHECK_MESSAGE(!addr.IsValid(), "IsValid privkey as pubkey:" + strTest);
        }
        else
        {
            std::string exp_addrType = json_spirit::find_value(metadata, "addrType").get_str(); // "script" or "pubkey"
            // Must be valid public key
            BOOST_CHECK_MESSAGE(addr.SetString(exp_base58string), "SetString:" + strTest);
            BOOST_CHECK_MESSAGE(addr.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(addr.IsScript() == (exp_addrType == "script"), "isScript mismatch" + strTest);
            CTxDestination dest = addr.Get();
            BOOST_CHECK_MESSAGE(boost::apply_visitor(TestAddrTypeVisitor(exp_addrType), dest), "addrType mismatch" + strTest);

            // Public key must be invalid private key
            secret.SetString(exp_base58string);
            BOOST_CHECK_MESSAGE(!secret.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
    SelectParams(CChainParams::MAIN);
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(base58_keys_valid_gen)
{
    json_spirit::Array tests = read_json("base58_keys_valid.json");
    std::vector<unsigned char> result;
    BOOST_FOREACH(json_spirit::Value& tv, tests)
    {
        json_spirit::Array test = tv.get_array();
        std::string strTest = json_spirit::write_string(tv, false);
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const json_spirit::Object &metadata = test[2].get_obj();
        bool isPrivkey = json_spirit::find_value(metadata, "isPrivkey").get_bool();
        bool isTestnet = json_spirit::find_value(metadata, "isTestnet").get_bool();
        if (isTestnet)
            SelectParams(CChainParams::TESTNET);
        else
            SelectParams(CChainParams::MAIN);
        if(isPrivkey)
        {
            bool isCompressed = json_spirit::find_value(metadata, "isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            CHoneySecret secret;
            secret.SetKey(key);
            BOOST_CHECK_MESSAGE(secret.ToString() == exp_base58string, "result mismatch: " + strTest);
        }
        else
        {
            std::string exp_addrType = json_spirit::find_value(metadata, "addrType").get_str();
            CTxDestination dest;
            if(exp_addrType == "pubkey")
            {
                dest = CKeyID(uint160(exp_payload));
            }
            else if(exp_addrType == "script")
            {
                dest = CScriptID(uint160(exp_payload));
            }
            else if(exp_addrType == "none")
            {
                dest = CNoDestination();
            }
            else
            {
                BOOST_ERROR("Bad addrtype: " << strTest);
                continue;
            }
            CHoneyAddress addrOut;
            BOOST_CHECK_MESSAGE(boost::apply_visitor(CHoneyAddressVisitor(&addrOut), dest), "encode dest: " + strTest);
            BOOST_CHECK_MESSAGE(addrOut.ToString() == exp_base58string, "mismatch: " + strTest);
        }
    }

    // Visiting a CNoDestination must fail
    CHoneyAddress dummyAddr;
    CTxDestination nodest = CNoDestination();
    BOOST_CHECK(!boost::apply_visitor(CHoneyAddressVisitor(&dummyAddr), nodest));

    SelectParams(CChainParams::MAIN);
}

// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(base58_keys_invalid)
{
    json_spirit::Array tests = read_json("base58_keys_invalid.json"); // Negative testcases
    std::vector<unsigned char> result;
    CHoneySecret secret;
    CHoneyAddress addr;

    BOOST_FOREACH(json_spirit::Value& tv, tests)
    {
        json_spirit::Array test = tv.get_array();
        std::string strTest = json_spirit::write_string(tv, false);
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        addr.SetString(exp_base58string);
        BOOST_CHECK_MESSAGE(!addr.IsValid(), "IsValid pubkey:" + strTest);
        secret.SetString(exp_base58string);
        BOOST_CHECK_MESSAGE(!secret.IsValid(), "IsValid privkey:" + strTest);
    }
}


BOOST_AUTO_TEST_SUITE_END()
