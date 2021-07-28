#include "protostate.h"
#include "scoped_configuration.h"
#include "analyzer_utils.h"
#include <gtest.h>

TEST(sinsp_protostate, test_zero)
{
    sinsp_protostate protostate;
    auto protos = make_unique<draiosproto::proto_info>();
    protostate.to_protobuf(protos.get(), 1, 20);
    EXPECT_FALSE(protos->has_http());
    EXPECT_FALSE(protos->has_mysql());  
    EXPECT_FALSE(protos->has_postgres());
    EXPECT_FALSE(protos->has_mongodb());
}

// "standard" class can be used to access private members
class test_helper
{
public:
    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_server_urls(
        sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_server_urls;
    }

    static vector<unordered_map<string, sinsp_url_details>::iterator>* get_client_urls(
        sinsp_protostate_marker* spm)
    {
        return &spm->m_http.m_client_urls;
    }
                    
    static sinsp_http_parser::Result* get_result(sinsp_http_parser* parser)
    {
        return &parser->m_result;
    }
};

// need 3 classes of URLs for this test
// -URLs which are in the top 15 in a stat
// -URLs which are not in the top 15, but are in a group and are top in that group
// -URLs which are not in the top 15, but are in a group and NOT top in that group
//
// we'll use 1 for our test...because easier    
TEST(sinsp_protostate, test_url_groups)
{
	const std::string config = R"EOF(
url_grouping_enabled: true
url_groups:
  - ".*group.*"
)EOF";
	test_helpers::scoped_configuration enable_config(config);
	ASSERT_TRUE(enable_config.loaded());

    sinsp_protostate protostate;    

    for (int i = 0; i < 5; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://test");
        test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
        test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    for (int i = 0; i < 3; ++i)
    {
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://testgroup1");
        test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
        test_helper::get_result(http_parser)->status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1, false, 512);
    }

    auto transaction = make_unique<sinsp_partial_transaction>();
    auto http_parser = new sinsp_http_parser();
    auto url = string("http://testgroup2");
    test_helper::get_result(http_parser)->url = const_cast<char*>(url.c_str());
    test_helper::get_result(http_parser)->status_code = 200;
    http_parser->m_is_valid = true;
    transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
    transaction->m_protoparser = http_parser;
    protostate.update(transaction.get(), 1, false, 512);

    sinsp_protostate_marker marker;
    marker.add(&protostate);
    marker.mark_top(1);

    auto client_urls = test_helper::get_client_urls(&marker);
    EXPECT_EQ(client_urls->size(), 3);

    for (auto url = client_urls->begin(); url != client_urls->end(); ++url)
    {
        if ((*url)->first == "http://testgroup1")
        {
            EXPECT_GT((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
        else
        {
            EXPECT_EQ((*url)->second.m_flags & SRF_INCLUDE_IN_SAMPLE, 0);
        }
    }
}

TEST(sinsp_protostate, test_per_container_distribution)
{
	const std::string config = R"EOF(
url_grouping_enabled: true
url_groups:
	- ".*group.*"
)EOF";
	test_helpers::scoped_configuration enable_config(config);

    std::array<sinsp_protostate, 80> protostates;
    for (auto& protostate : protostates)
    {
        for (auto j = 0; j < 100; ++j)
        {
            auto transaction = make_unique<sinsp_partial_transaction>();
            auto http_parser = new sinsp_http_parser();
            auto url = string("http://test") + to_string(j);
            http_parser->m_result.url = url.c_str();
            http_parser->m_result.status_code = 200;
            http_parser->m_is_valid = true;
            transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
            transaction->m_protoparser = http_parser;
            protostate.update(transaction.get(), j, false, 512);
        }
    }
    sinsp_protostate_marker marker;
    for (auto& protostate : protostates)
    {
        marker.add(&protostate);
    }
    marker.mark_top(15);
    auto has_urls = 0;
    for (auto& protostate : protostates)
    {
        auto protos = make_unique<draiosproto::proto_info>();
        protostate.to_protobuf(protos.get(), 1, 15);
        if (protos->has_http())
        {
            auto http = protos->http();

            if (http.client_urls().size() > 0)
            {
                has_urls += 1;
            }
        }
        EXPECT_FALSE(protos->has_mysql());
        EXPECT_FALSE(protos->has_postgres());
        EXPECT_FALSE(protos->has_mongodb());
    }
    EXPECT_EQ(15, has_urls);
}

TEST(sinsp_protostate, test_top_call_should_be_present)
{
	const std::string config = R"EOF(
url_grouping_enabled: true
url_groups:
	- ".*group.*"
)EOF";
	test_helpers::scoped_configuration enable_config(config);

    std::array<sinsp_protostate, 80> protostates;
    for (auto& protostate : protostates)
    {
        for (auto j = 0; j < 100; ++j)
        {
            auto transaction = make_unique<sinsp_partial_transaction>();
            auto http_parser = new sinsp_http_parser();
            auto url = string("http://test") + to_string(j);
            http_parser->m_result.url = url.c_str();
            http_parser->m_result.status_code = 200;
            http_parser->m_is_valid = true;
            transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
            transaction->m_protoparser = http_parser;
            protostate.update(transaction.get(), j, false, 512);
        }
    }
    {
        auto& protostate = protostates.at(0);
        auto transaction = make_unique<sinsp_partial_transaction>();
        auto http_parser = new sinsp_http_parser();
        auto url = string("http://test/url/slow");
        http_parser->m_result.url = url.c_str();
        http_parser->m_result.status_code = 200;
        http_parser->m_is_valid = true;
        transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
        transaction->m_protoparser = http_parser;
        protostate.update(transaction.get(), 1000, false, 512);
    }

    {
        auto& protostate = protostates.at(50);
        for (auto j = 0; j < 500; ++j)
        {
            auto transaction = make_unique<sinsp_partial_transaction>();
            auto http_parser = new sinsp_http_parser();
            auto url = string("http://test/url/topcall");
            http_parser->m_result.url = url.c_str();
            http_parser->m_result.status_code = 204;
            http_parser->m_is_valid = true;
            transaction->m_type = sinsp_partial_transaction::TYPE_HTTP;
            transaction->m_protoparser = http_parser;
            protostate.update(transaction.get(), 2, false, 512);
        }
    }

    sinsp_protostate_marker marker;
    for (auto& protostate : protostates)
    {
        marker.add(&protostate);
    }
    marker.mark_top(15);
    auto found_slow = false;
    auto found_top_call = false;
    auto top_ncalls = 0;
    for (auto& protostate : protostates)
    {
        auto protos = make_unique<draiosproto::proto_info>();
        protostate.to_protobuf(protos.get(), 1, 15);
        if (protos->has_http())
        {
            auto http = protos->http();

            if (http.client_urls().size() > 0)
            {
                for (auto url : http.client_urls())
                {
                    if (url.url().find("slow") != string::npos)
                    {
                        found_slow = true;
                    }
                    if (url.url().find("topcall") != string::npos)
                    {
                        found_top_call = true;
                    }
                }
            }
            for (auto status_code : http.client_status_codes())
            {
                if (status_code.status_code() == 204)
                {
                    top_ncalls = status_code.ncalls();
                }
            }
        }
        EXPECT_FALSE(protos->has_mysql());
        EXPECT_FALSE(protos->has_postgres());
        EXPECT_FALSE(protos->has_mongodb());
    }
    EXPECT_TRUE(found_slow);
    EXPECT_TRUE(found_top_call);
    EXPECT_EQ(500, top_ncalls);
}
