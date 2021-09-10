#include "promscrape_cli.h"
#include <gtest.h>
#include <sstream>

static void populate_stats_map(const std::string& tgt, promscrape_stats::stats_map_t& stats_map)
{
    promscrape_stats::metric_stats stats;
    stats.raw_scraped = 110;
    stats.raw_job_filter_dropped = 10;
    stats.raw_over_job_limit = 10;
    stats.raw_global_filter_dropped = 10;
    stats.raw_sent = 70;
    stats.calc_scraped = 210;
    stats.calc_job_filter_dropped = 20;
    stats.calc_over_job_limit = 20;
    stats.calc_global_filter_dropped = 20;
    stats.calc_sent = 140;
    stats.over_global_limit = 1;
    stats_map[tgt] = stats;
}


TEST(promscrape_cli_test, get_prometheus_global_stats)
{
    promscrape_stats::stats_map_t stats_map;
    populate_stats_map("http://target1", stats_map);
    populate_stats_map("http://target2", stats_map);

    std::string output;
    promscrape_cli::display_prometheus_stats(stats_map, output);
    std::string exp_out;
    exp_out = " Total Targets          2   \n"
              " Global Unsent Metrics  100 \n";
    EXPECT_EQ(output, exp_out);  
}

TEST(promscrape_cli_test, display_targets_empty)
{
    promscrape_stats::stats_map_t stats_map;
    populate_stats_map("http://100.105.83.1:10055/metrics", stats_map);

    Json::Value data;
    std::string output;
    promscrape_cli::display_targets(data, stats_map, output);
    std::string exp_out;
    exp_out = "No targets monitored. \n";
    EXPECT_EQ(output, exp_out);
}

TEST(promscrape_cli_test, display_targets)
{
    promscrape_stats::stats_map_t stats_map;
    populate_stats_map("http://100.105.83.1:10055/metrics", stats_map);

    std::string target = R"EOF(
        {
        "activeTargets": [
            {
                "discoveredLabels": {
                    "__meta_kubernetes_pod_name": "kube-dns-1"
                },
                "scrapePool": "k8s-pods",
                "scrapeUrl": "http://100.105.83.1:10055/metrics",
                "lastError": "",
                "health": "up"
            }
            ]
        }
        )EOF";

    Json::Value data;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(target, data));
    
    std::string output;
    promscrape_cli::display_targets(data, stats_map, output);

    std::istringstream ss(output);
    std::string exp_out;
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("Pool: k8s-pods"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("URL"), std::string::npos);
    EXPECT_NE(exp_out.find("Health"), std::string::npos);
    EXPECT_NE(exp_out.find("Pod"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("http://100.105.83.1:10055/metrics"), std::string::npos);
    EXPECT_NE(exp_out.find("up"), std::string::npos);
    EXPECT_NE(exp_out.find("kube-dns-1"), std::string::npos);
}

TEST(promscrape_cli_test, display_target)
{
    promscrape_stats::stats_map_t stats_map;
    const std::string url = "http://100.105.83.1:10055/metrics";
    populate_stats_map(url, stats_map);

    std::string target = R"EOF(
        {
        "activeTargets": [
            {
                "discoveredLabels": {
                    "__meta_kubernetes_pod_name": "kube-dns-1"
                },
                "scrapePool": "k8s-pods",
                "scrapeUrl": "http://100.105.83.1:10055/metrics",
                "lastError": "",
                "health": "up"
            }
            ]
        }
        )EOF";

    Json::Value data;
    Json::Reader reader;
    ASSERT_TRUE(reader.parse(target, data));
   
    std::string output;
    promscrape_cli::display_target(data, stats_map, url, output);
    std::string exp_out;
    exp_out = " URL                        http://100.105.83.1:10055/metrics \n"
              " Health                     up                                \n"
              " Instance/Pod               kube-dns-1                        \n"  
              " Total Metrics Scraped      320                               \n"
              " Total Metrics Sent         210                               \n"
              " Total Metrics Filtered     60                                \n" 
              " Total Metrics Unsent       50                                \n"
              " Metrics Over Global Limit  1                                 \n"
              " Raw Metrics:                                                 \n"
              " Scraped                    110                               \n"
              " Sent                       70                                \n"
              " Filtered By Job            10                                \n"
              " Filtered By Global         10                                \n"
              " Metrics Over Job Limit     10                                \n"
              " Calculated Metrics:                                          \n"
              " Scraped                    210                               \n"
              " Sent                       140                               \n"
              " Filtered By Job            20                                \n"
              " Filtered By Global         20                                \n"
              " Metrics Over Job Limit     20                                \n"
              " Error                      -                                 \n";

    EXPECT_EQ(output, exp_out);
}

TEST(promscrape_cli_test, display_brief_metadata)
{
    const std::string url = "http://100.105.83.1:10055/metrics";
    promscrape_stats::metric_metadata_map_t mm_map;
    mm_map["m1"] = {"histogram", "M1", "", 20};
    mm_map["m2"] = {"histogram", "M2", "", 20};
    mm_map["m3"] = {"histogram", "M3", "", 20};
    mm_map["m4"] = {"histogram", "M4", "", 20};
    mm_map["m5"] = {"histogram", "M5", "", 20};
    mm_map["m6"] = {"histogram", "M6", "", 20};
    mm_map["m7"] = {"histogram", "M7", "", 20};
    mm_map["m8"] = {"histogram", "M8", "", 20};
    mm_map["m9"] = {"histogram", "M9", "", 20};
    mm_map["m10"] = {"histogram", "M10", "", 30};
    mm_map["m11"] = {"histogram", "M11", "", 40};

    std::string output;
    promscrape_cli::display_target_metadata(url, mm_map, output, true);
    std::istringstream ss(output);
    std::string exp_out;
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("http://100.105.83.1:10055/metrics"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("Name"), std::string::npos);
    EXPECT_NE(exp_out.find("Type"), std::string::npos);
    EXPECT_NE(exp_out.find("#TS"), std::string::npos);
    EXPECT_NE(exp_out.find("Description"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("m11"), std::string::npos);
    EXPECT_NE(exp_out.find("histogram"), std::string::npos);
    EXPECT_NE(exp_out.find("40"), std::string::npos);
    EXPECT_NE(exp_out.find("M11"), std::string::npos);

    int i = 0;
    while (i < 8)
    {
        std::getline(ss, exp_out, '\n');
        i++;
    }

    //Checking 10th record
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("m1"), std::string::npos);
    EXPECT_NE(exp_out.find("histogram"), std::string::npos);
    EXPECT_NE(exp_out.find("20"), std::string::npos);
    EXPECT_NE(exp_out.find("M1"), std::string::npos);

    //Make sure 11th record is not there
    exp_out.clear();
    std::getline(ss, exp_out, '\n');
    ASSERT_TRUE(exp_out.empty());
}

TEST(promscrape_cli_test, display_full_metadata)
{
    const std::string url = "http://100.105.83.1:10055/metrics";
    promscrape_stats::metric_metadata_map_t mm_map;
    mm_map["m1"] = {"histogram", "M1", "", 20};
    mm_map["m2"] = {"histogram", "M2", "", 20};
    mm_map["m3"] = {"histogram", "M3", "", 20};
    mm_map["m4"] = {"histogram", "M4", "", 20};
    mm_map["m5"] = {"histogram", "M5", "", 20};
    mm_map["m6"] = {"histogram", "M6", "", 20};
    mm_map["m7"] = {"histogram", "M7", "", 20};
    mm_map["m8"] = {"histogram", "M8", "", 20};
    mm_map["m9"] = {"histogram", "M9", "", 20};
    mm_map["m10"] = {"histogram", "M10", "", 30};
    mm_map["m11"] = {"histogram", "M11", "", 40};

    std::string output;
    promscrape_cli::display_target_metadata(url, mm_map, output, false);
        std::istringstream ss(output);
    std::string exp_out;
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("http://100.105.83.1:10055/metrics"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("Name"), std::string::npos);
    EXPECT_NE(exp_out.find("Type"), std::string::npos);
    EXPECT_NE(exp_out.find("#TS"), std::string::npos);
    EXPECT_NE(exp_out.find("Description"), std::string::npos);
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("m11"), std::string::npos);
    EXPECT_NE(exp_out.find("histogram"), std::string::npos);
    EXPECT_NE(exp_out.find("40"), std::string::npos);
    EXPECT_NE(exp_out.find("M11"), std::string::npos);

    int i = 0;
    while (i < 9)
    {
        std::getline(ss, exp_out, '\n');
        i++;
    }

    //Checking more than 10 records are present ~= 11th record
    std::getline(ss, exp_out, '\n');
    EXPECT_NE(exp_out.find("m1"), std::string::npos);
    EXPECT_NE(exp_out.find("histogram"), std::string::npos);
    EXPECT_NE(exp_out.find("20"), std::string::npos);
    EXPECT_NE(exp_out.find("M1"), std::string::npos);
}
