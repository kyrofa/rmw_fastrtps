// Copyright 2020 Canonical Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fstream>
#include <string>

#include "rmw/error_handling.h"

#include "rmw_fastrtps_shared_cpp/rmw_security_logging.hpp"

#include "gmock/gmock.h"

using ::testing::HasSubstr;

namespace
{
const char logging_plugin_property_name[] = "dds.sec.log.plugin";
const char log_file_property_name[] = "dds.sec.log.builtin.DDS_LogTopic.log_file";
const char verbosity_property_name[] = "dds.sec.log.builtin.DDS_LogTopic.event_log_level";
const char distribute_enable_property_name[] =
  "dds.sec.log.builtin.DDS_LogTopic.distribute";
const char distribute_depth_property_name[] =
  "com.rti.serv.secure.logging.distribute.writer_history_depth";

std::string write_logging_xml(const std::string & xml)
{
  // mkstemp isn't cross-platform, and we don't care about security here
  std::string xml_file_path(std::tmpnam(nullptr));

  std::ofstream xml_file;
  xml_file.open(xml_file_path);
  xml_file << "<?xml version='1.0' encoding='UTF-8'?>" << std::endl;
  xml_file << "<security_log version='1'>" << std::endl;
  xml_file << xml << std::endl;
  xml_file << "</security_log>" << std::endl;
  xml_file.close();

  return xml_file_path;
}

const eprosima::fastrtps::rtps::Property & lookup_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties, const std::string & property_name)
{
  auto iterator = std::find_if(
    properties.begin(), properties.end(),
    [&property_name](const eprosima::fastrtps::rtps::Property & item) -> bool {
      return item.name() == property_name;
    });

  if (iterator == properties.end()) {
    ADD_FAILURE() << "Expected property " << property_name << " to be in list";
  }

  return *iterator;
}

const eprosima::fastrtps::rtps::Property & logging_plugin_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties)
{
  return lookup_property(properties, logging_plugin_property_name);
}

const eprosima::fastrtps::rtps::Property & log_file_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties)
{
  return lookup_property(properties, log_file_property_name);
}

const eprosima::fastrtps::rtps::Property & verbosity_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties)
{
  return lookup_property(properties, verbosity_property_name);
}

const eprosima::fastrtps::rtps::Property & distribute_enable_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties)
{
  return lookup_property(properties, distribute_enable_property_name);
}

const eprosima::fastrtps::rtps::Property & distribute_depth_property(
  const eprosima::fastrtps::rtps::PropertySeq & properties)
{
  return lookup_property(properties, distribute_depth_property_name);
}

class SecurityLoggingTest : public ::testing::Test
{
public:
  void TearDown()
  {
    rmw_reset_error();
  }
};
}  // namespace

TEST_F(SecurityLoggingTest, test_logging_plugin)
{
  std::string xml_file_path = write_logging_xml("");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 1u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");
}

TEST_F(SecurityLoggingTest, test_log_file)
{
  std::string xml_file_path = write_logging_xml("<file>foo</file>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = log_file_property(properties);
  EXPECT_EQ(property.name(), log_file_property_name);
  EXPECT_EQ(property.value(), "foo");
}

TEST_F(SecurityLoggingTest, test_log_verbosity)
{
  std::string xml_file_path = write_logging_xml("<verbosity>CRITICAL</verbosity>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = verbosity_property(properties);
  EXPECT_EQ(property.name(), verbosity_property_name);
  EXPECT_EQ(property.value(), "CRITICAL");
}

TEST_F(SecurityLoggingTest, test_log_distribute)
{
  std::string xml_file_path = write_logging_xml("<distribute>true</distribute>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = distribute_enable_property(properties);
  EXPECT_EQ(property.name(), distribute_enable_property_name);
  EXPECT_EQ(property.value(), "true");
}

TEST_F(SecurityLoggingTest, test_log_depth)
{
  std::string xml_file_path = write_logging_xml("<qos><depth>10</depth></qos>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = distribute_depth_property(properties);
  EXPECT_EQ(property.name(), distribute_depth_property_name);
  EXPECT_EQ(property.value(), "10");
}

TEST_F(SecurityLoggingTest, test_profile)
{
  std::string xml_file_path = write_logging_xml("<qos><profile>DEFAULT</profile></qos>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = distribute_depth_property(properties);
  EXPECT_EQ(property.name(), distribute_depth_property_name);
  EXPECT_EQ(property.value(), "10");
}

TEST_F(SecurityLoggingTest, test_profile_overwrite)
{
  std::string xml_file_path = write_logging_xml(
    "<qos>\n"
    "  <profile>DEFAULT</profile>\n"
    "  <depth>42</depth>\n"
    "</qos>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 2u);

  auto property = logging_plugin_property(properties);
  EXPECT_EQ(property.name(), logging_plugin_property_name);
  EXPECT_EQ(property.value(), "builtin.DDS_LogTopic");

  property = distribute_depth_property(properties);
  EXPECT_EQ(property.name(), distribute_depth_property_name);
  EXPECT_EQ(property.value(), "42");
}

TEST_F(SecurityLoggingTest, test_profile_invalid)
{
  std::string xml_file_path = write_logging_xml("<qos><profile>INVALID_PROFILE</profile></qos>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_FALSE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_TRUE(rmw_error_is_set());
  EXPECT_THAT(rmw_get_error_string().str, HasSubstr("INVALID_PROFILE is not a supported profile"));

  ASSERT_TRUE(properties.empty());
}

TEST_F(SecurityLoggingTest, test_all)
{
  std::string xml_file_path = write_logging_xml(
    "<file>foo</file>\n"
    "<verbosity>CRITICAL</verbosity>\n"
    "<distribute>true</distribute>\n"
    "<qos>\n"
    "  <depth>10</depth>\n"
    "</qos>");
  eprosima::fastrtps::rtps::PropertySeq properties;
  EXPECT_TRUE(apply_logging_configuration_from_file(xml_file_path, properties));
  EXPECT_FALSE(rmw_error_is_set());

  ASSERT_EQ(properties.size(), 5u);

  auto property = log_file_property(properties);
  EXPECT_EQ(property.name(), log_file_property_name);
  EXPECT_EQ(property.value(), "foo");

  property = verbosity_property(properties);
  EXPECT_EQ(property.name(), verbosity_property_name);
  EXPECT_EQ(property.value(), "CRITICAL");

  property = distribute_enable_property(properties);
  EXPECT_EQ(property.name(), distribute_enable_property_name);
  EXPECT_EQ(property.value(), "true");

  property = distribute_depth_property(properties);
  EXPECT_EQ(property.name(), distribute_depth_property_name);
  EXPECT_EQ(property.value(), "10");
}
