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

#include <tinyxml2.h>

#include <utility>
#include <string>

#include "rmw/error_handling.h"
#include "rmw/qos_profiles.h"
#include "rmw/types.h"

#include "rmw_fastrtps_shared_cpp/rmw_security_logging.hpp"

namespace
{
const char logging_plugin_property_name[] = "dds.sec.log.plugin";
const char log_file_property_name[] = "dds.sec.log.builtin.DDS_LogTopic.log_file";
const char verbosity_property_name[] = "dds.sec.log.builtin.DDS_LogTopic.event_log_level";
const char distribute_enable_property_name[] =
  "dds.sec.log.builtin.DDS_LogTopic.distribute";
const char distribute_depth_property_name[] =
  "com.rti.serv.secure.logging.distribute.writer_history_depth";

const struct
{
  const std::string name;
  rmw_qos_profile_t profile;
} supported_profiles[] =
{
  {"SENSOR_DATA", rmw_qos_profile_sensor_data},
  {"PARAMETERS", rmw_qos_profile_parameters},
  {"DEFAULT", rmw_qos_profile_default},
  {"SERVICES_DEFAULT", rmw_qos_profile_services_default},
  {"PARAMETER_EVENTS", rmw_qos_profile_parameter_events},
  {"SYSTEM_DEFAULT", rmw_qos_profile_system_default},
};

bool string_to_rmw_qos_profile(const std::string & str, rmw_qos_profile_t & profile)
{
  for (const auto & item : supported_profiles) {
    if (item.name == str) {
      profile = item.profile;
      return true;
    }
  }

  return false;
}

void add_property(
  eprosima::fastrtps::rtps::PropertySeq & properties,
  eprosima::fastrtps::rtps::Property && property)
{
  // Add property to vector. If property already exists, overwrite it.
  std::string property_name = property.name();
  for (auto & existing_property : properties) {
    if (existing_property.name() == property_name) {
      existing_property = property;
      return;
    }
  }

  properties.push_back(property);
}

bool add_property_from_xml_element(
  eprosima::fastrtps::rtps::PropertySeq & properties, const std::string & property_name,
  const tinyxml2::XMLElement & element, const char * const tag_name)
{
  auto tag = element.FirstChildElement(tag_name);
  if (tag != nullptr) {
    const char * text = tag->GetText();
    if (text == nullptr) {
      RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "failed to set security logging %s: improper format",
        tag_name);
      return false;
    }

    add_property(properties, eprosima::fastrtps::rtps::Property(property_name, text));
  }

  return true;
}

void add_properties_from_qos_profile(
  eprosima::fastrtps::rtps::PropertySeq & properties, const rmw_qos_profile_t & profile)
{
  // TODO(kyrofa): Talk to artivis about what QoS settings will be exposed.
  add_property(
    properties,
    eprosima::fastrtps::rtps::Property(
      distribute_depth_property_name,
      std::to_string(profile.depth)));
}
}  // namespace

bool apply_logging_configuration_from_file(
  const std::string & xml_file_path,
  eprosima::fastrtps::rtps::PropertySeq & properties)
{
  tinyxml2::XMLDocument document;
  document.LoadFile(xml_file_path.c_str());

  auto log_element = document.FirstChildElement("security_log");
  if (log_element == nullptr) {
    RMW_SET_ERROR_MSG("logger xml file missing 'security_log'");
    return RMW_RET_ERROR;
  }

  eprosima::fastrtps::rtps::PropertySeq new_properties;
  add_property(
    new_properties,
    eprosima::fastrtps::rtps::Property(
      logging_plugin_property_name,
      "builtin.DDS_LogTopic"));

  bool status = add_property_from_xml_element(
    new_properties,
    log_file_property_name,
    *log_element,
    "file");
  if (!status) {
    return status;
  }

  status = add_property_from_xml_element(
    new_properties,
    verbosity_property_name,
    *log_element,
    "verbosity");
  if (!status) {
    return status;
  }

  status = add_property_from_xml_element(
    new_properties,
    distribute_enable_property_name,
    *log_element,
    "distribute");
  if (!status) {
    return status;
  }

  auto qos_element = log_element->FirstChildElement("qos");
  if (qos_element != nullptr) {
    // First thing we need to do is apply any QoS profile that was specified.
    // Once that has happened, further settings can be applied to customize.
    auto profile_element = qos_element->FirstChildElement("profile");
    if (profile_element != nullptr) {
      const char * profile_str = profile_element->GetText();
      if (profile_str == nullptr) {
        RMW_SET_ERROR_MSG("failed to set security logging profile: improper format");
        return false;
      }

      rmw_qos_profile_t profile;
      if (!string_to_rmw_qos_profile(profile_str, profile)) {
        RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
          "failed to set security logging profile: %s is not a supported profile",
          profile_str);
        return false;
      }

      add_properties_from_qos_profile(new_properties, profile);
    }

    status = add_property_from_xml_element(
      new_properties,
      distribute_depth_property_name,
      *qos_element,
      "depth");
    if (!status) {
      return status;
    }
  }

  // Now that we're done parsing, actually update the properties
  for (auto & item : new_properties) {
    add_property(properties, std::move(item));
  }

  return true;
}
