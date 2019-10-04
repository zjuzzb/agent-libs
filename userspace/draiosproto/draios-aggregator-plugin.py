#!/usr/bin/env python

# This file generates a c++ aggregator for the agent protobuf.
#
# Class Hierarchy:
# 
# agent_message_aggregator: pre-defined interface that declares what each message type must
#                           be able to do
# <message_name>_message_aggregator: generated derived class of agent_message_aggregator.
#                                    Along with the pure-virtual fields, it also creates
#                                    a virtual aggregator function for each field which
#                                    can be overridden.
# message_aggregator_builder: base class with virtual builders for each of the
#                             *_message_aggregators. Each aggregator holds a pointer
#                             to this. See the "Overriding" section for notes on usage
#
# Default Aggregation Methods:
# 1) single numeric type -> aggregated type: This is the most common use case and deals with
#   a requried or optional numeric type and a corresponding aggregations field. The mapping
#   between the two is stored in the "field_extension" dictionary, and in each case, we invoke
#   agent_message_aggregator::default_aggregate_value, which handles the aggregation.
#
# 2) repeated numeric type-> repeated aggregated type: This is used most often when we have
#   a fixed-size list of values, say one metric per CPU, which maps to a list of aggregated
#   types (also stored in the 'field_extension" dictionary. In each case, we invoke
#   agent_message_aggregator::default_aggregate_list, which aggregates each index of the list as
#   if it was a separate field.
#
# 3) single message type. In the case of field which is a message, we maintain an instance
#   of the message_aggregator representing that field, and invoke its aggregate method.
#   That instance is unique per-field, so if multiple instances of a given message occur,
#   they each have their own instance of the aggregator. Each instance behaves identically,
#   however, which means aggregation for a given message type is consistent across all
#   instances of a message. This means you cannot have an instance of "message foo" which,
#   say, takes the max of each field, and another which takes the min. Two message types
#   would have to be created as they have differing behavior.
#
# 4) non-message repeated type. In the case where we have a repeated field which is not
#   type (2), and is also not a message type, the default action is a union. In order to
#   do this efficiently, we maintain a set for each such field, and only new unique entries
#   to said set are added to the actual field in the aggregated protobuf.
#
# 5) repeated message type. From a high level, this works like type (4). However, as the
#   type we're attempting to make unique is a message, we need some way to determine the
#   "primary key" of the message. As such, we make a first pass of all the messages to
#   identify message types which are used as a type (5) field elsewhere, and create an
#   additional method that defines the primary key for that message type. That method
#   is implemented as a list of strings defined in "primary_keys" for the message type.
#   When a duplicate message is found on aggregation, the aggregator for that message will be
#   invoked on the duplicated message, otherwise the message will be appended to the end of
#   the output field.
#
# 6) single type: for non-message, non type (1) fields, we choose one of the inputs to be
#   the output.
#
# 7) map types take the union of the maps. This is not implemented as no user of the
#   aggregator currently requires it
#
# "skip" list: Some messages we don't want to bother generating aggregator methods/classes
#   for (for whatever reason). Add these to the "skip" list
#
import sys
import itertools
import json

from google.protobuf.compiler import plugin_pb2 as plugin
from google.protobuf.descriptor_pb2 import DescriptorProto, EnumDescriptorProto
from google.protobuf.descriptor import FieldDescriptor
from draios_proto_extension import *

# This dict maps a message name to a map of field index to field entry
index_dict = {}

# This set contains all message names which are used as part of a primary key for
# some repeated message field. Messages in this set need to generate hash/equals methods
# based on primary keys
key_messages = set()

def traverse(proto_file):

    def _traverse(package, items):
        for item in items:
            yield item, package

            if isinstance(item, DescriptorProto):
                for enum in item.enum_type:
                    yield enum, package

                for nested in item.nested_type:
                    nested_package = package + item.name

                    for nested_item in _traverse(nested, nested_package):
                        yield nested_item, nested_package

    return itertools.chain(
        _traverse(proto_file.package, proto_file.enum_type),
        _traverse(proto_file.package, proto_file.message_type),
    )

# generates a map of the names of the fields which aggregate to other fields.
# out = map<source_field_name, destination_field_name>
# targets = set<detination_field_name>
def generate_aggregator_list(item):
    out = {}
    targets = set()

    if item.name not in field_extension:
        return out, targets

    for key, value in field_extension[item.name].items():
        if value is PRIMARY_KEY:
            continue
        if value is OR:
            continue
        out[index_dict[item.name][key].name] = index_dict[item.name][value].name;
        targets.add(index_dict[item.name][value].name)

    return out, targets

# This is ugly. There are a few fields we have that are protoc reserved keywords. It gets
# around this by adding a _. Use this function when accessing fields in the protobuf
def get_adjusted_field_name(name):
    if name == "namespace":
        return "namespace_"
    return name

# field type has the package prepended. strip it to get the actual type
def type_name(field):
    return field.type_name[len(".draiosproto."):]

# these should probably be an enum at some point. SMAGENT-1977
def get_field_type(field, sub_aggregator_list):
    if field.name in sub_aggregator_list:
        if field.label is FieldDescriptor.LABEL_REPEATED:
            return 2 # repeated numeric aggregation
        else:
           return 1 # single numeric aggregation

    if field.type is FieldDescriptor.TYPE_MESSAGE:
        if field.label is FieldDescriptor.LABEL_REPEATED:
            # this is a map. map types are .draiosproto.<message_type>.<mangledfieldname>Entry
            # we'll just check for the dot in the type_name
            if "." in type_name(field):
                return 7 # map
            return 5 # repeated message
        return 3 #single message

    if field.label is FieldDescriptor.LABEL_REPEATED:
        return 4 # non-message repeated type

    return 6 # non-message single type

# generates a virtual function to aggregate a given field in a messagae
def generate_field_aggregator_function(message_name, field, sub_aggregator_list):
    # write the function header
    out = """    virtual void aggregate_%s(const draiosproto::%s& input, draiosproto::%s& output)
    {
""" % (field.name, message_name, message_name)

    if get_field_type(field, sub_aggregator_list) is 1:
        out += """        if (input.has_%s())
     {
         default_aggregate_value<decltype(input.%s()),
                                 decltype(*output.mutable_%s())>(input.%s(), *output.mutable_%s());
     }
""" % (field.name, field.name, sub_aggregator_list[field.name], field.name, sub_aggregator_list[field.name])

    if get_field_type(field, sub_aggregator_list) is 2:
        out += """        default_aggregate_list<decltype(input.%s()),
                               decltype(*output.mutable_%s())>(input.%s(), *output.mutable_%s());
""" % (field.name, sub_aggregator_list[field.name], field.name, sub_aggregator_list[field.name])

    if get_field_type(field, sub_aggregator_list) is 3:
        out += """        if (input.has_%s())
        {
            if (!m_%s_field_aggregator)
            {
                m_%s_field_aggregator = &m_builder.build_%s();
            }

            m_%s_field_aggregator->aggregate(input.%s(), *output.mutable_%s());
        }
""" % (field.name, field.name, field.name, type_name(field), field.name, field.name, field.name)

    if get_field_type(field, sub_aggregator_list) is 4:
        out += """        for (auto i : input.%s())
        {
            if (%s_cache.find(i) == %s_cache.end())
            {
                output.add_%s(i);
                %s_cache.insert(i);
            }
        }
""" % (field.name, field.name, field.name, field.name, field.name)

    # note: the "new" case is a bit tricky. Since the key of the map is/depends on the
    # message in the output protobuf, we have to aggregate into that protobuf BEFORE
    # we add the key to the map, and values that compromise the primary key should
    # never be changed after the initial set, otherwise you'll end up with duplicate
    # entries (and effectively a corrupt hashmap)
    if get_field_type(field, sub_aggregator_list) is 5:
        out += """        for (auto i : input.%s())
        {
            if (%s_map.find(&i) == %s_map.end())
            {
                auto new_entry = output.add_%s();
                agent_message_aggregator<draiosproto::%s>* new_aggregator = &m_builder.build_%s();
                new_aggregator->aggregate(i, *new_entry);
                %s_map.insert(
                    std::make_pair<draiosproto::%s*,
                                   std::pair<uint32_t,
                                             std::unique_ptr<agent_message_aggregator<draiosproto::%s>>>>(
                        std::move(new_entry),
                        std::make_pair<uint32_t,
                                       std::unique_ptr<agent_message_aggregator<draiosproto::%s>>>(
                            output.%s().size() - 1,
                            std::unique_ptr<agent_message_aggregator<draiosproto::%s>>(new_aggregator)
                        )
                    )
                );
            }
            else
            {
                %s_map[&i].second->aggregate(i, (*output.mutable_%s())[%s_map[&i].first]);
            }
        }
""" % (field.name, # for
       field.name, field.name, # if 
       field.name, # new_entry
       type_name(field), type_name(field), # new_aggregator
       field.name, # insert
       type_name(field), # make pair
       type_name(field), # unique ptr
       type_name(field), # unique ptr
       field.name, # output.size
       type_name(field), # unique ptr
       field.name, field.name, field.name) # else

    if get_field_type(field, sub_aggregator_list) is 6:
        if message_name in field_extension and \
           field.number in field_extension[message_name] and \
           field_extension[message_name][field.number] is OR:
            out+= """        if (input.has_%s())
        {
            output.set_%s(output.%s() | input.%s());
        }
""" % (get_adjusted_field_name(field.name), get_adjusted_field_name(field.name), get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))
        else: 
            out+= """        if (input.has_%s())
        {
            output.set_%s(input.%s());
        }
""" % (get_adjusted_field_name(field.name), get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))

    if get_field_type(field, sub_aggregator_list) is 7:
        pass

    # close the function
    out +="""    }

"""

    return out

# generates a function which iterates over fields in a message and invokes
# their aggregation function
def generate_message_aggregator_function(message, aggregator_targets, sub_aggregator_list):
    # function header
    out = """    virtual void aggregate(const draiosproto::%s& input, draiosproto::%s& output)
    {
""" % (message.name, message.name)

    # loop through fields and invoke aggregator
    for field in message.field:
        if field.name in aggregator_targets or \
           type_name(field) in skip or \
           get_field_type(field, sub_aggregator_list) is 7:
            continue
        out += """        aggregate_%s(input, output);
""" % (field.name)

    # close the function
    out +="""    }
"""

    return out

# generates a constructor function, which mainly has to construct all
# the sub-aggregators used by this class
def generate_constructor_function(message, aggregator_targets, sub_aggregator_list):
    out = ""

    # have to write the constructor, which will invoke the builder to allocate
    # the appropriate message type for each sub-message aggregator
    out += """
    %s_message_aggregator(const message_aggregator_builder& builder)
        : agent_message_aggregator(builder)
""" % message.name
    for field in message.field:
        if field.name in aggregator_targets or \
           type_name(field) in skip or \
           get_field_type(field, sub_aggregator_list) is 7:
            continue
        if get_field_type(field, sub_aggregator_list) is 3:
            out += """         ,m_%s_field_aggregator(nullptr)
""" % (field.name)

    out += """    {}
"""

    return out

def generate_destructor_function(message, aggregator_targets, sub_aggregator_list):
    out = ""

    out += """
    ~%s_message_aggregator()
    {
        reset();
    }
""" % message.name

    return out

def get_cpp_type(field):
    if field.type is FieldDescriptor.TYPE_DOUBLE:
        cpp_type = "double"
    elif field.type is FieldDescriptor.TYPE_FLOAT:
        cpp_type = "double"
    elif field.type is FieldDescriptor.TYPE_UINT64:
        cpp_type = "uint64_t"
    elif field.type is FieldDescriptor.TYPE_UINT32:
        cpp_type = "uint32_t"
    elif field.type is FieldDescriptor.TYPE_STRING:
        cpp_type = "std::string"
    elif field.type is FieldDescriptor.TYPE_BYTES:
        cpp_type = "std::string"
    elif field.type is FieldDescriptor.TYPE_ENUM:
        cpp_type = "uint32_t"
    else:
        cpp_type = "uh oh! Unsupported field type"

    return cpp_type

# generates the code for each message field, including supporting fields and functions
def generate_field_aggregations(message, sub_aggregator_list, aggregator_targets):
    out = ""

    for field in message.field:
        if field.name in aggregator_targets or \
           type_name(field) in skip or \
           get_field_type(field, sub_aggregator_list) is 7:
            continue

        # Single message just gets the aggregator for the field
        if get_field_type(field, sub_aggregator_list) is 3:
            out += """    agent_message_aggregator<draiosproto::%s>* m_%s_field_aggregator;
""" % (type_name(field), field.name)

        # Repeated non-message gets a set to know if entry exists
        if get_field_type(field, sub_aggregator_list) is 4:
            out += """    std::set<%s> %s_cache;
""" % (get_cpp_type(field), field.name)

        # Repeated message types need a map to index in output and corresponding aggregator
        if type_name(field) == message.name:
            function_namespace = ""
        else:
            function_namespace = "%s_message_aggregator::" % type_name(field)

        if get_field_type(field, sub_aggregator_list) is 5:
            # note: have to use unique ptr in cases where messages reference themselves
            out += """    std::unordered_map<draiosproto::%s*,
                       std::pair<uint32_t, std::unique_ptr<agent_message_aggregator<draiosproto::%s>>>,
                       %shasher,
                       %scomparer> %s_map;
""" % (type_name(field), type_name(field), function_namespace, function_namespace, field.name)

        # generate aggregation function
        out += generate_field_aggregator_function(message.name, field, sub_aggregator_list) 

    return out

# generates the reset function, which clears any state and resets all sub-aggregators
def generate_reset_function(message, aggregator_targets, sub_aggregator_list):
    out = ""

    out += """
    virtual void reset()
    {
"""
    
    for field in message.field:
        if field.name in aggregator_targets or \
           type_name(field) in skip or \
           get_field_type(field, sub_aggregator_list) is 7:
            continue

        if get_field_type(field, sub_aggregator_list) is 3:
            out += """        if (m_%s_field_aggregator)
        {
            delete m_%s_field_aggregator;
        }
        m_%s_field_aggregator = nullptr;
""" % (field.name, field.name, field.name)

        if get_field_type(field, sub_aggregator_list) is 4:
            out += """        %s_cache.clear();
""" % field.name

        if get_field_type(field, sub_aggregator_list) is 5:
            out += """       %s_map.clear();
""" % field.name
    
    out += """    }

"""

    return out

# generates hasher and comparer functions so this class can be used as a key in a map/set
def generate_key_functions(message, aggregator_targets, sub_aggregator_list):
    hasher = """    struct hasher {
        size_t operator()(const draiosproto::%s* input) const
        {
            size_t hash = 0;

""" % message.name

    comparer = """    struct comparer {
        bool operator()(const draiosproto::%s* lhs, const draiosproto::%s* rhs) const
        {
            bool result = true;

""" % (message.name, message.name)

    # create the functions on fields that are in the primary key. Obviously we just
    # compare for the comparison function, but for the hash function, we're going to
    # be lazy and multiply + xor the fields in the key. This should be good enough
    for field in message.field:
        if message.name in field_extension and \
           field.number in field_extension[message.name] and \
           field_extension[message.name][field.number] is PRIMARY_KEY:
            if get_field_type(field, sub_aggregator_list) is 6:
                hasher += """            hash = (hash * 7) ^ std::hash<%s>()(input->%s());
""" % (get_cpp_type(field), get_adjusted_field_name(field.name))
                comparer += """            result &= lhs->%s() == rhs->%s();
""" % (get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))
            elif get_field_type(field, sub_aggregator_list) is 3:
                hasher += """            hash = (hash * 9) ^ %s_message_aggregator::hasher()(&input->%s());
""" % (type_name(field), get_adjusted_field_name(field.name))
                comparer += """            result &= %s_message_aggregator::comparer()(&lhs->%s(), &rhs->%s());
""" % (type_name(field), get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))
            elif get_field_type(field, sub_aggregator_list) is 4:
                hasher += """            for (auto i : input->%s())
            {
                hash = (hash * 7) ^ std::hash<%s>()(i);
            }
""" % (field.name, get_cpp_type(field))
                comparer += """            if (lhs->%s().size() != rhs->%s().size())
            {
                return false;
            }
            for (size_t i = 0; i < lhs->%s().size(); ++i)
            {
                result &= (lhs->%s()[i] == rhs->%s()[i]);
            }
""" % (field.name, field.name, field.name, field.name, field.name)

            elif get_field_type(field, sub_aggregator_list) is 5:
                hasher += """            for (auto i : input->%s())
            {
                hash = (hash * 9) ^ %s_message_aggregator::hasher()(&i);
            }
""" % (field.name, type_name(field))
                comparer += """            if (lhs->%s().size() != rhs->%s().size())
            {
                return false;
            }
            for (size_t i = 0; i < lhs->%s().size(); ++i)
            {
                result &= %s_message_aggregator::comparer()(&lhs->%s()[i], &rhs->%s()[i]);
            }
""" % (field.name, field.name, field.name, type_name(field), field.name, field.name)

            else:
                hasher += "uhoh! Unsupported primary key type."
                comparer += "uhoh! Unsupported primary key type."

    comparer += """ 
            return result;
        }
    };
"""
    hasher +="""
            return hash;
        }
    };
"""

    return hasher + comparer

def generate_class(message):
    if message.name in skip:
        return ""

    sub_aggregator_list, aggregator_targets = generate_aggregator_list(message)

    # write the class header
    out = """class %s_message_aggregator : public agent_message_aggregator<draiosproto::%s>
{
public:
""" % (message.name, message.name)

    # hash/compare functions must come first since aggregations might depend on them
    if message.name in key_messages:
        out += generate_key_functions(message, aggregator_targets, sub_aggregator_list)

    out += """
protected: 
"""
    out += generate_field_aggregations(message, sub_aggregator_list, aggregator_targets)

    out += """
public:
"""

    # now write the implementation of the aggregate function for the message
    out += generate_message_aggregator_function(message, aggregator_targets, sub_aggregator_list)

    out += generate_constructor_function(message, aggregator_targets, sub_aggregator_list)
    out += generate_destructor_function(message, aggregator_targets, sub_aggregator_list)

    out += generate_reset_function(message, aggregator_targets, sub_aggregator_list)


    #close the class
    out += """}; // %s_message_aggregator


""" % (message.name)

    # so now we have
    return out

def find_primary_keys(message):
    # prevents infinite recursion
    if message.name in key_messages:
        return

    key_messages.add(message.name)

    # recurse on fields that are messages and in the primary key
    for field in message.field:
        if message.name in field_extension and \
           field.number in field_extension[message.name] and \
           field_extension[message.name][field.number] is PRIMARY_KEY and \
           get_field_type(field, {}) is 3:
            find_primary_keys(index_dict[type_name(field)][0])
            


def generate_code(request, response):
    builder_header = response.file.add()
    builder_header.name = 'draios.proto_builder.h'
    builder_header.content = """#pragma once

// This file contains the API for building aggregators. If any of the virtual methods
// of aggregators are overridden, this builder must be subclassed and the appropriate
// build method overridden allocating the correct version of the aggregator.
// See draios-aggregator-plugin.py.

#include "aggregator_base.h"

class message_aggregator_builder
{
public:
"""

    aggregator_header = response.file.add()
    aggregator_header.name = 'draios.proto.h'
    aggregator_header.content = """#pragma once

// This file contains code for performing aggregations on the agent-emitted protobuf.
// See draios-aggregator-plugin.py.

#include "aggregator_base.h"
#include "%s"


""" % builder_header.name

    builder_source = response.file.add()
    builder_source.name = 'draios.proto_builder.cpp'
    builder_source.content = """#include "%s"
#include "%s"

""" % (aggregator_header.name, builder_header.name)

    # pass 1 of the protobuf: build a map allowing us to easily access fields
    # and messages.
    # index_dict[<message_name>][0] => the message object
    # index_dict[<message_name>][<field_number>] => the field object
    for proto_file in request.proto_file:
        for message, package in traverse(proto_file):
            if isinstance(message, DescriptorProto):
                # first step, generate entry in the index dict
                index_dict[message.name] = {}
                index_dict[message.name][0] = message
                for field in message.field:
                    index_dict[message.name][field.number] = field

    # pass 2 of the protobuf: identify the messages types which are repeated fields in
    # other messages. This must be done recursively, and thus requires a second pass
    for proto_file in request.proto_file:
        for message, package in traverse(proto_file):
            if isinstance(message, DescriptorProto):
                for field in message.field:
                    if get_field_type(field, {}) is 5:
                        find_primary_keys(index_dict[type_name(field)][0])
                        
    # pass 3 of the protobuf: generate the actual code
    for proto_file in request.proto_file:
        for message, package in traverse(proto_file):
            if isinstance(message, DescriptorProto):
                # generate the class for this message
                aggregator_header.content += generate_class(message)

                # generate the builders for this field
                if message.name not in skip:
                    builder_header.content += """    virtual agent_message_aggregator<draiosproto::%s>& build_%s() const;
""" % (message.name, message.name) 
                    builder_source.content += """agent_message_aggregator<draiosproto::%s>&
message_aggregator_builder::build_%s() const
{
    return *(new %s_message_aggregator(*this));
}

""" % (message.name, message.name, message.name)    
            elif isinstance(message, EnumDescriptorProto):
                pass
            elif isinstance(message, tuple):
                pass
            else:
                aggregator_header.content += "uhoh Unsupported message meta-type\n"

    builder_header.content += """};"""


if __name__ == '__main__':
    # Read request message from stdin
    data = sys.stdin.read()

    # Parse request
    request = plugin.CodeGeneratorRequest()
    request.ParseFromString(data)

    # Create response
    response = plugin.CodeGeneratorResponse()

    # Generate code
    generate_code(request, response)

    # Serialise response message
    output = response.SerializeToString()

    # Write to stdout
    sys.stdout.write(output)
