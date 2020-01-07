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

# This set contains tuples of every (message, field) pair which is limited, and thus
# for which the builder needs a construction parameter and accessor
limited_messages = set()

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

# generates a set of fields which adhere to certain properties.
# this is helpful rather than directly looking up the entries in the field_extension map so
# you don't have to worry about performing a null check every time
# limited: set of repeated fields which can have their size limited
# unique: set of repeated fields which the client guarantees will be unique within
#         a given individual protobuf. does not apply across protobufs
# aggregation_targets: set of fields which are targets for aggregations from other fields
# aggregation_map: map from field name -> field name of fields which get aggregated
def generate_tags_list(message):
    limited = set()
    unique = set()
    aggregation_targets = set()
    aggregation_map = {}

    if message.name not in field_extension:
        return limited, unique, aggregation_targets, aggregation_map

    for key, value in field_extension[message.name].items():
        if type(value) is set:
            if LIMITED in value:
                limited.add(index_dict[message.name][key].name)
            if UNIQUE in value:
                unique.add(index_dict[message.name][key].name)
        elif value is OR:
            continue
        else:
            aggregation_map[index_dict[message.name][key].name] = index_dict[message.name][value].name
            aggregation_targets.add(index_dict[message.name][value].name)

    return limited, unique, aggregation_targets, aggregation_map

# This is ugly. There are a few fields we have that are protoc reserved keywords. It gets
# around this by adding a _. Use this function when accessing fields in the protobuf
def get_adjusted_field_name(name):
    if name == "namespace":
        return "namespace_"
    return name

# field type has the package prepended. strip it to get the actual type
def type_name(field):
    return field.type_name[len(".draiosproto."):]

AGG_TYPE_SINGLE_NUMERIC_AGGREGATED = 1
AGG_TYPE_REPEATED_NUMERIC_AGGREGATED = 2
AGG_TYPE_SINGLE_MESSAGE = 3
AGG_TYPE_REPEATED_NUMERIC = 4
AGG_TYPE_REPEATED_MESSAGE = 5
AGG_TYPE_SINGLE_NUMERIC = 6
AGG_TYPE_MAP = 7
AGG_TYPE_SINGLE_STRING = 8
AGG_TYPE_REPEATED_STRING = 9

def get_field_type(field, sub_aggregator_list):
    if field.name in sub_aggregator_list:
        if field.label is FieldDescriptor.LABEL_REPEATED:
            return AGG_TYPE_REPEATED_NUMERIC_AGGREGATED
        else:
           return AGG_TYPE_SINGLE_NUMERIC_AGGREGATED

    if field.type is FieldDescriptor.TYPE_MESSAGE:
        if field.label is FieldDescriptor.LABEL_REPEATED:
            # this is a map. map types are .draiosproto.<message_type>.<mangledfieldname>Entry
            # we'll just check for the dot in the type_name
            if "." in type_name(field):
                return AGG_TYPE_MAP
            return AGG_TYPE_REPEATED_MESSAGE
        return AGG_TYPE_SINGLE_MESSAGE

    if field.label is FieldDescriptor.LABEL_REPEATED:
        if field.type is FieldDescriptor.TYPE_STRING:
            return AGG_TYPE_REPEATED_STRING
        return AGG_TYPE_REPEATED_NUMERIC

    if field.type is FieldDescriptor.TYPE_STRING:
        return AGG_TYPE_SINGLE_STRING

    return AGG_TYPE_SINGLE_NUMERIC

# generates a map from field name->type
def generate_type_map(message, sub_aggregator_list):
    field_map = {}
    for field in message.field:
        field_map[field.name] = get_field_type(field, sub_aggregator_list)

    return field_map

# generates a virtual function to aggregate a given field in a message
def generate_field_aggregator_function(message_name, field, type_map, aggregation_map, unique):
    # why two field names? PB will adjust field names if you happened to use a reserved
    # keyword. we don't internally, so technically all PB apis should use the adjusted
    # name, and all sysdig APIs should use the un-adjusted name.
    string_map = {"field_name": field.name,
                  "pb_field_name": get_adjusted_field_name(field.name),
                  "field_type": type_name(field),
                  "message_name": message_name}

    if field.name in aggregation_map:
        string_map["target_name"] = aggregation_map[field.name]

    # write the function header
    out = """    virtual void aggregate_%(field_name)s(draiosproto::%(message_name)s& input,
        draiosproto::%(message_name)s& output,
        bool in_place)
    {
""" % string_map

    if type_map[field.name] is AGG_TYPE_SINGLE_NUMERIC_AGGREGATED:
        out += """        if (input.has_%(field_name)s())
        {
            default_aggregate_value<decltype(input.%(field_name)s()),
                                    decltype(*output.mutable_%(target_name)s())>(input.%(field_name)s(), *output.mutable_%(target_name)s());
            if (in_place) {
                input.clear_%(field_name)s();
            }
        }
""" % string_map

    if type_map[field.name] is AGG_TYPE_REPEATED_NUMERIC_AGGREGATED:
        out += """        default_aggregate_list<decltype(input.%(field_name)s()),
                                                 decltype(*output.mutable_%(target_name)s())>(input.%(field_name)s(), *output.mutable_%(target_name)s());
        if (in_place) {
            input.clear_%(field_name)s();
        }
""" % string_map

    if type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
        out += """        if (input.has_%(field_name)s())
        {
            if (!m_%(field_name)s_field_aggregator)
            {
                m_%(field_name)s_field_aggregator = &m_builder.build_%(field_type)s();
            }

            if (in_place)
            {
                m_%(field_name)s_field_aggregator->aggregate(*output.mutable_%(field_name)s(), *output.mutable_%(field_name)s(), true);
            } else {
                if (!output.has_%(field_name)s()) {
                    output.set_allocated_%(field_name)s(input.release_%(field_name)s());
                    m_%(field_name)s_field_aggregator->aggregate(*output.mutable_%(field_name)s(), *output.mutable_%(field_name)s(), true);
                } else {
                    m_%(field_name)s_field_aggregator->aggregate(*input.mutable_%(field_name)s(), *output.mutable_%(field_name)s(), false);
                }
            }
        }
""" % string_map

    if type_map[field.name] is AGG_TYPE_REPEATED_NUMERIC:
        if field.name in unique:
            # this is not implemented as there are no users, but the rough outline
            # is if in place, nothing
            # to do. otherwise build the cache from the existing output entry, then
            # do the same as the non-unique case.
            out += """ NOT IMPLEMENTED """
        else: # not unique
            # the general way the loop works is we have a pointer to the next element
            # we want to "insert" (the leader) as well as the last element in the array
            # that is unique. If the leader is a duplicate, we swap it with the trailer,
            # insert it, and then find a new trailer. Must use signed-ints, as
            # a corner case if all numbers are the same, trailer will end up at -1 after
            # first pass.
            out += """        if (in_place) {
            int32_t leader = 0;
            for (int32_t trailer = input.%(field_name)s().size() - 1; leader <= trailer; leader++) {
                // thing is duplicate. swap it with trailer, which is guaranteed to not be
                if (%(field_name)s_cache.find(input.%(field_name)s()[leader]) != %(field_name)s_cache.end()) {
                    input.mutable_%(field_name)s()->SwapElements(leader, trailer);
                }
                // now thing is guaranteed to not be in cache, so add it
                %(field_name)s_cache.insert(input.%(field_name)s()[leader]);
                // move the trailer to point to a new valid input
                while (trailer >= leader && %(field_name)s_cache.find(input.%(field_name)s()[trailer]) != %(field_name)s_cache.end()) {
                    trailer--;
                }
            }
            // delete the duplicate subrange
            output.mutable_%(field_name)s()->Truncate(%(field_name)s_cache.size());
        } else {
            for (auto i : input.%(field_name)s())
            {
                if (%(field_name)s_cache.find(i) == %(field_name)s_cache.end())
                {
                    output.add_%(field_name)s(i);
                    %(field_name)s_cache.insert(i);
                }
            }
        }
""" % string_map

    # note: the "new" case is a bit tricky. Since the key of the map is/depends on the
    # message in the output protobuf, we have to aggregate into that protobuf BEFORE
    # we add the key to the map, and values that compromise the primary key should
    # never be changed after the initial set, otherwise you'll end up with duplicate
    # entries (and effectively a corrupt hashmap)
    if type_map[field.name] is AGG_TYPE_REPEATED_MESSAGE:
        if field.name in unique:
            out += """        if (in_place) {
            // create aggregators, recursively invoke
            for (uint32_t i = 0; i < input.%(field_name)s().size(); i++) {
                %(field_name)s_vector.push_back(std::unique_ptr<agent_message_aggregator<draiosproto::%(field_type)s>>(&m_builder.build_%(field_type)s()));
                %(field_name)s_vector[i]->aggregate((*input.mutable_%(field_name)s())[i], (*output.mutable_%(field_name)s())[i], true);
            }
        } else {
            // will need to build map on second time through
            if (%(field_name)s_map.size() != output.%(field_name)s().size()) {
                for (uint32_t i = 0; i < output.%(field_name)s().size(); i++) {
                    %(field_name)s_map.insert(std::pair<const draiosproto::%(field_type)s*, uint32_t>(&output.%(field_name)s()[i], i));
                }
            }
            for (uint32_t i = 0; i < input.%(field_name)s().size(); i++) {
                auto entry = &(*input.mutable_%(field_name)s())[i];
                if (%(field_name)s_map.find(entry) == %(field_name)s_map.end()) {
                    %(field_name)s_vector.push_back(std::unique_ptr<agent_message_aggregator<draiosproto::%(field_type)s>>(&m_builder.build_%(field_type)s()));
                    auto new_entry = new draiosproto::%(field_type)s(std::move(*entry));
                    %(field_name)s_vector[%(field_name)s_vector.size() - 1]->aggregate(*new_entry, *new_entry, true);
                    output.mutable_%(field_name)s()->UnsafeArenaAddAllocated(new_entry);
                    %(field_name)s_map.insert(std::pair<const draiosproto::%(field_type)s*, uint32_t>(&output.%(field_name)s()[output.%(field_name)s().size() - 1], output.%(field_name)s().size() - 1));
                } else {
                    %(field_name)s_vector[%(field_name)s_map[entry]]->aggregate(*entry, (*output.mutable_%(field_name)s())[%(field_name)s_map[entry]], false);
                }
            }
        }
""" % string_map
        else:
            out += """        if (in_place) {
            int32_t leader = 0;
            for (int32_t trailer = input.%(field_name)s().size() - 1; leader <= trailer; leader++) {
                // thing is duplicate. swap it with trailer, which is guaranteed to not be
                auto entry = &(*input.mutable_%(field_name)s())[leader];
                if (%(field_name)s_map.find(entry) != %(field_name)s_map.end()) {
                    // We could in theory perform the duplicate aggregation while doing this (or the trailer decrement below)
                    // but this code is difficult to reason about as is, so we'll just do them all in one pass at the end
                    input.mutable_%(field_name)s()->SwapElements(leader, trailer);
                    entry = &(*input.mutable_%(field_name)s())[leader];
                }
                // now thing is guaranteed to not be in cache, so add it
                %(field_name)s_vector.push_back(std::unique_ptr<agent_message_aggregator<draiosproto::%(field_type)s>>(&m_builder.build_%(field_type)s()));
                %(field_name)s_vector[%(field_name)s_vector.size() - 1]->aggregate(*entry, *entry, true);
                %(field_name)s_map.insert(std::pair<const draiosproto::%(field_type)s*, uint32_t>(entry, leader));
                // move the trailer to point to a new valid input
                while (trailer >= leader && %(field_name)s_map.find(&input.%(field_name)s()[trailer]) != %(field_name)s_map.end()) {
                    trailer--;
                }
            }
            // aggregate the duplicates
            for (uint32_t i = %(field_name)s_map.size(); i < output.%(field_name)s().size(); i++)
            {
                uint32_t target_index = %(field_name)s_map[&output.%(field_name)s()[i]];
                %(field_name)s_vector[target_index]->aggregate((*output.mutable_%(field_name)s())[i], (*output.mutable_%(field_name)s())[target_index], false);
            }
            // delete the duplicate subrange
            output.mutable_%(field_name)s()->DeleteSubrange(%(field_name)s_map.size(), output.%(field_name)s().size() - %(field_name)s_map.size());
        } else {
            for (uint32_t i = 0; i < input.%(field_name)s().size(); i++) {
                auto entry = &(*input.mutable_%(field_name)s())[i];
                if (%(field_name)s_map.find(entry) == %(field_name)s_map.end()) {
                    %(field_name)s_vector.push_back(std::unique_ptr<agent_message_aggregator<draiosproto::%(field_type)s>>(&m_builder.build_%(field_type)s()));
                    auto new_entry = new draiosproto::%(field_type)s(std::move(*entry));
                    %(field_name)s_vector[%(field_name)s_vector.size() - 1]->aggregate(*new_entry, *new_entry, true);
                    output.mutable_%(field_name)s()->UnsafeArenaAddAllocated(new_entry);
                    %(field_name)s_map.insert(std::pair<const draiosproto::%(field_type)s*, uint32_t>(&output.%(field_name)s()[output.%(field_name)s().size() - 1], output.%(field_name)s().size() - 1));
                } else {
                    %(field_name)s_vector[%(field_name)s_map[entry]]->aggregate(*entry, (*output.mutable_%(field_name)s())[%(field_name)s_map[entry]], false);
                }
            }
        }
"""  % string_map

    if type_map[field.name] is AGG_TYPE_SINGLE_NUMERIC:
        if message_name in field_extension and \
           field.number in field_extension[message_name] and \
           field_extension[message_name][field.number] is OR:
            out+= """        if (input.has_%(field_name)s())
        {
            output.set_%(field_name)s(output.%(field_name)s() | input.%(field_name)s());
        }
""" % string_map
        else: 
            out+= """        if (!output.has_%(field_name)s() && input.has_%(field_name)s())
        {
            output.set_%(field_name)s(input.%(field_name)s());
        }
""" % string_map

    if type_map[field.name] is AGG_TYPE_MAP:
        pass

    if type_map[field.name] is AGG_TYPE_SINGLE_STRING:
        out+= """        if (!output.has_%(pb_field_name)s() && input.has_%(pb_field_name)s())
        {
            output.set_allocated_%(pb_field_name)s(input.release_%(pb_field_name)s());
        }
""" % string_map

    if type_map[field.name] is AGG_TYPE_REPEATED_STRING:
        if field.name in unique:
            # implementation would be similar to AGG_TYPE_REPEATED_NUMERIC
            out += """ NOT IMPLEMENTED """
        else: # not unique
            # see AGG_TYPE_REPEATED_NUMERIC for description of algorithm
            out += """        if (in_place) {
            int32_t leader = 0;
            for (int32_t trailer = input.%(field_name)s().size() - 1; leader <= trailer; leader++) {
                // thing is duplicate. swap it with trailer, which is guaranteed to not be
                if (%(field_name)s_cache.find(&input.%(field_name)s()[leader]) != %(field_name)s_cache.end()) {
                    input.mutable_%(field_name)s()->SwapElements(leader, trailer);
                }
                // now thing is guaranteed to not be in cache, so add it
                %(field_name)s_cache.insert(&input.%(field_name)s()[leader]);
                // move the trailer to point to a new valid input
                while (trailer >= leader && %(field_name)s_cache.find(&input.%(field_name)s()[trailer]) != %(field_name)s_cache.end()) {
                    trailer--;
                }
            }
            // delete the duplicate subrange
            output.mutable_%(field_name)s()->DeleteSubrange(%(field_name)s_cache.size(), output.%(field_name)s().size() - %(field_name)s_cache.size());
        } else {
            for (auto& i : input.%(field_name)s())
            {
                if (%(field_name)s_cache.find(&i) == %(field_name)s_cache.end())
                {
                    output.add_%(field_name)s(std::move(i));
                    %(field_name)s_cache.insert(&output.%(field_name)s()[output.%(field_name)s().size() - 1]);
                }
            }
        }
""" % string_map

    # close the function
    out +="""    }

"""

    return out

# generates a function which iterates over fields in a message and invokes
# their aggregation function
def generate_message_aggregator_function(message, type_map, aggregation_targets):
    # function header
    out = """    virtual void aggregate(draiosproto::%s& input,
                           draiosproto::%s& output,
                           bool in_place)
    {
""" % (message.name, message.name)

    # loop through fields and invoke aggregator
    for field in message.field:
        if field.name in aggregation_targets or \
           type_name(field) in skip or \
           type_map[field.name] is AGG_TYPE_MAP:
            continue
        out += """        aggregate_%s(input, output, in_place);
""" % (field.name)

    # close the function
    out +="""    }
"""

    return out

# generates a function which iterates over fields in a message and invokes
# their limit functions. We also invoke any "dedicated" limit functions which must
# exist based on the limit list
def generate_limiters(message, type_map, limited):
    out = "public:\n"

    # generate declarations for limiters to be implemented manually
    for field in message.field:
        if field.name in limited:
            out += """    static void limit_%s(draiosproto::%s& output, uint32_t limit);
""" % (field.name, message.name)
            limited_messages.add((message.name, field.name));
    
    # function header
    out += """    static void limit(const message_aggregator_builder& builder,
                      draiosproto::%s& output)
    {
""" % (message.name)

    # loop through fields and invoke our internal limiter if necessary
    for field in message.field:
        if field.name in limited:
            out += """        if (builder.get_%s_%s_limit() < output.%s().size()) {
            limit_%s(output, builder.get_%s_%s_limit());
        }
""" % (message.name, field.name, field.name, field.name, message.name, field.name)

    # loop through fields, and invoke limiter on sub-messages
    for field in message.field:
        if type_name(field) not in skip:
            if type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
                out += """        %s_message_aggregator::limit(builder, *output.mutable_%s());
""" % (type_name(field), field.name)
            if type_map[field.name] is AGG_TYPE_REPEATED_MESSAGE:
                out += """        for (auto& i : *output.mutable_%s()) {
            %s_message_aggregator::limit(builder, i);
        }
""" % (field.name, type_name(field))



    # close the function
    out +="""    }
"""

    return out

# generates a constructor function, which mainly has to construct all
# the sub-aggregators used by this class
def generate_constructor_function(message, type_map, aggregation_targets):
    out = ""

    # have to write the constructor, which will invoke the builder to allocate
    # the appropriate message type for each sub-message aggregator
    out += """
    %s_message_aggregator(const message_aggregator_builder& builder)
        : agent_message_aggregator(builder)
""" % message.name
    for field in message.field:
        if field.name in aggregation_targets or \
           type_name(field) in skip or \
           type_map[field.name] is AGG_TYPE_MAP:
            continue
        if type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
            out += """         ,m_%s_field_aggregator(nullptr)
""" % (field.name)

    out += """    {}
"""

    return out

def generate_destructor_function(message):
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
def generate_field_aggregations(message, type_map, aggregation_map, aggregation_targets, unique):
    out = ""

    for field in message.field:
        if field.name in aggregation_targets or \
           type_name(field) in skip or \
           type_map[field.name] is AGG_TYPE_MAP:
            continue

        # Single message just gets the aggregator for the field
        if type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
            out += """    agent_message_aggregator<draiosproto::%s>* m_%s_field_aggregator;
""" % (type_name(field), field.name)

        # Repeated non-message gets a set to know if entry exists
        if type_map[field.name] is AGG_TYPE_REPEATED_NUMERIC:
            out += """    std::set<%s> %s_cache;
""" % (get_cpp_type(field), field.name)
        if type_map[field.name] is AGG_TYPE_REPEATED_STRING:
            out += """    std::set<const std::string*, agent_message_aggregator::string_pointer_comparer> %s_cache;
""" % field.name
        if type_map[field.name] is AGG_TYPE_REPEATED_MESSAGE:
            if type_name(field) == message.name:
                function_namespace = ""
            else:
                function_namespace = "%s_message_aggregator::" % type_name(field)

            # note: have to use unique ptr in cases where messages reference themselves
            out += """    std::unordered_map<const draiosproto::%s*,
                       uint32_t,
                       %shasher,
                       %scomparer> %s_map;
    std::vector<std::unique_ptr<agent_message_aggregator<draiosproto::%s>>> %s_vector;
""" % (type_name(field), function_namespace, function_namespace, field.name, type_name(field), field.name)

        # generate aggregation function
        out += generate_field_aggregator_function(message.name, field, type_map, aggregation_map, unique) 

    return out

# generates the reset function, which clears any state and resets all sub-aggregators
def generate_reset_function(message, type_map, aggregation_targets):
    out = ""

    out += """
    virtual void reset()
    {
"""
    
    for field in message.field:
        if field.name in aggregation_targets or \
           type_name(field) in skip or \
           type_map[field.name] is AGG_TYPE_MAP:
            continue

        if type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
            out += """        if (m_%s_field_aggregator)
        {
            delete m_%s_field_aggregator;
        }
        m_%s_field_aggregator = nullptr;
""" % (field.name, field.name, field.name)

        if type_map[field.name] in {AGG_TYPE_REPEATED_NUMERIC, AGG_TYPE_REPEATED_STRING}:
            out += """        %s_cache.clear();
""" % field.name

        if type_map[field.name] is AGG_TYPE_REPEATED_MESSAGE:
            out += """        %s_map.clear();
        %s_vector.clear();
""" % (field.name, field.name)
    
    out += """    }

"""

    return out

# generates hasher and comparer functions so this class can be used as a key in a map/set
def generate_key_functions(message, type_map):
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
           type(field_extension[message.name][field.number]) is set and \
           PRIMARY_KEY in field_extension[message.name][field.number]:
            if type_map[field.name] in {AGG_TYPE_SINGLE_NUMERIC, AGG_TYPE_SINGLE_STRING}:
                hasher += """            hash = (hash * 7) ^ std::hash<%s>()(input->%s());
""" % (get_cpp_type(field), get_adjusted_field_name(field.name))
                comparer += """            result &= lhs->%s() == rhs->%s();
""" % (get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))

            elif type_map[field.name] is AGG_TYPE_SINGLE_MESSAGE:
                hasher += """            hash = (hash * 9) ^ %s_message_aggregator::hasher()(&input->%s());
""" % (type_name(field), get_adjusted_field_name(field.name))
                comparer += """            result &= %s_message_aggregator::comparer()(&lhs->%s(), &rhs->%s());
""" % (type_name(field), get_adjusted_field_name(field.name), get_adjusted_field_name(field.name))

            elif type_map[field.name] in {AGG_TYPE_REPEATED_NUMERIC, AGG_TYPE_REPEATED_STRING}:
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

            elif type_map[field.name] is AGG_TYPE_REPEATED_MESSAGE:
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
                hasher += "uhoh! Unsupported primary key type %d." % type_map[field.name]
                comparer += "uhoh! Unsupported primary key type %d." % type_map[field.name]


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

    limited, unique, aggregation_targets, aggregation_map = generate_tags_list(message)
    type_map = generate_type_map(message, aggregation_map)

    # write the class header
    out = """class %s_message_aggregator : public agent_message_aggregator<draiosproto::%s>
{
public:
""" % (message.name, message.name)

    # hash/compare functions must come first since aggregations might depend on them
    if message.name in key_messages:
        out += generate_key_functions(message, type_map)

    out += """
protected:
"""
    out += generate_field_aggregations(message, type_map, aggregation_map, aggregation_targets, unique)

    out += """
public:
"""

    # now write the implementation of the aggregate function for the message
    out += generate_message_aggregator_function(message, type_map, aggregation_targets)
    out += generate_limiters(message, type_map, limited)
    out += generate_constructor_function(message, type_map, aggregation_targets)
    out += generate_destructor_function(message)
    out += generate_reset_function(message, type_map, aggregation_targets)


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
           type(field_extension[message.name][field.number]) is set and \
           PRIMARY_KEY in field_extension[message.name][field.number] and \
           get_field_type(field, {}) in {AGG_TYPE_SINGLE_MESSAGE, AGG_TYPE_REPEATED_MESSAGE}:
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
                    if get_field_type(field, {}) is AGG_TYPE_REPEATED_MESSAGE:
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

    # write the stuff for the limiters
    builder_header.content += """
    
private:
"""
    for limit in limited_messages:
        builder_header.content += """    uint32_t m_%s_%s_limit;
""" % (limit[0], limit[1])

    builder_header.content += """
public:
"""
    for limit in limited_messages:
        builder_header.content += """    uint32_t get_%s_%s_limit() const {
        return m_%s_%s_limit;
    }
""" % (limit[0], limit[1], limit[0], limit[1])
        builder_header.content += """    void set_%s_%s_limit(uint32_t limit) {
        m_%s_%s_limit = limit;
    }
""" % (limit[0], limit[1], limit[0], limit[1])


    #generate a constructor which just sets everything to infinite limit
    builder_header.content += """
    message_aggregator_builder() :
"""
    
    for i, limit in enumerate(limited_messages):
        if i is  not 0:
            builder_header.content += """,
"""
        builder_header.content += """        m_%s_%s_limit(UINT32_MAX)""" % (limit[0], limit[1])

    builder_header.content += "\n    {}\n\n"
   
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
