--[[
Copyright (C) 2013-2014 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

-- Chisel description
description = "multidimensional table generator."
short_description = "multidimensional table generator"
category = "IO"
hidden = true

-- Chisel argument list
args = 
{
	{
		name = "keys", 
		description = "comma-separated list of filter fields to use for grouping", 
		argtype = "string"
	},
	{
		name = "keydescs", 
		description = "comma separated list of human readable descriptions for the key", 
		argtype = "string"
	},
	{
		name = "keydefaults", 
		description = "comma separated list of default values for keys. If not specified or -, a default value is used when the key is not present", 
		argtype = "string"
	},
	{
		name = "values", 
		description = "comma separated list of values to count for every key", 
		argtype = "string"
	},
	{
		name = "valuedescs", 
		description = "comma separated list of human readable descriptions for the values", 
		argtype = "string"
	},
	{
		name = "valueoperations", 
		description = "comma separated list of operations to apply to values. Valid operations are 'SUM', 'AVG', 'MIN', 'MAX'.", 
		argtype = "string"
	},
	{
		name = "valueunits", 
		description = "how to render the values in the result. Can be 'bytes', 'time', 'timepct', or 'none'.", 
		argtype = "string"
	},
	{
		name = "valuedefaults", 
		description = "comma separated list of default values for keys. If not specified or -, a default value is used when the value is not present.", 
		argtype = "string"
	},
	{
		name = "filter", 
		description = "the filter to apply", 
		argtype = "string"
	},
	{
		name = "top_number", 
		description = "maximum number of elements to display", 
		argtype = "string"
	},
	{
		name = "do_diff", 
		description = "'true' if the script should perform a diff among the two input trace files, 'false' otherwise.", 
		argtype = "bool"
	},
}

require "common"
dcube = require "datacube"
require "deltas"
terminal = require "ansiterminal"

grtable = {}
filter = ""
islive = false
fkeys = {}
run_cnt = 0

vizinfo = 
{
	key_fld = {},
	key_desc = {},
	key_defaults = nil,
	value_fld = {},
	value_desc = {},
	value_operations = {},
	value_defaults = nil,
	valueunits = {},
	top_number = 0,
	output_format = "normal",
	do_diff = false
}

-- Argument notification callback
function on_set_arg(name, val)
	if name == "keys" then
		vizinfo.key_fld = split(val, ",")		
		return true
	elseif name == "keydescs" then
		vizinfo.key_desc = split(val, ",")
		return true
	elseif name == "keydefaults" then
		if val ~= "-" and val ~= "" then
			vizinfo.key_defaults = split(val, ",")

			if #vizinfo.key_fld ~= #vizinfo.key_defaults then
				print("error: number of entries in keys different from number entries in keydefaults")
				return false
			end
		
			local noneset = true
			for i, v in ipairs(vizinfo.key_defaults) do
				if vizinfo.key_defaults[i] == "" then
					vizinfo.key_defaults[i] = nil
				else
					noneset = false
				end
			end
			
			if noneset then
				vizinfo.key_defaults = nil
			end
		end
					
		return true
	elseif name == "values" then
		vizinfo.value_fld = split(val, ",")
		return true
	elseif name == "valuedescs" then
		vizinfo.value_desc = split(val, ",")
		return true
	elseif name == "valueoperations" then
		vizinfo.value_operations = split(val, ",")
		return true
	elseif name == "valueunits" then
		vizinfo.valueunits = split(val, ",")
		return true
	elseif name == "valuedefaults" then
		if val ~= "-" and val ~= "" then
			vizinfo.value_defaults = split(val, ",")
		end
		return true
	elseif name == "filter" then
		if val ~= "-" and val ~= "" then
			filter = val
		end
		return true
	elseif name == "top_number" then
		vizinfo.top_number = tonumber(val)
		return true
	elseif name == "do_diff" then
		if val == 'true' then 
			vizinfo.do_diff = true
		end
		return true
	end

	return false
end

function on_init()
	run_cnt = run_cnt + 1
	
	dcube.set_viz_info(vizinfo)

	if #vizinfo.key_fld ~= #vizinfo.key_desc then
		print("error: number of entries in keys different from number entries in keydescs")
		return false
	end
	
	if #vizinfo.value_fld ~= #vizinfo.value_desc then
		print("error: number of entries in values different from number entries in valuedescs")
		return false
	end
	
	if #vizinfo.value_fld ~= #vizinfo.value_operations then
		print("error: number of entries in values different from number entries in valueoperations")
		return false
	end
	
	if #vizinfo.value_fld ~= #vizinfo.valueunits then
		print("error: number of entries in values different from number entries in valueunits")
		return false
	end
	
	if vizinfo.value_defaults ~= nil then
		if #vizinfo.value_fld ~= #vizinfo.value_defaults then
			print("error: number of entries in values different from number entries in valuedefaults")
			return false
		end
	end
		
	-- Request the fields we need
	for i, name in ipairs(vizinfo.key_fld) do
		fkeys[i] = chisel.request_field(name)
	end

	fvalue = chisel.request_field(vizinfo.value_fld[1])

	-- set the filter
	if filter ~= "" then
		chisel.set_filter(filter)
	end
	
	return true
end

function on_capture_start()
	islive = sysdig.is_live()
	vizinfo.output_format = sysdig.get_output_format()

	if islive then
		chisel.set_interval_s(1)
		if vizinfo.output_format ~= "json" then
			terminal.clearscreen()
			terminal.hidecursor()
		end
	end
	
	return true
end

function on_event()
	local value = evt.field(fvalue)

	if value ~= nil then
		dcube.insert(fkeys, vizinfo.key_defaults, grtable, value, 1)
	else
		if vizinfo.value_defaults ~= nil then 
			dcube.insert(keys, grtable, vizinfo.value_defaults[1], 1)
		end
	end

	return true
end

function on_interval(ts_s, ts_ns, delta)	
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.goto(0, 0)
	end
	
	dcube.print(grtable, ts_s, 0, delta, vizinfo)

	-- Clear the table
	grtable = {}
	
	return true
end

function on_capture_end(ts_s, ts_ns, delta)
	if islive and vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.goto(0 ,0)
		terminal.showcursor()
		return true
	end

	if vizinfo.do_diff then
		if run_cnt == 1 then

			-- t1 is global because we use it at the next run
			t1 = {}
			t1.children = create_json_table(grtable, delta, vizinfo, 1)
			t1.name = "root"
			t1.timedelta = delta

			grtable = {}
		else
			local t2 = {}

			t2.children = create_json_table(grtable, delta, vizinfo, 1)
			t2.name = "root"
			t2.timedelta = delta
			
			print_table_difference(t1, t2, vizinfo)
		end
	else
		dcube.print(grtable, ts_s, 0, delta, vizinfo)
	end
	
	return true
end
