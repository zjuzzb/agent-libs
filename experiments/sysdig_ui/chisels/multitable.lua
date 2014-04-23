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
		name = "value_units", 
		description = "how to render the values in the result. Can be 'bytes', 'time', 'timepct', or 'none'.", 
		argtype = "string"
	},
	{
		name = "do_diff", 
		description = "'true' if the script should perform a diff among the two input trace files, 'false' otherwise.", 
		argtype = "bool"
	},
}

require "common"
require "deltas"
terminal = require "ansiterminal"

grtable = {}
filter = ""
islive = false
fkeys = {}
run_cnt = 0

vizinfo = 
{
	key_fld = "",
	key_desc = "",
	value_fld = "",
	value_desc = "",
	value_units = "none",
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
	elseif name == "values" then
		vizinfo.value_fld = split(val, ",")
		return true
	elseif name == "valuedescs" then
		vizinfo.value_desc = split(val, ",")
		return true
	elseif name == "filter" then
		filter = val
		return true
	elseif name == "top_number" then
		vizinfo.top_number = tonumber(val)
		return true
	elseif name == "value_units" then
		vizinfo.value_units = val
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
	
	if #vizinfo.key_fld ~= #vizinfo.key_desc then
		print("error: number of entries in keys different from number entries in keydescs")
		return false
	end

	if #vizinfo.value_fld ~= #vizinfo.value_desc then
		print("error: number of entries in values different from number entries in valuedescs")
		return false
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

function insert(tbl, value, depth)
	local key = evt.field(fkeys[depth])

	if key ~= nil then
		local entryval = tbl[key]

		if entryval == nil then
			tbl[key] = {{}, value}

			if depth < #fkeys then
				insert(tbl[key][1], value, depth + 1)
			end
		else
			tbl[key][2] = tbl[key][2] + value
			
			if depth < #fkeys then
				insert(tbl[key][1], value, depth + 1)
			end
		end
	end
end

function on_event()
	local value = evt.field(fvalue)

	if value ~= nil then
		insert(grtable, value, 1)
	end
	
	return true
end

function on_interval(ts_s, ts_ns, delta)	
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.goto(0, 0)
	end
	
	print_sorted_table(grtable, ts_s, 0, delta, vizinfo)

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
			local str = table_to_json_string(grtable, ts_s, 0, delta, vizinfo)

			local f = assert(io.open("ttt.json", "w"))
			f:write(str)
			f:close()

			grtable = {}
		else
			print_table_difference(grtable, ts_s, 0, delta, vizinfo)
		end
	else
		print_sorted_table(grtable, ts_s, 0, delta, vizinfo)
	end
	
	return true
end
