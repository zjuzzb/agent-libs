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

--[[ 
This file contains a bunch of functions that are helpful in multiple scripts
]]--

--[[ 
Extends a string to newlen with spaces
]]--
function extend_string(s, newlen)
	local ccs = "                                                                                                        "
	s = s .. string.sub(ccs, 0, newlen - string.len(s))
	return s
end

--[[ 
Basic string split.
]]--
function split(s, delimiter)
    local result = {}
	
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

--[[ 
convert a number into a byte representation.
E.g. 1230 becomes 1.23K
]]--
function format_bytes(val)
	if val > (1024 * 1024 * 1024) then
		return string.format("%.2fP", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024) then
		return string.format("%.2fT", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024 * 1024) then
		return string.format("%.2fG", val / (1024 * 1024 * 1024))
	elseif val > (1024 * 1024) then
		return string.format("%.2fM", val / (1024 * 1024))
	elseif val > 1024 then
		return string.format("%.2fKB", val / (1024))
	else
		return string.format("%dB", val)
	end
end

--[[ 
convert a nanosecond time interval into a s.ns representation.
E.g. 1100000000 becomes 1.1s
]]--
ONE_S_IN_NS=1000000000
ONE_MS_IN_NS=1000000
ONE_US_IN_NS=1000

function format_time_interval(val)
	if val >= (ONE_S_IN_NS) then
		return string.format("%u.%02us", math.floor(val / ONE_S_IN_NS), (val % ONE_S_IN_NS) / 10000000)
	elseif val >= (ONE_S_IN_NS / 100) then
		return string.format("%ums", math.floor(val / (ONE_S_IN_NS / 1000)))
	elseif val >= (ONE_S_IN_NS / 1000) then
		return string.format("%u.%02ums", math.floor(val / (ONE_S_IN_NS / 1000)), (val % ONE_MS_IN_NS) / 10000)
	elseif val >= (ONE_S_IN_NS / 100000) then
		return string.format("%uus", math.floor(val / (ONE_S_IN_NS / 1000000)))
	elseif val >= (ONE_S_IN_NS / 1000000) then
		return string.format("%u.%02uus", math.floor(val / (ONE_S_IN_NS / 1000000)), (val % ONE_US_IN_NS) / 10)
	else
		return string.format("%uns", val)
	end
end

--[[ 
extract the top num entries from the table t, after sorting them based on the entry value using the function order()
]]--
function pairs_top_by_val(t, num, order)
	local keys = {}
	for k in pairs(t) do keys[#keys+1] = k end

	table.sort(keys, function(a,b) return order(t, a, b) end)

	local i = 0
	return function()
		i = i + 1
		if (num == 0 or i <= num) and keys[i] then
			return keys[i], t[keys[i]]
		end
	end
end

--[[ 
Pick a key-value table and render it to the console in sorted top format
]]--
json = require ("dkjson")

function print_table_normal(tbl, timedelta, viz_info, depth)
	local sorted_grtable = pairs_top_by_val(tbl, viz_info.top_number, function(t,a,b) return t[b][2] < t[a][2] end)
	
	for k,v in sorted_grtable do
		if viz_info.valueunits[1] == "none" then
			print(extend_string("", depth - 1) .. extend_string(v[2], 10) .. k)
		elseif viz_info.valueunits[1] == "bytes" then
			print(extend_string(format_bytes(v[2]), 10) .. k)
		elseif viz_info.valueunits[1] == "time" then
			print(extend_string(format_time_interval(v[2]), 10) .. k)
		elseif viz_info.valueunits[1] == "timepct" then
			if timedelta ~= 0 then
				pctstr = string.format("%.2f%%", v[2] / timedelta * 100)
			else
				pctstr = "0.00%"
			end

			print(extend_string(pctstr, 10) .. k)
		end
		
		if depth < #viz_info.key_fld then
			print_table_normal(v[1], timedelta, viz_info, depth + 1)
		end
	end
end

function create_json_table(input_tbl, timedelta, viz_info, depth)
	local sorted_grtable = pairs_top_by_val(input_tbl, viz_info.top_number, function(t,a,b) return t[b][2] < t[a][2] end)
	
	local j = 1
	local res = {}
		
	for k,v in sorted_grtable do
		local entry = {}
		entry.name = k
		res[j] = entry
		j = j + 1

		if depth < #viz_info.key_fld then
			entry.children = create_json_table(v[1], timedelta, viz_info, depth + 1)
		else
			entry.value = v[2]
		end
	end
		
	return res
end

function table_to_json_string(stable, ts_s, ts_ns, timedelta, viz_info)		
	local jtable = {}
	jtable.children = create_json_table(stable, timedelta, viz_info, 1)
	jtable.name = "root"

	return json.encode(jtable, { indent = true })
end

function print_sorted_table(stable, ts_s, ts_ns, timedelta, viz_info)		
	if viz_info.output_format == "json" then
		local str = table_to_json_string(stable, ts_s, ts_ns, timedelta, viz_info)
		print(str)
	else
		header = ""
		for i, name in ipairs(vizinfo.value_desc) do
			header = header .. extend_string(name, 10)
		end

		for i, name in ipairs(viz_info.key_desc) do
			header = header .. extend_string(name, 20)
		end

		print(header)
		print("------------------------------")
		
		print_table_normal(stable, timedelta, viz_info, 1)
	end
end
