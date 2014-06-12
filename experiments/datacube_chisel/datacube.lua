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
This file implements a multidimensional table
]]--

json = require ("dkjson")

local datacube = {}

datacube.OP_SUM = 0
datacube.OP_MIN = 1
datacube.OP_MAX = 2
datacube.OP_AVG = 3

function datacube.set_viz_info(viz_info)
	datacube.viz_info = viz_info
end

function datacube.add(entry, values)
	for j, v in ipairs(values) do
		if datacube.viz_info.value_operations[j] == datacube.OP_SUM then
			entry[j + 1] = entry[j + 1] + v
		elseif datacube.viz_info.value_operations[j] == datacube.OP_AVG then
			entry[j + 1] = entry[j + 1] + v
			if entry.cnt == nil then
				entry.cnt = {}
			end
			
			entry.cnt[j + 1] = (entry.cnt[j + 1] or 1) + 1
		elseif datacube.viz_info.value_operations[j] == datacube.OP_MIN then
			if v < entry[j + 1] then
				entry[j + 1] = v
			end
		elseif datacube.viz_info.value_operations[j] == datacube.OP_MAX then
			if v > entry[j + 1] then
				entry[j + 1] = v
			end
		end
	end
end

function datacube.insert(keys, tbl, values, depth, raw)
	local key
	
	if raw == true then
		key = keys[depth]
	else
		key = evt.field(keys[depth])
	end
	
	if key == nil then
		if datacube.viz_info.key_defaults ~= nil then
			key = datacube.viz_info.key_defaults[depth]
		else
			return false
		end
	end

	local entry = tbl[key]

	if entry == nil then
		entry = {{}}
				
		if depth < #keys then
			if datacube.insert(keys, entry[1], values, depth + 1, raw) == false then
				return false
			end
		end

		if depth == #keys or datacube.viz_info.aggregate_vals == true then
			for j, v in ipairs(values) do
				entry[j + 1] = v
			end
		end
		
		tbl[key] = entry		
	else
		if depth < #keys then
			if datacube.insert(keys, entry[1], values, depth + 1, raw) == false then
				return false
			end
		end
		
		if depth == #keys or datacube.viz_info.aggregate_vals == true then
			local cval = entry[2]
			if cval ~= nil then
				datacube.add(entry, values)
			else
				for j, v in ipairs(values) do
					entry[j + 1] = v
				end
			end
		end				
	end	
	
	return true
end

local VALS_OFF = 20
local KEYS_OFF = 10

function datacube.print_table_normal(tbl, timedelta, depth)
--print("*" .. serialize_table(tbl))
	local sorted_grtable = pairs_top_by_val(tbl, datacube.viz_info.top_number, function(t,a,b) return t[b][2] < t[a][2] end)

	for k,v in sorted_grtable do
	
		local allvalstr = ""

		for j = 2, #v do
			local valstr = ""
			local val = v[j]
			
			if val == nil then
				valstr = ""
				break
			end
			
			if datacube.viz_info.value_operations[j - 1] == datacube.OP_AVG then
				val = val / v.cnt[j]
			end
			
			if datacube.viz_info.valueunits[j - 1] == "none" then
				valstr = val
			elseif datacube.viz_info.valueunits[j - 1] == "bytes" then
				valstr = format_bytes(val)
			elseif datacube.viz_info.valueunits[j - 1] == "time" then
				valstr = format_time_interval(val)
			elseif datacube.viz_info.valueunits[j - 1] == "timepct" then
				if timedelta ~= 0 then
					pctstr = string.format("%.2f%%", val / timedelta * 100)
				else
					pctstr = "0.00%"
				end

				valstr = extend_string(pctstr, 10)
			end
			
			if j < #v then
				valstr = extend_string(valstr, KEYS_OFF)
			end
			
			allvalstr = allvalstr .. valstr
		end
		
		if allvalstr == "" then
			allvalstr = "-"
		end
		
		if datacube.viz_info.print_keys_first then
			local rvals_off = VALS_OFF - depth
			print(extend_string(extend_string("", depth - 1) .. string.sub(k, 0, rvals_off - 1), VALS_OFF) .. allvalstr)
		else
			local rkeys_off = KEYS_OFF - depth
			print(extend_string("", depth - 1) .. extend_string(string.sub(allvalstr, 0, rkeys_off - 1), KEYS_OFF) .. k)
		end

		if v[1] ~= nil then
			datacube.print_table_normal(v[1], timedelta, depth + 1)
		end
	end
end

function datacube.create_json_table(input_tbl, timedelta, depth)
	local sorted_grtable = pairs_top_by_val(input_tbl, datacube.viz_info.top_number, function(t,a,b) return t[b][2] < t[a][2] end)
	
	local j = 1
	local res = {}
		
	for k,v in sorted_grtable do
		local entry = {}
		entry.name = k
		res[j] = entry
		j = j + 1

		if next(v[1]) ~= nil then
			entry.children = datacube.create_json_table(v[1], timedelta, depth + 1)
		else
			entry.value = v[2]
		end
	end
		
	return res
end

function datacube.table_to_json_string(stable, ts_s, ts_ns, timedelta)		
	local jtable = {}
	jtable.children = datacube.create_json_table(stable, timedelta, 1)
	jtable.name = "root"

	return json.encode(jtable, { indent = true })
end

function datacube.print(stable, ts_s, ts_ns, timedelta)
	if datacube.viz_info.output_format == "json" then
		local str = datacube.table_to_json_string(stable, ts_s, ts_ns, timedelta)
		print(str)
	else
		header = ""

		if datacube.viz_info.print_keys_first then
			if datacube.viz_info.key_desc ~= nil then
				for i, name in ipairs(datacube.viz_info.key_desc) do
					header = header .. extend_string(name, KEYS_OFF)
				end
			end

			header = extend_string(header, VALS_OFF)
					
			for i, name in ipairs(datacube.viz_info.value_desc) do
				header = header .. extend_string(name, KEYS_OFF)
			end
		else
			for i, name in ipairs(datacube.viz_info.value_desc) do
				header = header .. extend_string(name, KEYS_OFF)
			end

			if datacube.viz_info.key_desc ~= nil then
				for i, name in ipairs(datacube.viz_info.key_desc) do
					header = header .. name .. "/"
				end
			end
		end
		
		print(header)
		
		separator = ""
		for j = 0, #header do
			separator = separator.. "-"
		end
		print(separator)
		
		datacube.print_table_normal(stable, timedelta, 1)
	end
end

return datacube
