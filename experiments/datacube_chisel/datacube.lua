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

function datacube.set_viz_info(viz_info)
	datacube.viz_info = viz_info
end

function datacube.insert(keys, key_deflts, tbl, value, depth)
	local key = evt.field(keys[depth])
	
	if key == nil then
		if key_deflts ~= nil then
			key = key_deflts[depth]
		end
	end

	if key == nil then
		return
	end
	
	local entryval = tbl[key]

	if entryval == nil then
		tbl[key] = {{}, value}

		if depth < #keys then
			datacube.insert(keys, key_deflts, tbl[key][1], value, depth + 1)
		end
	else
		tbl[key][2] = tbl[key][2] + value
		
		if depth < #keys then
			datacube.insert(keys, key_deflts, tbl[key][1], value, depth + 1)
		end
	end	
end

function datacube.print_table_normal(tbl, timedelta, depth)
	local sorted_grtable = pairs_top_by_val(tbl, datacube.viz_info.top_number, function(t,a,b) return t[b][2] < t[a][2] end)
		
	for k,v in sorted_grtable do
		if datacube.viz_info.valueunits[1] == "none" then
			print(extend_string("", depth - 1) .. extend_string(v[2], 10) .. k)
		elseif datacube.viz_info.valueunits[1] == "bytes" then
			print(extend_string(format_bytes(v[2]), 10) .. k)
		elseif datacube.viz_info.valueunits[1] == "time" then
			print(extend_string(format_time_interval(v[2]), 10) .. k)
		elseif datacube.viz_info.valueunits[1] == "timepct" then
			if timedelta ~= 0 then
				pctstr = string.format("%.2f%%", v[2] / timedelta * 100)
			else
				pctstr = "0.00%"
			end

			print(extend_string(pctstr, 10) .. k)
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

		if depth < #datacube.viz_info.key_fld then
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
		for i, name in ipairs(datacube.viz_info.value_desc) do
			header = header .. extend_string(name, 10)
		end

		for i, name in ipairs(datacube.viz_info.key_desc) do
			header = header .. extend_string(name, 20)
		end

		print(header)
		print("------------------------------")
		
		datacube.print_table_normal(stable, timedelta, 1)
	end
end

return datacube
