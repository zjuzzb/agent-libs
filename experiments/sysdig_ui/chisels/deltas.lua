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

function subtract_tables(table1, table2, viz_info, max_result_size)
	local merge = {}

	-- push table1 in the merge map
	for k,v in pairs(table1) do
		merge[v.name] = {v1=v.value}
	end

	-- push table2 in the merge map. Add a new element only if the key is not
	-- there yet, otherwise just add the v2 field
	for k,v in pairs(table2) do
		if merge[v.name] == nil then
			merge[v.name] = {}
		end
		
		merge[v.name].v2 = v.value
	end	
	
	-- scan the merge map to perform the subtraction
	for k,v in pairs(merge) do
		local v1 = v.v1
		if v1 == nil then
			v1 = 0
		end

		local v2 = v.v2
		if v2 == nil then
			v2 = 0
		end
		
		v.delta = v2 - v1
	end
	
	local fullres = {}
	local j = 1
	
	-- Sort the merge map
	local sorted_map = pairs_top_by_val(merge, viz_info.top_number, function(t,a,b) return t[b].delta < t[a].delta end)
	
	for k,v in sorted_map do
		fullres[j] = {name=k, v1=v.v1, v2=v.v2, delta=v.delta}
		j = j + 1
	end

	-- filter the sorted map by applying the max_result_size limit
	j = j - 1
	local res = {}
	
	for i = 1, math.min(j / 2, max_result_size / 2) do
		res[i] = fullres[i]
	end
		
	for i = math.max(j / 2, j - max_result_size / 2), j do
		res[i] = fullres[i]
	end
	
	return res
end

function print_table_difference(stable, ts_s, ts_ns, timedelta, viz_info)		
	local f = assert(io.open("ttt.json", "r"))
	local t = f:read("*all")
	f:close()
	
	-- Load the first table from file
	local t1 = json.decode(t)
	
	--local str = json.encode(jtable, { indent = true })
	
	-- Generate the second table from the data
	local t2 = {}
	t2.children = create_json_table(stable, timedelta, viz_info, 1)
	t2.name = "root"
	
	-- Do the subtraction
	local diff = subtract_tables(t1.children, t2.children, viz_info, 20)
	
	local str = json.encode(diff, { indent = true })
	print(str)
end
