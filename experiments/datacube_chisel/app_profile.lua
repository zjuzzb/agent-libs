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
description = "Measures the number of calls and the time spent in the parts of the application tagged with sysdig's apptags."
short_description = "application profiler"
category = "Performance"

-- Chisel argument list
args = {}

require "common"
dcube = require "datacube"
terminal = require "ansiterminal"

grtable = {}
islive = false
fkeys = {}
fntags = nil
run_cnt = 0

vizinfo = 
{
	key_fld = nil,
	key_desc = nil,
	key_defaults = nil,
	value_fld = {"appevt.latency"},
	value_desc = {"time"},
	value_operations = {"SUM"},
	value_defaults = nil,
	valueunits = {"time"},
	top_number = 0,
	output_format = "normal",
	do_diff = false
}

-- Argument notification callback
function on_set_arg(name, val)
	return false
end

function on_init()
	run_cnt = run_cnt + 1
			
	-- Request the fields that we need
	fntags = chisel.request_field("appevt.ntags")
	
	-- Note: we assume the user won't specify more than 32 nested tags
	for i = 0, 32 do
		fkeys[i] = chisel.request_field("appevt.tag[0]")
	end

	fvalue = chisel.request_field(vizinfo.value_fld[1])

	-- Init the datacube
	dcube.set_viz_info(vizinfo)
	
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
