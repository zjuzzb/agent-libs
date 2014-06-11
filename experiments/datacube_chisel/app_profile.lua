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
fvals = {}
fntags = nil
run_cnt = 0

vizinfo = 
{
	key_fld = nil,
	key_desc = nil,
	key_defaults = nil,
	value_fld = {"appevt.latency", "evt.count"},
--	value_fld = {"evt.count"},
	value_desc = {"time"},
	value_operations = {"SUM"},
	value_defaults = nil,
	valueunits = {"time", "none"},
--	valueunits = {"none"},
	top_number = 0,
	output_format = "normal",
	aggregate_vals = false,
	print_keys_first = true
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
	for j = 0, 32 do
		fkeys[j + 1] = chisel.request_field("appevt.tag[" .. j .. "]")
	end

	for j = 1, #vizinfo.value_fld do
		fvals[j] = chisel.request_field(vizinfo.value_fld[j])
	end

	-- Init the datacube
	dcube.set_viz_info(vizinfo)

	chisel.set_filter("evt.type=appevt and evt.dir=<")
		
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
	local ntags = evt.field(fntags)
	local keys = {}
	local vals = {}
	
	for j = 1, ntags do
		keys[j] = evt.field(fkeys[j])
	end
	
	for j = 1, #fvals do
		local v = evt.field(fvals[j])
		if v == nil then
			return true
		end
		
		vals[j] = v
	end

	dcube.insert_raw(keys, vizinfo.key_defaults, grtable, vals, 1)

	return true
end

function on_interval(ts_s, ts_ns, delta)	
	if vizinfo.output_format ~= "json" then
		terminal.clearscreen()
		terminal.goto(0, 0)
	end
	
	dcube.print(grtable, ts_s, 0, delta)

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

	dcube.print(grtable, ts_s, 0, delta)
	
	return true
end
