var keys_info = [
  {id: 0, name:"Process Name", field:"proc.name", filter:""},
  {id: 1, name:"Directory", field:"fd.directory", filter:""},
  {id: 2, name:"Filename", field:"fd.filename", filter:""},
  {id: 3, name:"Process ID", field:"proc.pid", filter:""},
  {id: 4, name:"Process Arguments", field:"proc.args", filter:""},
  {id: 5, name:"Process Name + Arguments", field:"proc.cmdline", filter:""},
  {id: 6, name:"Thread ID", field:"thread.tid", filter:""},
  {id: 7, name:"Username", field:"user.name", filter:""},
  {id: 8, name:"Parent Process Name", field:"proc.pname", filter:""},
  {id: 9, name:"Parent Process ID", field:"proc.ppid", filter:""},
  {id: 10, name:"I/O direction", field:"evt.io_dir", filter:""},
  {id: 11, name:"Error Code", field:"evt.res", filter:""},
  {id: 12, name:"System call type", field:"evt.type", filter:""},
  {id: 13, name:"Executed Process Name", field:"evt.arg.exe", filter:""},
  {id: 14, name:"Server Port", field:"fd.sport", filter:""},
  {id: 15, name:"Client IP", field:"fd.cip", filter:""},
  {id: 16, name:"Server IP", field:"fd.sip", filter:""},
  {id: 17, name:"Connection Info", field:"fd.name", filter:""},
  {id: 18, name:"CPU", field:"evt.cpu", filter:""},
  {id: 19, name:"FD Name", field:"fd.name", filter:""},
  {id: 20, name:"Process Name", field:"proc.name", filter:""},
  {id: 21, name:"Full File Name", field:"fd.name", filter:""},
  {id: 22, name:"None", field:"", filter:""},
// full executed process command line (name + args)
// process grandparent
// cpu
// in/out (for I/O)
// error code
// network protocol
];

var key_list_io = [0, 1, 2, 21, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 22];
var key_list_failed_io = [0, 12, 2, 21, 3, 4, 5, 6, 7, 8, 9, 10, 11, 22];
var key_list_slow_io = [0, 2, 12, 21, 3, 4, 5, 6, 7, 8, 9, 10, 11, 22];
var key_list_net = [0, 14, 17, 15, 16, 22];
var key_list_failed_net = [0, 17, 22];
var key_list_syscall = [12, 0, 18, 2, 22, 3, 4, 5, 6, 7, 8, 9, 11, 19, 22];
var key_list_failed_syscall = [12, 11, 0, 2, 22, 3, 4, 5, 6, 7, 8, 9, 18, 19, 22];
var key_list_commands = [8, 13, 18, 7, 9, 22];
var key_list_CPU = [0, 4, 6, 18, 3, 5, 7, 8, 9, 22];
var default_list_CPU = ["idle", "no arguments", "idle", "", "idle", "idle", "", "idle", "idle", ""];

var value_list = [
  {name:"CPU usage (including idle)", description:"CPU time used by the element", field:"thread.exectime", filter:"", keys: key_list_CPU, key_defaults: default_list_CPU, unit:"time"},
  {name:"CPU usage (no idle)", description:"CPU time used by the element", field:"thread.exectime", filter:"", keys: key_list_CPU, unit:"time"},
  {name:"I/O Bytes", description:"amount of bytes read/written to files", field:"evt.rawarg.res", filter:"fd.type=file and evt.is_io=true and evt.failed=false", keys: key_list_io, unit:"bytes"},
  {name:"I/O Time", description:"Time spent doing file I/O", field:"evt.latency", filter:"fd.type=file and evt.is_io=true", keys: key_list_io, unit:"time"},
  {name:"IOPS", description:"Number of I/O operations per second", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=false", keys: key_list_io, unit:"count"},
  {name:"File R/W Failure Count", description:"Number of errors during file I/O", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=true", keys: key_list_failed_io, unit:"count"},
  {name:"File Open Failure Count", description:"Number of file opens that failed", field:"evt.count", filter:"evt.type=open and evt.dir=< and evt.failed=true", keys: key_list_failed_io, unit:"count"},
  {name:"> 1ms I/O calls count", description:"number of file I/O calls that took more than 1 ms to return", field:"evt.count", filter:"fd.type=file and evt.latency > 1000000", keys: key_list_slow_io, unit:"count"},
  {name:"> 10ms I/O calls count", description:"number of file I/O calls that took more than 10 ms to return", field:"evt.count", filter:"fd.type=file and evt.latency > 10000000", keys: key_list_slow_io, unit:"count"},
  {name:"> 100ms I/O calls count", description:"number of file I/O calls that took more than 100 ms to return", field:"evt.count", filter:"fd.type=file and evt.latency > 100000000", keys: key_list_slow_io, unit:"count"},
  {name:"Network Bytes", description:"amount of bytes sent/received on the network", field:"evt.rawarg.res", filter:"fd.type=ipv4 and evt.is_io=true", keys: key_list_net, unit:"bytes"},
  {name:"Incoming Connection Count", description:"Number of received network connections", description:"number of received network connections", field:"evt.count", filter:"evt.type=accept and evt.dir=<", keys: key_list_net, unit:"count"},
  {name:"Outgoing Connection Count", description:"Number of established network connections", description:"number of attempted network connections", field:"evt.count", filter:"evt.type=connect and evt.dir=<", keys: key_list_net, unit:"count"},
  {name:"Failed Connection Attempts", description:"number of falied network connection attempts", field:"evt.count", filter:"(fd.type=ipv4 or fd.type=ipv6) and evt.type=connect and evt.dir=< and evt.failed=true", keys: key_list_failed_net, unit:"count"},
  {name:"System Call Count", description:"number of system calls", field:"evt.count", filter:"evt.dir=<", keys: key_list_syscall, unit:"count"},
  {name:"System Call Time", description:"Time spent in system calls", field:"evt.latency", filter:"evt.dir=<", keys: key_list_syscall, unit:"time"},
  {name:"Failed System Call Count", description:"number of system calls that failed", field:"evt.count", filter:"evt.dir=< and evt.failed=true", keys: key_list_failed_syscall, unit:"count"},
  {name:"# Executed Commands", description:"number of processes that were started", field:"evt.count", filter:"evt.dir=< and evt.type=execve", keys: key_list_commands, unit:"count"},
// time breakdown (disk vs cpu vs net)
// system call latency
// cpu usage
// number of threads
// number of FDs
// number of forks
// number of page faults
// average size of an I/O call
// number of created files
// Number of moved/deleted files
// number of DNS resolutions
// FD usage %
// cpu vs network vs disk time
// fd usage by type
];


////////////////////////////////////////////////////////////////////
// Chart data management
////////////////////////////////////////////////////////////////////
var g_treemap;
var chartunit;

function on_data_load(json) {
  g_treemap = new treemap2(json, chartunit);
}

function on_progress(json) {
  var progress = JSON.parse(json);
  pt = $("#progresstext")[0];

  if(progress < 100)
  {
    setTimeout(function(){on_run();}, 200);
    pt.innerHTML = 'Progress: ' + progress + '%';
  }
  else
  {
    pt.innerHTML = 'Progress: done';

    $.ajax({
      type : 'GET',
      url : '/data',
      dataType : 'json',
      success : on_data_load,
      error : on_error,
      async : false,
    });
  }
}

function on_run(json) {
  $.ajax({
    type : 'GET',
    url : '/progress',
    dataType : 'json',
    success : on_progress,
    error : on_error,
    async : false,
  });
}

function on_error(jqXHR, textStatus, errorThrown) {
  alert(textStatus);
}

//
// Load json data from the given URL
//
function update_chart() {
  var value = value_list[$('#valuecombo')[0].value];
  
  chartunit = value.unit;

  var value_simple = JSON.parse(JSON.stringify(value_list[$('#valuecombo')[0].value]));
  value_simple.keys = undefined;
  var keylist = value.keys;
  var key1 = JSON.parse(JSON.stringify(keys_info[keylist[$('#keycombo1')[0].value]]));
  var key2 = JSON.parse(JSON.stringify(keys_info[keylist[$('#keycombo2')[0].value]]));
  var key3 = JSON.parse(JSON.stringify(keys_info[keylist[$('#keycombo3')[0].value]]));
  
  var filter = $('#filterinput')[0].value;

  var data_to_send = {"value":value_simple, 
    "key1": key1, 
    "key2": key2, 
    "key3": key3,
    "filter": filter};

  if(value.key_defaults) {
    data_to_send["key1"]["default"] = value.key_defaults[$('#keycombo1')[0].value];
    data_to_send["key2"]["default"] = value.key_defaults[$('#keycombo2')[0].value];
    data_to_send["key3"]["default"] = value.key_defaults[$('#keycombo3')[0].value];
  }

  body = JSON.stringify(data_to_send)
  
  $.ajax({
    type : 'POST',
    url : '/run',
    dataType : 'json',
    success : on_run,
    error : on_error,
    data : body,
    async : false,
    processData: false
  });
}

////////////////////////////////////////////////////////////////////
// Field list management
////////////////////////////////////////////////////////////////////
function populate_keys(klist) {
  var kc;

  kc = $("#keycombo1")[0];
  kc.innerHTML = '';
  for(var j=0; j < klist.length; j++) {
    kc.innerHTML += '<option value="' + j + '">' + keys_info[klist[j]].name + '</option>';
  }
  kc.selectedIndex = 0;

  kc = $("#keycombo2")[0];
  kc.innerHTML = '';
  for(var j=0; j < klist.length; j++) {
    kc.innerHTML += '<option value="' + j + '">' + keys_info[klist[j]].name + '</option>';
  }
  kc.selectedIndex = 1;

  kc = $("#keycombo3")[0];
  kc.innerHTML = '';
  for(var j=0; j < klist.length; j++) {
    kc.innerHTML += '<option value="' + j + '">' + keys_info[klist[j]].name + '</option>';
  }
  kc.selectedIndex = 2;
}

function populate_fields() {
  var vc = $("#valuecombo")[0];

  vc.innerHTML = '';
  for(var j=0; j < value_list.length; j++) {
    vc.innerHTML += '<option value="' + j + '">' + value_list[j].name + '</option>';
  }

  populate_keys(value_list[0].keys);
}

function on_value_selected(sel) {
  var sid = sel.value;

  populate_keys(value_list[sid].keys);
}

////////////////////////////////////////////////////////////////////
// Entry point for the page scripts
////////////////////////////////////////////////////////////////////
$(window).load(function() {
  populate_fields();
});
