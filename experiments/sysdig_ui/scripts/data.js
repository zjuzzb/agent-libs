var keys_info = [
  {id: 0, name:"Process Name", field:"proc.name", filter:""},
  {id: 1, name:"Directory", field:"fd.directory", filter:""},
  {id: 2, name:"Filename", field:"fd.name", filter:""},
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
  {id: 21, name:"None", field:"", filter:""},
// full executed process command line (name + args)
// process grandparent
// cpu
// in/out (for I/O)
// error code
// network protocol
];

var key_list_io = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 21];
var key_list_failed_io = [0, 12, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 21];
var key_list_slow_io = [0, 2, 12, 3, 4, 5, 6, 7, 8, 9, 10, 11, 21];
var key_list_net = [0, 14, 17, 15, 16, 21];
var key_list_failed_net = [0, 17, 21];
var key_list_syscall = [12, 0, 18, 2, 3, 4, 5, 6, 7, 8, 9, 11, 19, 21];
var key_list_failed_syscall = [12, 11, 0, 2, 3, 4, 5, 6, 7, 8, 9, 18, 19, 21];
var key_list_commands = [8, 13, 18, 7, 9];

var value_list = [
  {name:"I/O Bytes", description:"amount of bytes read/written to disk", field:"evt.rawarg.res", filter:"fd.type=file and evt.is_io=true and evt.failed=false", keys: key_list_io},
  {name:"I/O Time", field:"evt.latency", filter:"fd.type=file and evt.is_io=true", keys: key_list_io},
  {name:"IOPS", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=false", keys: key_list_io},
  {name:"File R/W Failure Count", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=true", keys: key_list_failed_io},
  {name:"File Open Failure Count", field:"evt.count", filter:"evt.type=open and evt.dir=< and evt.failed=true", keys: key_list_failed_io},
  {name:"> 1ms I/O calls count", field:"evt.count", filter:"fd.type=file and evt.latency > 1000000", keys: key_list_slow_io},
  {name:"> 10ms I/O calls count", field:"evt.count", filter:"fd.type=file and evt.latency > 10000000", keys: key_list_slow_io},
  {name:"> 100ms I/O calls count", field:"evt.count", filter:"fd.type=file and evt.latency > 100000000", keys: key_list_slow_io},
  {name:"Network Bytes", description:"amount of bytes sent/received on the network", field:"evt.rawarg.res", filter:"fd.type=ipv4 and evt.is_io=true", keys: key_list_net},
  {name:"Incoming Connection Count", description:"number of received network connections", field:"evt.count", filter:"evt.type=accept and evt.dir=<", keys: key_list_net},
  {name:"Outgoing Connection Count", description:"number of attempted network connections", field:"evt.count", filter:"evt.type=connect and evt.dir=<", keys: key_list_net},
  {name:"Failed Connection Attempts", description:"number of falied network connection attempts", field:"evt.count", filter:"(fd.type=ipv4 or fd.type=ipv6) and evt.type=connect and evt.dir=< and evt.failed=true", keys: key_list_failed_net},
  {name:"System Call Count", description:"number of system calls", field:"evt.count", filter:"evt.dir=<", keys: key_list_syscall},
  {name:"System Call Time", description:"Time spent in system calls", field:"evt.latency", filter:"evt.dir=<", keys: key_list_syscall},
  {name:"Failed System Call Count", description:"number of system calls that failed", field:"evt.count", filter:"evt.dir=< and evt.failed=true", keys: key_list_failed_syscall},
  {name:"# Executed Commands", description:"number of started processes", field:"evt.count", filter:"evt.dir=< and evt.type=execve", keys: key_list_commands},
// time breakdown (disk vs cpu vs net)
// system call latency
// cpu usage
// number of threads
// number of FDs
// number of forks
// number of page faults
];


////////////////////////////////////////////////////////////////////
// Chart data management
////////////////////////////////////////////////////////////////////
function on_data_load(json) {
  treemap2(json);
}

function on_data_load_error(jqXHR, textStatus, errorThrown) {
  var a = 0;
}

//
// Load json data from the given URL
//
function update_chart() {
  var value = value_list[$('#valuecombo')[0].value];
  var value_simple = JSON.parse(JSON.stringify(value_list[$('#valuecombo')[0].value]));
  value_simple.keys = undefined;
  var keylist = value.keys;
  var key1 = keys_info[keylist[$('#keycombo1')[0].value]];
  var key2 = keys_info[keylist[$('#keycombo2')[0].value]];
  var key3 = keys_info[keylist[$('#keycombo3')[0].value]];
  body = JSON.stringify({"value":value_simple, "key1": key1, "key2": key2, "key3": key3})
  
  $.ajax({
    type : 'POST',
    url : '/run',
    dataType : 'json',
    success : on_data_load,
    error : on_data_load_error,
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
