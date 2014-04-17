var key_list_io = [
  {name:"Process Name", field:"proc.name", filter:""},
  {name:"Directory", field:"fd.directory", filter:""},
  {name:"Filename", field:"fd.name", filter:""},
  {name:"Process ID", field:"proc.pid", filter:""},
  {name:"Process Name + Arguments", field:"proc.cmdline", filter:""},
  {name:"Thread ID", field:"thread.tid", filter:""},
  {name:"Username", field:"user.name", filter:""},
  {name:"Parent Process Name", field:"proc.pname", filter:""},
  {name:"Parent Process ID", field:"proc.ppid", filter:""},
  {name:"I/O direction", field:"evt.io_dir", filter:""},
  {name:"Error Code", field:"evt.res", filter:""},
  {name:"System call type", field:"evt.type", filter:""},
  {name:"None", field:"", filter:""},
// cpu
// in/out (for I/O)
// error code
];

var key_list_net = [
  {name:"Process Name", field:"proc.name", filter:""},
  {name:"Server Port", field:"fd.sport", filter:""},
  {name:"Client IP", field:"fd.cip", filter:""},
  {name:"Server IP", field:"fd.sip", filter:""},
  {name:"Connection", field:"fd.name", filter:""},
  {name:"Process PID", field:"proc.pid", filter:""},
  {name:"Username", field:"user.name", filter:""},
  {name:"None", field:"", filter:""},
// network protocol
];

var value_list = [
  {name:"I/O Bytes", description:"amount of bytes read/written to disk", field:"evt.rawarg.res", filter:"fd.type=file and evt.is_io=true and evt.failed=false", keys: key_list_io},
  {name:"I/O Time", field:"evt.latency", filter:"fd.type=file and evt.is_io=true", keys: key_list_io},
  {name:"IOPS", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=false", keys: key_list_io},
  {name:"Disk I/O Failure Count", field:"evt.count", filter:"fd.type=file and evt.is_io=true and evt.dir=< and evt.failed=true", keys: key_list_io},
  {name:"File Open Failure Count", field:"evt.count", filter:"evt.type=open and evt.dir=< and evt.failed=true", keys: key_list_io},
  {name:"System call Failure Count", field:"evt.count", filter:"evt.dir=< and evt.failed=true", keys: key_list_io},
  {name:"Network Bytes", description:"amount of bytes sent/received on the network", field:"evt.rawarg.res", filter:"fd.type=ipv4 and evt.is_io=true", keys: key_list_net},
  {name:"Incoming Connection Count", description:"number of received network connections", field:"evt.count", filter:"evt.type=accept and evt.dir=<", keys: key_list_net},
  {name:"Outgoing Connection Count", description:"number of attempted network connections", field:"evt.count", filter:"evt.type=connect and evt.dir=<", keys: key_list_net},
  {name:"Failed Connection Attempts", description:"number of falied network connection attempts", field:"evt.count", filter:"evt.type=connect and evt.dir=< and evt.failed=true", keys: key_list_net},
// number of system calls
// system call latency
// failed system calls
// cpu usage
// failed I/O system calls
// number of threads
// number of FDs
// I/O calls with latency bigger than 1ms
// I/O calls with latency bigger than 10ms
// I/O calls with latency bigger than 100ms
// number of forks
// number of executed commands
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
  var key1 = keylist[$('#keycombo1')[0].value];
  var key2 = keylist[$('#keycombo2')[0].value];
  var key3 = keylist[$('#keycombo3')[0].value];
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
    kc.innerHTML += '<option value="' + j + '">' + klist[j].name + '</option>';
  }
  kc.selectedIndex = 0;

  kc = $("#keycombo2")[0];
  kc.innerHTML = '';
  for(var j=0; j < klist.length; j++) {
    kc.innerHTML += '<option value="' + j + '">' + klist[j].name + '</option>';
  }
  kc.selectedIndex = 1;

  kc = $("#keycombo3")[0];
  kc.innerHTML = '';
  for(var j=0; j < klist.length; j++) {
    kc.innerHTML += '<option value="' + j + '">' + klist[j].name + '</option>';
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
