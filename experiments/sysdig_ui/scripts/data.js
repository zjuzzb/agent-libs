var key_list_io = [
  {name:"Process Name", field:"proc.name", filter:""},
  {name:"Directory", field:"fd.directory", filter:""},
  {name:"Filename", field:"fd.name", filter:""},
  {name:"Process PID", field:"proc.pid", filter:""},
  {name:"Username", field:"user.name", filter:""},
  {name:"None", field:"", filter:""},
];

var key_list_net = [
  {name:"Process Name", field:"proc.name", filter:""},
  {name:"Server Port", field:"fd.sport", filter:""},
  {name:"Cliet IP", field:"fd.cip", filter:""},
  {name:"Server IP", field:"proc.sip", filter:""},
  {name:"Connection", field:"fd.name", filter:""},
  {name:"Process PID", field:"proc.pid", filter:""},
  {name:"Username", field:"user.name", filter:""},
  {name:"None", field:"", filter:""},
];

var value_list = [
  {name:"I/O Bytes (R+W)", field:"evt.rawarg.res", filter:"fd.type=file and evt.is_io=true", keys: key_list_io},
  {name:"I/O Bytes (R)", field:"evt.rawarg.res", filter:"fd.type=file and evt.is_io=true", keys: key_list_io},
  {name:"Network Bytes (R+W)", field:"evt.rawarg.res", filter:"fd.type=ipv4 and evt.is_io=true", keys: key_list_net},
];


////////////////////////////////////////////////////////////////////
// Chart data management
////////////////////////////////////////////////////////////////////
function on_data_load(json) {
  var a = 0;
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
