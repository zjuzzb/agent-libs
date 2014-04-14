////////////////////////////////////////////////////////////////////////////////////////
// This file contains a bunch of small functions to manage the cohexistence of multiple
// charts on the screen.
////////////////////////////////////////////////////////////////////////////////////////

var g_ChartManager = {
  TYPE_TREEMAP: 0,
  TYPE_DEPENDENCY_GRAPH: 1,
  TYPE_OPLIST: 2,
  TYPE_PIE : 3,
  _stack: [],
  CHART_HEIGHT: 550,
  selected_value: 'disk_rwbytes',
  push: function(url, type, scroll) {    
    var chcont = $('#chart_container')[0];
    var id = this._stack.length;
    
    var str = "";
    str += '        <div id="vizcon' + id + '">\n';
    str += '          <ul id="bc_hierarchy' + id + '" class="breadcrumb smallbc">\n';  
    str += '            <li><a href="/root.html">All Machines</a> <span class="divider">></span></li>\n';  
    str += '          </ul>\n';
    str += '          <div id="d3viz' + id + '" class="hero-unit viz">\n';
    str += '          </div>\n';
    str += '        </div>\n';
  
    chcont.innerHTML = (str + chcont.innerHTML);

    if(type === this.TYPE_TREEMAP || type === "treemap") {
      this._stack.push(new DrTreeMap('d3viz' + this._stack.length, false));
    } else if(type === this.TYPE_DEPENDENCY_GRAPH || type === "depgraph") {
      this._stack.push(new DrDepGrap('d3viz' + this._stack.length, false));
    } else if(type === this.TYPE_OPLIST || type === "oplist") {
      this._stack.push(new DrOpList('d3viz' + this._stack.length, false));
    } else if(type === this.TYPE_PIE || type === "pie") {
      this._stack.push(new DrPie('d3viz' + this._stack.length, false));
    }
    
    var ntm = this._stack[this._stack.length - 1]; 
      
    load_data(url);

    if(scroll === undefined) {
      scroll = true;
    }

    if(scroll == true) {
      if(this._stack.length == 1) {
        ntm.show();
      } else {
        $('#vizcon' + id).hide();
        $('#vizcon' + id).slideDown(500, function() {
          // Slidedown animation complete.
          ntm.show();
        });        
      }
    } else {
      ntm.show();      
    }
  },
  pop: function() {
    this._stack.pop();  
  },
  add_key_option: function(objs_list, listid, name) {
    objs_list.innerHTML += '<li><a href="#" onclick=\"g_ChartManager.update_key(\'button_' + listid + '\', \'' + name + '\');\">' + name + '</a></li>';
  },
  update_key_options: function(listid, type) {
    var objs_list = $('#show-' + listid)[0];

    objs_list.innerHTML = '';

    if(type === 'io') {
      this.add_key_option(objs_list, listid, "Proc Name");
      this.add_key_option(objs_list, listid, "Pid");
      this.add_key_option(objs_list, listid, "Directory");
      this.add_key_option(objs_list, listid, "File Name");
      this.add_key_option(objs_list, listid, "User Name");
      this.add_key_option(objs_list, listid, "None");
    } else if (type === 'net') {
      this.add_key_option(objs_list, listid, "Proc Name");
      this.add_key_option(objs_list, listid, "Pid");
      this.add_key_option(objs_list, listid, "Tuple");
      this.add_key_option(objs_list, listid, "Server Port");
      this.add_key_option(objs_list, listid, "Client Port");
      this.add_key_option(objs_list, listid, "None");
    }
  },
  update_value: function(new_value, new_desc) {
    if(new_value === 'disk_rwbytes') {
      this.update_key_options('key1', 'io');
      this.update_key_options('key2', 'io');
      this.update_key_options('key3', 'io');
      document.getElementById('button_key1').innerHTML = 'Proc Name' + '<span class="caret"></span>';
      document.getElementById('button_key2').innerHTML = 'Directory' + '<span class="caret"></span>';
      document.getElementById('button_key3').innerHTML = 'File Name' + '<span class="caret"></span>';
	  $('#button_key1').attr("selval", "Proc Name");
	  $('#button_key2').attr("selval", "Directory");
	  $('#button_key3').attr("selval", "File Name");
    } else if (new_value === 'net_bytes') {
      this.update_key_options('key1', 'net');
      this.update_key_options('key2', 'net');
      this.update_key_options('key3', 'net');
      document.getElementById('button_key1').innerHTML = 'Proc Name' + '<span class="caret"></span>';
      document.getElementById('button_key2').innerHTML = 'Server Port' + '<span class="caret"></span>';
      document.getElementById('button_key3').innerHTML = 'Tuple' + '<span class="caret"></span>';
	  $('#button_key1').attr("selval", "Proc Name");
	  $('#button_key2').attr("selval", "Server Port");
	  $('#button_key3').attr("selval", "Tuple");
    }

    this.selected_value = new_value;
    document.getElementById('button_value').innerHTML = new_desc + '<span class="caret"></span>';
  },
  update_key: function(which, new_value) {
    document.getElementById(which).innerHTML = new_value + '<span class="caret"></span>';
	var el = $('#' + which);
	el.attr("selval", new_value);
	var pippo = 33;
  },
  replace_last: function(new_fname, new_chart_type) {
    this.pop();
    breadcrumb_pop(false, 1);

    d3.select('#vizcon' + (this._stack.length))
      .remove();

    setTimeout(function(m, f, t){
      m.push(f, t, false);
    }, 0, this, new_fname, new_chart_type);
  },
  current: function() {
    return this._stack[this._stack.length - 1];  
  },
  current_bcrumb_id: function() {
    return 'bc_hierarchy' + (this._stack.length - 1);  
  }
}
