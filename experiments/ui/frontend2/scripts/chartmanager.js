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
