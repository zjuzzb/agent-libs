////////////////////////////////////////////////////////////////////////////////////////
// This file contains a bunch of small functions to manage  the page readcrumb control
////////////////////////////////////////////////////////////////////////////////////////

var stack = [];

function breadcrumb_redraw() {
  bc = document.getElementById(g_ChartManager.current_bcrumb_id());

  bc.innerHTML = '';
  
  for(var j = 0; j < stack.length; j++) {
    if(j < stack.length - 1) {
      bc.innerHTML += '<li><a href="#" onclick=\"breadcrumb_click(' + j + ');\">' + stack[j].name + '</a><span class="divider">></span></li>';    
    }
    else {
      bc.innerHTML += '<li class="active">' + stack[j].name + '</li>';
    }
  }
}

function breadcrumb_set(val, redraw) {
  stack = [];
  stack.push(val);
  if(redraw) {
    breadcrumb_redraw();
  }
}

function breadcrumb_push(val, redraw) {
  stack.push(val);
  if(redraw) {
    breadcrumb_redraw();
  }
}

function breadcrumb_pop(redraw, nitems) {
  for(var j = 0; j < nitems; j++) {
    stack.pop();  
  }
  if(redraw) {
    breadcrumb_redraw();
  }
}

function breadcrumb_click(level) {
  breadcrumb_pop(true, stack.length - level - 1);
  
  if(level < 1) {
    g_ChartManager.current().zoom(null, 1500, ZOOM_TYPE_OUT);
  } else {
    g_ChartManager.current().zoom(stack[level], 1500, ZOOM_TYPE_OUT);
  }
}
