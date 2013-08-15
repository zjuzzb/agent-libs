function DrOpList(parent_div_id, shownow) {
  var This = this;
  This.shownow = (typeof shownow !== 'undefined') ? shownow : true;
  This.is_initialized = false;
  This.parent_div_id = parent_div_id;
  This.w = document.getElementById(parent_div_id).clientWidth - 40;
  This.h = g_ChartManager.CHART_HEIGHT;
  This.root = null;
  This.force = null;
  This.path = null;
  This.circle = null;
  This.text = null;
  This.numcol = 0;    // This is the 0-based number of the the column that is going to be used for the circle size. 
                      // For example, if numcol is 1, c1 will be used.
  This.opw = 300;
  This.zoom_box_w = 280;
  This.pzoom = null;
  This.hline = null;
  This.zlines = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  This.linestarts = [];
  This.linewidth = 0;
  This.svg = null;
  This.nprocs = -1;
  This.zboxes = null;
  This.ztexts = null;
    
  /////////////////////////////////////////////////////////////////////////////////
  // A couple of simple helper functions
  /////////////////////////////////////////////////////////////////////////////////  
  This.op_to_col = function(op) {
    var fg;
    var bg;
    
    if(op == 'R') {
      bg='00bf00';
      fg='#000000';
    }
    else if(op == 'W') {
      bg='#007f00';
      fg='#000000';
    }
    else if(op == 'O') {
      bg='ffc000';
      fg='#000000';
    }
    else if(op == 'C') {
      bg='#aaaa00';
      fg='#000000';
    }
    else if(op == 'N') {
      bg='#666666';
      fg='#666666';
    }
    else if(op == 'L') {
      bg='#000000';
      fg='#ff0000';
    }

    var res = new Object();
    res.bg = bg;
    res.fg = fg;    
    return res;
  }

  This.op_to_name = function(op) {
    if(op == 'R') {
      return 'READ';
    }
    else if(op == 'W') {
      return 'WRITE';
    }
    else if(op == 'O') {
      return 'OPEN';
    }
    else if(op == 'C') {
      return 'CLOSE';
    }
    else if(op == 'N') {
      return '';
    }
    else if(op == 'L') {
      return 'LOCK';
    }
    else {
      return 'None';
    }
  }

  /////////////////////////////////////////////////////////////////////////////////
  // Viz creation entry point
  /////////////////////////////////////////////////////////////////////////////////  
  This.draw_proc = function(proc, x, width) {
    ops = proc.ops;

    //
    // Process name on top
    //
    This.svg
      .append("svg:text")
        .attr("class", "headerlabels")
        .text(proc.name)
        .attr("font", "20px sans-serif")
//        .attr("font-size", ".95em")
        .attr("text-anchor", "middle")
        .attr("x", x + width / 2)
        .attr("y", 13);

    //
    // A line for each operation
    //
    This.svg.selectAll("rectl")
    .data(ops)
    .enter()
    .append("svg:rect")
      .attr("x", function(d, i) {
        return x;
      })
      .attr("y", function(d, i) { return i + 20; })
      .attr("height", 1)
      .attr("width", width)
      .style("stroke", function(d, i) {
        var col = This.op_to_col(d[1]);
        d.col = col;
        return col.bg;
      });
  }
  
  /////////////////////////////////////////////////////////////////////////////////
  // Locates a process based on the mouse position
  /////////////////////////////////////////////////////////////////////////////////  
  This.find_proc = function(mousepos) {
    for(var j = 0; j < This.nprocs; j++) {
      if(mousepos[0] > This.linestarts[j] && mousepos[0] < This.linestarts[j] + This.linewidth) {
        return j;
      }
    }
    
    return -1;
  }
  
  /////////////////////////////////////////////////////////////////////////////////
  // Viz creation entry point
  /////////////////////////////////////////////////////////////////////////////////  
  This.create_svg = function(data) {
    This.root = data;
        
    This.svg = d3.select("#" + parent_div_id).append("div")
      .attr("class", "chartz")
      .style("width", This.w + "px")
      .style("height", This.h + "px")
      .attr("id", "svg" + "ciao")
      .append("svg:svg")
      .attr("width", This.w)
      .attr("height", This.h)
      .on("mousemove", function() {
        var mpos = d3.svg.mouse(this);
        procid = This.find_proc(mpos);
        if(procid !== -1)
        {
          This.showzoom(procid, This.linestarts[procid] + This.linewidth / 2 - This.zoom_box_w / 2, mpos[1]);
        } else {
          This.hidezoom();
        }
      })
      ;
    
    //
    // Add a vertical column for each process in the json
    //
    This.nprocs = data.oplists.length;
    This.linewidth = (This.w - 100) / This.nprocs / 2;
    
    for(var j = 0; j < This.nprocs; j++) {
      This.linestarts[j] = (This.w - 100) / This.nprocs * j + 50 + (This.w - 100) / This.nprocs / 4;
      This.draw_proc(data.oplists[j], This.linestarts[j], This.linewidth);
    }

    //
    // The zoom box
    //
    This.pzoom = This.svg.append("svg:g")
      .attr("class", "opzoom")
      .style("opacity", 0)
      .attr("transform", function(d) { 
        return "translate(" + 100 + "," + 0 + ")"; });

    This.zboxes = This.pzoom.selectAll("zlines")
      .data(This.zlines)
      .enter()
      .append("svg:rect")
        .attr("x", 0)
        .attr("y", function(d, i) {
          return i * 16;
        })
        .attr("height", 16)
        .attr("width", This.zoom_box_w)
        .style("stroke", function(d, i) {
          return "#000000";
        })
        .style("fill", function(d, i) {
          return "#ffffff";
        })
        ;

    This.ztexts = This.pzoom.selectAll("ztext")
      .attr("class", "zoomlabels")
      .data(This.zlines)
      .enter()
      .append("svg:text")
        .text(function(d) { return "0123456789012345678"; })
        .attr("x", 5)
        .attr("y", function(d, i) {
          return i * 16 + 11;
        })
        .attr("font-size", ".85em")
        ;
        
    //
    // Horizontal line
    //
    This.hline = This.svg
    .append("svg:rect")
      .attr("x", 0)
      .attr("y", function(d, i) { return 100; })
      .attr("width", This.w)
      .attr("height", .5)
      .style("stroke", "#ff0000")
      .style("opacity", 0);
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // This does nothing for this chart for the moment
  /////////////////////////////////////////////////////////////////////////////////  
  This.show = function(data) {
  }

  /////////////////////////////////////////////////////////////////////////////////  
  // display the zoom layover 
  /////////////////////////////////////////////////////////////////////////////////  
  This.showzoom = function(nproc, x, y) {
    This.pzoom
      .style("opacity", .95)
      .attr("transform", function(d) { 
        return "translate(" + x + "," + (y + 20) + ")"; });
        
    This.hline
      .style("opacity", 1)
      .attr("y", y);
      
    This.zboxes
      .style("fill", function(d, i) {
        return This.root.oplists[nproc].ops[y-20+i].col.bg;
      });
      
    This.ztexts
      .text(function(d, i) { 
        var op = This.root.oplists[nproc].ops[y-20+i];
        return op[0] + " " + This.op_to_name(op[1]) + " " + op[2]; 
        })
      .style("fill", function(d, i) {
        return This.root.oplists[nproc].ops[y-20+i].col.fg;
      })
      ;
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // hide the zoom layover 
  /////////////////////////////////////////////////////////////////////////////////  
  This.hidezoom = function(x, y) {
    This.pzoom
      .style("opacity", 0);

    This.hline
      .style("opacity", 0)
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // Update the visualization with new data
  /////////////////////////////////////////////////////////////////////////////////  
  This.update_viz_data = function(json, column, action) {
    if(action === UPDATE_ACTION_LOAD) {
      This.create_svg(json);
    }
    else if (action === UPDATE_ACTION_REPLACE) {
      This.replace_viz(json);
    }
    else {
      This.numcol = column;
      document.getElementById('button_metrics').innerHTML = This.root.metric_alternatives[This.numcol][0] + '<span class="caret"></span>';      
      This.resize_circles();
    }
  }
}
