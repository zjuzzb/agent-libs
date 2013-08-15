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
  This.zoom_box_w = 400;
  This.pzoom = null;
  This.hline = null;
  This.zlines = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  This.linestarts = [];
  This.linewidth = 0;
  This.svg = null;
  This.nprocs = 0;
  This.boxes = null;
  This.zboxes = null;
  This.ztexts = null;
    
  /////////////////////////////////////////////////////////////////////////////////
  // A couple of simple helper functions
  /////////////////////////////////////////////////////////////////////////////////  
  This.id_to_col = function(id) {
    var fg;
    var bg;
    
    if(id == 0) {
      bg='00bf00';
      fg='#000000';
    }
    else if(id == 1) {
      bg='ffc000';
      fg='#000000';
    }
    else if(id == 2) {
      bg='#007f00';
      fg='#000000';
    }
    else if(id == 3) {
      bg='#aaaa00';
      fg='#000000';
    }
    else if(id == 4) {
      bg='#ff0000';
      fg='#000000';
    }
    else if(id == -1) {
      bg='#666666';
      fg='#666666';
    }

    var res = new Object();
    res.bg = bg;
    res.fg = fg;    
    return res;
  }

  /////////////////////////////////////////////////////////////////////////////////
  // Draw a process column
  /////////////////////////////////////////////////////////////////////////////////  
  This.draw_proc = function(name, id, ops, x, width) {
    //
    // Process name on top
    //
    This.svg
      .append("svg:text")
        .attr("class", "headerlabels")
        .text(name)
        .attr("font", "20px sans-serif")
//        .attr("font-size", ".95em")
        .attr("text-anchor", "middle")
        .attr("x", x + width / 2)
        .attr("y", 13);

    //
    // A line for each operation
    //
    var newboxes = This.svg.selectAll("rectl")
    .data(ops)
    .enter()
    .append("svg:rect")
      .attr("x", function(d, i) {
        return x;
      })
      .attr("y", function(d, i) { return d.n + 20; })
      .attr("height", 1)
      .attr("width", width)
      .style("stroke", function(d, i) {
        var proc = This.root.fulllist[d.n];
        var col;
        if(proc[0] === name) {
          col = This.id_to_col(d['c' + This.numcol]);          
        } else {
          col = This.id_to_col(-1);
        }
        d.col = col;
        return col.bg;
      });

      if(This.boxes === null) {
        This.boxes = newboxes;
      } else {
        This.boxes[0] = This.boxes[0].concat(newboxes[0]);
      }
  }
  
  /////////////////////////////////////////////////////////////////////////////////
  // Draw a process column
  /////////////////////////////////////////////////////////////////////////////////  
  This.update_cols = function() {
    //
    // Add a vertical column for each process in the json
    //
    This.boxes
//      .transition()
//        .duration(500)
      .style("stroke", function(d, i) {
        var proc = This.root.fulllist[d.n];
        var col;
        d.col = This.id_to_col(d['c' + This.numcol]);          
        return d.col.bg;
      });
  }

  /////////////////////////////////////////////////////////////////////////////////
  // Locates a process based on the mouse position
  /////////////////////////////////////////////////////////////////////////////////  
  This.find_proc = function(mousepos) {
    var res = -1;
    var j = 0;

    for(j = 0; j < This.nprocs; j++) {
      if(mousepos[0] > This.linestarts[j] && mousepos[0] < This.linestarts[j] + This.linewidth) {
        res = j;
        break;
      }
    }
    
    return res;
  }
  
  /////////////////////////////////////////////////////////////////////////////////
  // Viz creation entry point
  /////////////////////////////////////////////////////////////////////////////////  
  This.create_svg = function(data) {
    This.root = data;
    var j;

    This.datah = 0;
    for(var oplist in data.oplists) {
      This.nprocs++;

      if(data.oplists[oplist].length > This.datah) {
        This.datah = data.oplists[oplist].length;
      }
    }

    This.svg = d3.select("#" + parent_div_id).append("div")
      .attr("class", "chartz")
      .style("width", This.w + "px")
      .style("height", This.h + "px")
      .style("overflow", "auto")
      .attr("id", "svg" + "ciao")
      .append("svg:svg")
      .attr("width", This.w - 20)
      .attr("height", Math.max(This.h, This.datah))
      .on("mousemove", function() {
        var mpos = d3.svg.mouse(this);
        var procname;
        var j = 0;

        procid = This.find_proc(mpos);
        if(procid !== -1)
        {
          //
          // Identify the process name
          //
          for(var oplist in This.root.oplists) {
            if(j == procid) {
              procname = oplist;
              break;
            }
            j++;
          }

          This.showzoom(procname, This.linestarts[procid] + This.linewidth / 2 - This.zoom_box_w / 2, mpos[1]);
        } else {
          This.hidezoom();
        }
      })
      ;
    
    //
    // Add a vertical column for each process in the json
    //
    This.linewidth = (This.w - 100) / This.nprocs / 2;
    
    j = 0;
    for(var oplist in data.oplists) {
      This.linestarts[j] = (This.w - 100) / This.nprocs * j + 50 + (This.w - 100) / This.nprocs / 4;
      This.draw_proc(oplist, j, data.oplists[oplist], This.linestarts[j], This.linewidth);
      j++;
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
  This.showzoom = function(procname, x, y) {
    This.pzoom
      .style("opacity", .95)
      .attr("transform", function(d) { 
        return "translate(" + x + "," + (y + 20) + ")"; });
        
    This.hline
      .style("opacity", 1)
      .attr("y", y);
      
    This.zboxes
      .style("fill", function(d, i) {
        var proc = This.root.fulllist[y-20+i];
        if(proc[0] === procname) {
          var op = This.root.oplists[proc[0]][proc[1]];
          return op.col.bg;          
        } else {
          return This.id_to_col(-1).bg;
        }
      });
      
    This.ztexts
      .text(function(d, i) {
        var proc = This.root.fulllist[y-20+i];
        if(proc[0] === procname) {
          var op = This.root.oplists[proc[0]][proc[1]];
          return op.n + ") " + op.s + "."+ op.ns + " " + op.p + " " + op.d + " " + op.t + " " + op.a.substring(0, 30);
        }
      })
      .style("fill", function(d, i) {
        var proc = This.root.fulllist[y-20+i];
        if(proc[0] === procname) {
          var op = This.root.oplists[proc[0]][proc[1]];
          return op.col.fg;
        }
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
      This.update_cols();
    }
  }
}
