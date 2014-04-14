//
// Constants
//
var UPDATE_ACTION_CHANGE = 0;
var UPDATE_ACTION_LOAD = 1;
var UPDATE_ACTION_REPLACE = 2;
var ZOOM_TYPE_IN = 0;
var ZOOM_TYPE_OUT = 1;
var ZOOM_TYPE_SAME = 2;

function DrTreeMap (parent_div_id, shownow) {
  var This = this;
  This.shownow = (typeof shownow !== 'undefined') ? shownow : true;
  This.is_initialized = false;
  This.parent_div_id = parent_div_id;
  This.w = document.getElementById(parent_div_id).clientWidth - 40;
  This.h = g_ChartManager.CHART_HEIGHT;
  This.x = d3.scale.linear().range([0, This.w]);
  This.y = d3.scale.linear().range([0, This.h]);
  This.color = d3.scale.category20c();
  This.root = null;
  This.node = null;
  This.svg = null;
  This.vizlevel = 0;
  This.kx = 1;
  This.ky = 1;
  This.treemap = null;
  This.ZOOM_DURATION = 1500;
  This.REPLACE_DURATION = 500;
  This.is_zooming = false;
  
  //
  // Helper function that scans the input tree and extract the non-leaf nodes
  //
  This.create_container_list = function(node, res) {
    if(node.children && node.children.length != 0) {
      for(var j = 0; j < node.children.length; j++) {
        This.create_container_list(node.children[j], res);
      }
      
      if(node.l < This.root.data_depth - 1) {
        res.push(node);
      }
    }
    
    return res;
  }
        
  //
  // Helper function to find a node given its name
  //
  This.find_node = function(node, nametofind) {
    if(node.name === nametofind) {
      return node;
    }

    if(node.children && node.children.length != 0) {
      for(var j = 0; j < node.children.length; j++) {
        res = This.find_node(node.children[j], nametofind);
        
        if(res !== null) {
          return res;
        }
      }      
    }
    
    return null;
  }
  
  //
  // Helper function that, given a xy coordinate, scans the json tree and finds which visible node is at that coordinate
  //
  This.detect_click = function(d, mousepos) {
    var is_max_zoom = (This.vizlevel === This.root.data_depth - 1);
    if((d.l === This.vizlevel + 1)) {
      if(d.parent) {
        if((mousepos[0] >= d.parent.x && mousepos[0] <= d.parent.x + d.parent.dx) && 
        (mousepos[1] >= d.parent.y && mousepos[1] <= d.parent.y + d.parent.dy)){
          return d.parent;         
        }        
      }
    } else if(d.l === This.vizlevel && is_max_zoom) {
      if((mousepos[0] >= d.x && mousepos[0] <= d.x + d.dx) && 
      (mousepos[1] >= d.y && mousepos[1] <= d.y + d.dy)){
        return d;
      }
    }
    
    if(d.children && d.children.length != 0) {
      for(var j = 0; j < d.children.length; j++) {
        res = This.detect_click(d.children[j], mousepos);
        if(res !== null) {
          return res;
        }
      }
    }
    
    return null;
  }
  
  //
  // This is the function used to filter the nodes when the treemap is created
  //
  This.tmfilter = function(d) {
  //  return !d.children;
    if(d.l >= 0) {
      return true;
    }
    
    return false;
  }
  
  //
  // Convert a point inside the SVG into the correspondent absolute chart coorinate,
  // taking zooming into account 
  //
  This.abscoord = function(point) {
    point[0] = This.x.invert(point[0]);
    point[1] = This.y.invert(point[1]);
    return point;
  }
  
  //
  // Visualization main function
  //
  This.create_svg = function(data) {
    This.node = This.root = data;
    This.vizlevel = 0;
    This.kx = 1;
    This.ky = 1;
  
    //
    // Initialize the scaling to the whole svg visualization
    // 
    This.x.domain([0, This.w]);
    This.y.domain([0, This.h]);
  
    //
    // Create the svg visualization
    //
    This.svg = d3.select("#" + parent_div_id).append("div")
        .attr("class", "chart")
        .style("width", This.w + "px")
        .style("height", This.h + "px")
        .attr("id", "svg" + This.parent_div_id)
      .append("svg:svg")
        .attr("width", This.w)
        .attr("height", This.h)
      .on("mousemove", function() {
        //
        // Do nothing if the chart is currently zooming
        //
        if(This.is_zooming) {
          return;
        }
        
        mousepos = This.abscoord(d3.svg.mouse(this));
        This.node = This.detect_click(This.root, mousepos);
  
        This.svg.selectAll("g.cell")
          .style("opacity", function(d) {
            var is_max_zoom = (This.vizlevel === This.root.data_depth - 1);
            if((d.l === This.vizlevel + 1) || (d.l === This.vizlevel && is_max_zoom) || (d.l === This.vizlevel && d.children == undefined)) {
              var chknode;
              if(is_max_zoom) {
                chknode = d;
              } else {
                chknode = d.parent;                
              }
              
              if(chknode === This.node) {
                return .3;
              } else {
                return 1;
              }
            } else {
              return 0;
            }          
          });
    })    
    .on("mouseout", function() {
        This.svg.selectAll("g.cell")
          .style("opacity", function(d) {
            if((d.l === This.vizlevel + 1) || (d.l === This.vizlevel && This.vizlevel === This.root.data_depth - 1) || (d.l === This.vizlevel && d.children == undefined)) {
              return 1;
            } else {
              return 0;
            }
          });
    })
    .on("click", function() {
      mousepos = This.abscoord(d3.svg.mouse(this));
      
      This.node = This.detect_click(This.root, mousepos);
      
      if(This.vizlevel < This.root.data_depth - 1) {
        breadcrumb_push(This.node, true);
        This.zoom(This.node, This.ZOOM_DURATION, ZOOM_TYPE_IN);        
      }
    })
    .on("dblclick", function() {
          g_ChartManager.push(This.root.click_target[0], This.root.click_target[1]);
    })
    ;    

    if(This.shownow) {
      This.show(data);    
    }
  }
  
  //
  // Visualization main function
  //   
  This.show = function(data) {
    var data = This.root;
    
    //
    // Create the treemap layout
    //
    This.treemap = d3.layout.treemap()
      .round(false)
      .padding([0, 0, 0, 0])
      .size([This.w, This.h])
      .sticky(true)
      .value(function(d) { return d.c0; });
        
    //
    // Smooth visualization entrance
    //
    This.svg.style("opacity", 0)
      .transition()
        .duration(500)
        .style("opacity", 1);
      
    //
    // Create the nonchild dataset
    //
    var containers = This.create_container_list(This.root, []);
  
    //
    // Apply the treemap layout
    //
    var nodes = This.treemap.nodes(This.root)
        .filter(This.tmfilter);
  
    //
    // Create the leaves
    //
    var cell = This.svg.selectAll("g.cell")
        .data(nodes)
      .enter().append("svg:g")
        .attr("class", "cell")
        .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; })
        .style("opacity", function(d) {        
          if((d.l == This.vizlevel + 1) || (d.l === This.vizlevel && d.children == undefined)) {
            d.visible = true;
          } else {
            d.visible = false;
          }
          
          if(d.visible) {
            return 1;         
          }
          else {
            return 0;
          }
        });
  
    cell.append("svg:rect")
        .attr("class", "cellrect")
        .attr("width", function(d) { return d.dx - 1; })
        .attr("height", function(d) { return d.dy - 1; })
        .style("fill", function(d) { return This.color(d.parent.name); });
  
    cell.append("svg:text")
        .attr("class", "celltext")
        .attr("x", function(d) { return 1; })
        .attr("y", function(d) { return 7; })
        .attr("dy", ".35em")
  //      .attr("text-anchor", "start")
        .text(function(d) { return d.name; })
        .style("opacity", function(d) {
          d.w = this.getComputedTextLength();
          
          if(!This.root.show_child_labels) {
            return 0;          
          }
          
          return This.kx * d.dx > d.w ? 1 : 0;
        });
  
    //
    // Create the intermediate nodes
    //
    var container = This.svg.selectAll("g.containers")
        .data(containers)
      .enter().append("svg:g")
        .attr("class", "container")
        .attr("transform", function(d) { 
          return "translate(" + d.x + "," + d.y + ")"; });
  
    container.append("svg:text")
        .text(function(d) { return d.name; })
        .attr("class", "containertextshadow")
        .attr("x", function(d) { 
          d.w = this.getComputedTextLength();
          if(d.w > d.dx) {
            d.doclip = true;
            return 0;
          }
          return d.dx / 2;})
        .attr("y", function(d) { return d.dy / 2; })
        .attr("dy", ".35em")
        .attr("font-weight", "bold")
        .attr("font-size", ".85em")
        .attr("text-anchor", function(d) { return "middle"; })
  //      .attr("clip-path", function(d, i) { return "url(#" + d.clipname + ")"; })
        .style("opacity", function(d) {
            d.w = this.getComputedTextLength();
            
            if(d.l != This.vizlevel) {
              return 0;
            } else {
              return d.dx - 2 > d.w ? 1 : 0;             
            }
          });
        
    container.append("svg:text")
        .text(function(d) { return d.name; })
        .attr("class", "containertext")
        .attr("x", function(d) { return d.dx / 2; })
        .attr("y", function(d) { return d.dy / 2; })
        .attr("dy", ".35em")
        .attr("font-weight", "bold")
        .attr("font-size", ".85em")
        .attr("text-anchor", function(d) { return "middle"; })
  //      .attr("clip-path", function(d, i) { return "url(#" + d.clipname + ")"; })
        .style("opacity", function(d) { 
            d.w = this.getComputedTextLength();
            
            if(d.l != This.vizlevel) {
              return 0;
            } else {
              return d.dx - 2 > d.w ? 1 : 0;             
            }
          });
  
    if(This.root.zoom_target) {
      var n = This.find_node(This.root, This.root.zoom_target.name);
      
      if(n) {
        breadcrumb_push(n, true);
        This.zoom(n, This.ZOOM_DURATION, ZOOM_TYPE_IN);        
      }
    }
  }
  
  This.size = function(d) {
    return d.size;
  }
  
  This.count = function(d) {
    return 1;
  }
  
  ////////////////////////////////////////////////////////////////////////////////
  // ZOOM
  ////////////////////////////////////////////////////////////////////////////////
  This.zoom = function(targetnode, duration, zoom_type) {
    This.is_zooming = true;
    //
    // targetnode = null means that we've clicked on a breacrumb item that was created before the chart
    // and whose purpose is just reverting to root.
    // As a consequence, we set the node and change the vizlevel to simulate coming back to root.
    //
    if(targetnode === null) {
      targetnode = This.root;
      if(zoom_type === ZOOM_TYPE_OUT) {
        This.vizlevel = 1;
      } else if(zoom_type === ZOOM_TYPE_SAME) {
        This.vizlevel = 0;      
      } else {
        console.log("illegal zoom type");  
      }
    }
  
    if(targetnode) {
      This.kx = This.w / targetnode.dx;
      This.ky = This.h / targetnode.dy;    
    
      This.x.domain([targetnode.x, targetnode.x + targetnode.dx]);
      This.y.domain([targetnode.y, targetnode.y + targetnode.dy]);
    }
    
    if(zoom_type == ZOOM_TYPE_OUT) {
      This.vizlevel--;
    }
    else if(zoom_type == ZOOM_TYPE_IN) {
      This.vizlevel++;
    }
  //  console.log(duration);
    
    //
    // Leaves
    //
    var t = This.svg.selectAll("g.cell")
      .transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + This.x(d.x) + "," + This.y(d.y) + ")"; })
      .style("opacity", function(d) { 
        if(zoom_type == ZOOM_TYPE_OUT) {
          if((d.l === This.vizlevel + 1) || (d.l === This.vizlevel && d.children == undefined)) {
            d.visible = true;
          } else {
            d.visible = false;            
          }
        } else {
          if(d.parent === targetnode || d.parent.parent === targetnode) {
            if((d.l === This.vizlevel + 1) || (d.l === This.root.data_depth - 1) || (d.l === This.vizlevel && d.children == undefined)) {
              d.visible = true;              
            }
            else {
              d.visible = false;
            }
          } else {
            if(d.l === This.vizlevel) {
              d.visible = true;
            } else {
              d.visible = false;
            }
          }
        }
                  
        if(d.visible) {
          return 1;
        } else {
          return 0;
        }
      })
      ;
  
    t.select("rect.cellrect")
        .attr("width", function(d) { return This.kx * d.dx - 1; })
        .attr("height", function(d) { return This.ky * d.dy - 1; })
  
    t.select("text.celltext")
        .attr("x", function(d) { return 0; })
        .attr("y", function(d) { return 7; })
        .style("opacity", function(d) {
          if(!This.root.show_child_labels) {
            // When show_child_labels is set in the json, we never hide the label
            if(d.l > This.vizlevel) {
              return 0;          
            }
          }
          
          return This.kx * d.dx > d.w ? 1 : 0;
        });
  
    var cont = This.svg.selectAll("g.container").transition()
        .duration(duration)
        .attr("transform", function(d) { return "translate(" + This.x(d.x) + "," + This.y(d.y) + ")"; });
  
    cont.select("text.containertextshadow")
        .attr("x", function(d) { return This.kx * (d.dx / 2); })
        .attr("y", function(d) { return This.ky * (d.dy / 2); })
        .style("opacity", function(d) {      
          if(d.l != This.vizlevel) {
            return 0;
          } else {
            d.box = this.getBBox();
            if(d.box.width < d.dx && d.box.height < d.dy) {
              return 1;
            }
            else
            {
              return 0;
            }
          }
        });
        
    cont.select("text.containertext")
      .attr("x", function(d) { return This.kx * (d.dx / 2); })
      .attr("y", function(d) { return This.ky * (d.dy / 2); })
      .style("opacity", function(d) {        
        if(d.l != This.vizlevel) {
            return 0;
          } else {
            d.box = this.getBBox();
            if(d.box.width < d.dx && d.box.height < d.dy) {
              return 1;
            }
            else
            {
              return 0;
            }
          }
          });
        
    This.node = targetnode;
    
    if(d3.event) {
      d3.event.stopPropagation();  
    }
    
    setTimeout(This.on_endzoom, duration);
  }

  This.on_endzoom = function() {
    This.is_zooming = false;
  }
  
  //
  // Remove the current dataset and replace it with the given one 
  //
  This.replace_viz = function(data) {
    //
    // Fade out the whole thing
    //
    d3.select("#svg" + This.parent_div_id)
      .transition()
      .duration(This.REPLACE_DURATION)
      .style("opacity", 0)
      .remove();
  
    setTimeout(This.create_svg, 500, data);
  }
  
  //
  // Update the visualization with new data
  //
  This.update_viz_data = function(json, column, action) {
    if(action === UPDATE_ACTION_LOAD) {
      This.create_svg(json);
    }
    else if (action === UPDATE_ACTION_REPLACE) {
      This.replace_viz(json);
    }
    else {
      document.getElementById('button_metrics').innerHTML = This.root.metric_alternatives[column][0] + '<span class="caret"></span>';
      
      This.treemap.value(function(d) {
            return d['c' + column];
        }).nodes(This.root);
        
      This.zoom(null, 2000, ZOOM_TYPE_SAME);
    }
  }
}
