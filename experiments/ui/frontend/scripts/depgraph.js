function DrDepGrap(parent_div_id, shownow) {
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
  
  /////////////////////////////////////////////////////////////////////////////////
  //
  /////////////////////////////////////////////////////////////////////////////////  
  This.create_svg = function(data) {
    This.root = data;
    
    This.force = d3.layout.force()
        .nodes(data.nodes)
        .links(data.links)
        .size([This.w, This.h])
        .linkDistance(180)
        .charge(-600)
        .on("tick", This.tick)
        .start();
    
    var svg = d3.select("#" + parent_div_id).append("div")
        .attr("class", "chartz")
        .style("width", This.w + "px")
        .style("height", This.h + "px")
        .attr("id", "svg" + "ciao")
        .append("svg:svg")
        .attr("width", This.w)
        .attr("height", This.h);
    
    // Per-type markers, as they don't inherit styles.
    svg.append("svg:defs").selectAll("marker")
        .data(["ok", "warning", "error"])
      .enter().append("svg:marker")
        .attr("id", String)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 12)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
      .append("svg:path")
        .attr("d", "M0,-5L10,0L0,5");
    
    This.path = svg.append("svg:g").selectAll("path")
        .data(This.force.links())
      .enter().append("svg:path")
        .attr("class", function(d) { return "link " + d.status; })
        .attr("marker-end", function(d) { return "url(#" + d.status + ")"; });
    
    This.circle = svg.append("svg:g").selectAll("circle")
        .data(This.force.nodes())
      .enter().append("svg:circle")
        .attr("r", function(d) { 
            d.r = d["c"+This.numcol];
            return d.r;
          })
        .style("fill", function(d) {
          var s = d["c"+This.numcol];

          if(s < 23) {
            d.col = d3.rgb(10, 240, 10);      
          } else if(s < 30) {
            d.col = d3.rgb(240, 240, 10);        
          } else {
            d.col = d3.rgb(240, 10, 10);
          }
      
          return d.col;
          })
        .style("stroke", function(d) { return d.col.darker(2);})
        .call(This.force.drag)
        .on("dblclick", function() {
          d3.select(this)
          .style("stroke", "#dddd22")
          .style("stroke-width", 10);
          
          g_ChartManager.push(This.root.click_target[0], This.root.click_target[1]);
        })
        .on("mouseover", function() {
          d3.select(this)
          .transition()
          .duration(200)
          .attr("r", function(d) { return d.r + 10;});
        })
        .on("mouseout", function() {
          d3.select(this)
          .transition()
          .duration(1000)
          .attr("r", function(d) { return d.r;});
        })
        ;
    
    This.text = svg.append("svg:g").selectAll("g")
        .data(This.force.nodes())
      .enter().append("svg:g");
    
    // A copy of the text with a thick white stroke for legibility.
    This.text.append("svg:text")
        .attr("x", function(d) { 0;})
        .attr("y", ".31em")
        .attr("class", "shadow")
        .text(function(d) { return d.label; });
    
    This.text.append("svg:text")
        .attr("x", function(d) { 0;})
        .attr("y", ".31em")
        .text(function(d) { return d.label; });
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // This does nothing for this chart for the moment
  /////////////////////////////////////////////////////////////////////////////////  
  This.show = function(data) {
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // Use elliptical arc path segments to doubly-encode directionality.
  /////////////////////////////////////////////////////////////////////////////////  
  This.tick = function() {
    This.path.attr("d", function(d) {
      var dx = d.target.x - d.source.x,
          dy = d.target.y - d.source.y,
          dr = Math.sqrt(dx * dx + dy * dy) * 2;
      return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + (d.target.x - d.target["c"+This.numcol] + 3) + "," + (d.target.y);
    });
  
    This.circle.attr("transform", function(d) {
      return "translate(" + d.x + "," + d.y + ")";
    });
  
    This.text
    .attr("transform", function(d) {
      return "translate(" + (d.x + d["c"+This.numcol] + 2) + "," + d.y + ")";
    });
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // Use elliptical arc path segments to doubly-encode directionality.
  /////////////////////////////////////////////////////////////////////////////////  
  This.resize_circles = function() {
    This.path
    .transition()
    .duration(1000)
    .attr("d", function(d) {
      var dx = d.target.x - d.source.x,
          dy = d.target.y - d.source.y,
          dr = Math.sqrt(dx * dx + dy * dy) * 2;
      return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + (d.target.x - d.target["c"+This.numcol] + 3) + "," + (d.target.y);
    });
    
    This.circle
    .transition()
    .duration(1000)
    .style("fill", function(d) {
      var s = d["c"+This.numcol];

      if(s < 23) {
        d.col = d3.rgb(10, 240, 10);      
      } else if(s < 30) {
        d.col = d3.rgb(240, 240, 10);        
      } else {
        d.col = d3.rgb(240, 10, 10);
      }
  
      return d.col;
      })
    .style("stroke", function(d) { return d.col.darker(2);})
    .attr("r", function(d) {
      d.r = d["c"+This.numcol];
      return d.r;
    });

    This.text
    .transition()
    .duration(1000)
    .attr("transform", function(d) {
      return "translate(" + (d.x + d["c"+This.numcol] + 2) + "," + d.y + ")";
    });    
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
  
  /////////////////////////////////////////////////////////////////////////////////  
  // Update the visualization with new data
  /////////////////////////////////////////////////////////////////////////////////  
  This.randomize = function() {
      if(This.numcol !== 3) {
        This.numcol = 3;
      } else {
        This.numcol = 0;       
      }
      
      This.resize_circles();
  }
}
