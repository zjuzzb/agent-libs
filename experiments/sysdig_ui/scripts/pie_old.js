function DrPie(parent_div_id, shownow) {
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
  This.create_svg = function(json) {
    var data = json.data
    var radius = Math.min(This.w, This.h) / 2 - 30;
    
    var color = d3.scale.ordinal()
        .range(["#98abc5", "#8a89a6", "#7b6888", "#6b486b", "#a05d56", "#d0743c", "#ff8c00"]);

    var arc = d3.svg.arc()
        .outerRadius(radius - 10)
        .innerRadius(0);

    var arcOver = d3.svg.arc().outerRadius(radius + 10);

    var pie = d3.layout.pie()
        .sort(null)
        .value(function(d) { return d.c0; });

    var svg = d3.select("#" + parent_div_id).append("div")
        .attr("class", "chart")
        .style("width", This.w + "px")
        .style("height", This.h + "px")
        .attr("id", "svg" + This.parent_div_id)
        .append("svg:svg")
        .attr("width", This.w)
        .attr("height", This.h)
        .append("g")
          .attr("transform", "translate(" + This.w / 2 + "," + This.h / 2 + ")");

    //
    // Smooth visualization entrance
    //
    svg.style("opacity", 0)
      .transition()
        .duration(500)
        .style("opacity", 1);

    data.forEach(function(d) {
      d.c0 = +d.c0;
    });

    var g = svg.selectAll(".arc")
        .data(pie(data))
      .enter().append("g")
        .attr("class", "arc")
        .on("click", function(d) {
          g_ChartManager.push(d.data.click_target[0], d.data.click_target[1]);
        })
        .on("mouseover", function(d) {
            d3.select(this).select("path").transition()
               .duration(1000)
               .attr("d", arcOver);
        })
        .on("mouseout", function(d) {
            d3.select(this).select("path").transition()
               .duration(1000)
               .attr("d", arc);
        });

    var paths = g.append("path")
        .attr("d", arc)
        .style("fill", function(d) { return color(d.data.c0); });

    g.append("text")
        .attr("transform", function(d) { return "translate(" + arc.centroid(d) + ")"; })
        .attr("dy", ".35em")
        .style("text-anchor", "middle")
        .text(function(d) { return d.data.name; });

    var ar = d3.svg.arc()
    .startAngle(function(d, i){
      if(i == 0) {
        return 0;         
      } else {
        return 2;
      }
    })
    .endAngle(function(d, i){
      if(i == 0) {
        return 2;         
      } else {
        return 6.283185;
      }
    })
    ;

    paths
      .transition()
        .duration(1000)
        .attr("d", ar);
  }
  
  /////////////////////////////////////////////////////////////////////////////////  
  // This does nothing for this chart for the moment
  /////////////////////////////////////////////////////////////////////////////////  
  This.show = function(data) {
  }
    
  /////////////////////////////////////////////////////////////////////////////////  
  // Use elliptical arc path segments to doubly-encode directionality.
  /////////////////////////////////////////////////////////////////////////////////  
  This.resize_slices = function() {
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
      This.resize_slices();
    }
  }
}
