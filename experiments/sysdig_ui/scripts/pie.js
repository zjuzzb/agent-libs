// Inspired by http://jsfiddle.net/stephenboak/hYuPb/, http://blog.stephenboak.com/2011/08/07/easy-as-a-pie.html

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
  This.numcol = 0;    // This is the 0-based number of the the column that is going to be used for the slice size. 
                      // For example, if numcol is 1, c1 will be used.

  This.r = Math.min(This.w, This.h) / 2 - 30;       // Pie Radius
  This.ir = 0;
  This.textOffset = 14;
  This.tweenDuration = 250;
  
  //OBJECTS TO BE POPULATED WITH DATA
  This.lines;
  This.valueLabels;
  This.nameLabels;
  This.pieData = [];    
  This.oldPieData = [];
  This.filteredPieData = [];

  This.arc_group = undefined;
  This.label_group = undefined;
  This.center_group = undefined;
  This.paths = undefined;

  //D3 helper function to populate pie slice parameters from array data
  This.donut = d3.layout.pie().value(function(d){
    return d['c' + This.numcol];
  });

  //D3 helper function to create colors from an ordinal scale
  This.color = d3.scale.category20();

  //D3 helper function to draw arcs, populates parameter "d" in path object
  This.arc = d3.svg.arc()
    .startAngle(function(d){ return d.startAngle; })
    .endAngle(function(d){ return d.endAngle; })
    .innerRadius(This.ir)
    .outerRadius(This.r);

  This.arcOver = d3.svg.arc().outerRadius(This.r + 25);

  /////////////////////////////////////////////////////////////////////////////////
  //
  /////////////////////////////////////////////////////////////////////////////////  
  This.create_svg = function(data) {
    This.root = data;

    ///////////////////////////////////////////////////////////
    // CREATE VIS & GROUPS ////////////////////////////////////
    ///////////////////////////////////////////////////////////    
    var vis = d3.select("#" + parent_div_id).append("div")
            .attr("class", "chart")
            .style("width", This.w + "px")
            .style("height", This.h + "px")
            .attr("id", "svg" + This.parent_div_id)
            .append("svg:svg")
            .attr("width", This.w)
            .attr("height", This.h);

    //
    // Smooth visualization entrance
    //
    vis.style("opacity", 0)
      .transition()
        .duration(500)
        .style("opacity", 1);

    //GROUP FOR ARCS/PATHS
    This.arc_group = vis.append("svg:g")
      .attr("class", "arc")
      .attr("transform", "translate(" + (This.w/2) + "," + (This.h/2) + ")");

    //GROUP FOR LABELS
    This.label_group = vis.append("svg:g")
      .attr("class", "label_group")
      .attr("transform", "translate(" + (This.w/2) + "," + (This.h/2) + ")");

    //GROUP FOR CENTER TEXT  
    This.center_group = vis.append("svg:g")
      .attr("class", "center_group")
      .attr("transform", "translate(" + (This.w/2) + "," + (This.h/2) + ")");

    //PLACEHOLDER GRAY CIRCLE
    This.paths = This.arc_group.append("svg:circle")
        .attr("fill", "#EFEFEF")
        .attr("r", This.r);

    ///////////////////////////////////////////////////////////
    // CENTER TEXT ////////////////////////////////////////////
    ///////////////////////////////////////////////////////////

    //WHITE CIRCLE BEHIND LABELS
    var whiteCircle = This.center_group.append("svg:circle")
      .attr("fill", "white")
      .attr("r", This.ir);

    ///////////////////////////////////////////////////////////
    // UPDATE THE PIE
    // NOTE: this nee
    ///////////////////////////////////////////////////////////
    This.update();
    This.update();
  }
  

  ///////////////////////////////////////////////////////////
  // helper functions
  ///////////////////////////////////////////////////////////

  // Interpolate the arcs in data space.
  This.pieTween = function(d, i) {
    var s0;
    var e0;
    if(This.oldPieData[i]){
      s0 = This.oldPieData[i].startAngle;
      e0 = This.oldPieData[i].endAngle;
    } else if (!(This.oldPieData[i]) && This.oldPieData[i-1]) {
      s0 = This.oldPieData[i-1].endAngle;
      e0 = This.oldPieData[i-1].endAngle;
    } else if(!(This.oldPieData[i-1]) && This.oldPieData.length > 0){
      s0 = This.oldPieData[This.oldPieData.length-1].endAngle;
      e0 = This.oldPieData[This.oldPieData.length-1].endAngle;
    } else {
      s0 = 0;
      e0 = 0;
    }
    var i = d3.interpolate({startAngle: s0, endAngle: e0}, {startAngle: d.startAngle, endAngle: d.endAngle});
    return function(t) {
      var b = i(t);
      return This.arc(b);
    };
  }

  This.removePieTween = function(d, i) {
    s0 = 2 * Math.PI;
    e0 = 2 * Math.PI;
    var i = d3.interpolate({startAngle: d.startAngle, endAngle: d.endAngle}, {startAngle: s0, endAngle: e0});
    return function(t) {
      var b = i(t);
      return This.arc(b);
    };
  }

  This.textTween = function(d, i) {
    var a;
    if(This.oldPieData[i]){
      a = (This.oldPieData[i].startAngle + This.oldPieData[i].endAngle - Math.PI)/2;
    } else if (!(This.oldPieData[i]) && This.oldPieData[i-1]) {
      a = (This.oldPieData[i-1].startAngle + This.oldPieData[i-1].endAngle - Math.PI)/2;
    } else if(!(This.oldPieData[i-1]) && This.oldPieData.length > 0) {
      a = (This.oldPieData[This.oldPieData.length-1].startAngle + This.oldPieData[This.oldPieData.length-1].endAngle - Math.PI)/2;
    } else {
      a = 0;
    }
    var b = (d.startAngle + d.endAngle - Math.PI)/2;

    var fn = d3.interpolateNumber(a, b);
    return function(t) {
      var val = fn(t);
      return "translate(" + Math.cos(val) * (This.r+This.textOffset) + "," + Math.sin(val) * (This.r+This.textOffset) + ")";
    };
  }

  /////////////////////////////////////////////////////////////////////////////////  
  // Update function
  /////////////////////////////////////////////////////////////////////////////////  
  This.update = function() {
    arraySize = Math.ceil(Math.random()*10);
    streakerDataAdded = This.root.data;

    This.oldPieData = This.filteredPieData;
    This.pieData = This.donut(streakerDataAdded);

    var totalOctets = 0;
    This.filteredPieData = This.pieData.filter(filterData);
    function filterData(element, index, array) {
      element.name = streakerDataAdded[index].name;
      element.value = streakerDataAdded[index]['c' + This.numcol];
      totalOctets += element.value;
      return (element.value > 0);
    }

    if(This.filteredPieData.length > 0 && This.oldPieData.length > 0){

      //REMOVE PLACEHOLDER CIRCLE
      This.arc_group.selectAll("circle").remove();

      //DRAW ARC PATHS
      This.paths = This.arc_group.selectAll("path").data(This.filteredPieData);
      This.paths.enter().append("svg:path")
        .attr("stroke", "white")
        .attr("stroke-width", 0.5)
        .attr("fill", function(d, i) { return This.color(i); })
        .on("click", function(d) {
          g_ChartManager.push(d.data.click_target[0], d.data.click_target[1]);
        })
        .on("mouseover", function(d) {
            d3.select(this).transition()
               .duration(500)
               .attr("d", This.arcOver);
        })
        .on("mouseout", function(d) {
            d3.select(this).transition()
               .duration(500)
               .attr("d", This.arc);
        })
        .transition()
          .duration(This.tweenDuration)
          .attrTween("d", This.pieTween);
      This.paths
        .transition()
          .duration(This.tweenDuration)
          .attrTween("d", This.pieTween);
      This.paths.exit()
        .transition()
          .duration(This.tweenDuration)
          .attrTween("d", This.removePieTween)
        .remove();

      //DRAW TICK MARK LINES FOR LABELS
      This.lines = This.label_group.selectAll("line").data(This.filteredPieData);
      This.lines.enter().append("svg:line")
        .attr("x1", 0)
        .attr("x2", 0)
        .attr("y1", -This.r-3)
        .attr("y2", -This.r-8)
        .attr("stroke", "gray")
        .attr("transform", function(d) {
          return "rotate(" + (d.startAngle+d.endAngle)/2 * (180/Math.PI) + ")";
        });
      This.lines.transition()
        .duration(This.tweenDuration)
        .attr("transform", function(d) {
          return "rotate(" + (d.startAngle+d.endAngle)/2 * (180/Math.PI) + ")";
        });
      This.lines.exit().remove();

      //DRAW LABELS WITH PERCENTAGE VALUES
      This.valueLabels = This.label_group.selectAll("text.value").data(This.filteredPieData)
        .attr("dy", function(d){
          if ((d.startAngle+d.endAngle)/2 > Math.PI/2 && (d.startAngle+d.endAngle)/2 < Math.PI*1.5 ) {
            return 5;
          } else {
            return -7;
          }
        })
        .attr("text-anchor", function(d){
          if ( (d.startAngle+d.endAngle)/2 < Math.PI ){
            return "beginning";
          } else {
            return "end";
          }
        })
        .text(function(d){
          var percentage = (d.value/totalOctets)*100;
          return percentage.toFixed(1) + "%";
        });

      This.valueLabels.enter().append("svg:text")
        .attr("class", "value")
        .attr("transform", function(d) {
          return "translate(" + Math.cos(((d.startAngle+d.endAngle - Math.PI)/2)) * (This.r+This.textOffset) + "," + Math.sin((d.startAngle+d.endAngle - Math.PI)/2) * (This.r+This.textOffset) + ")";
        })
        .attr("dy", function(d){
          if ((d.startAngle+d.endAngle)/2 > Math.PI/2 && (d.startAngle+d.endAngle)/2 < Math.PI*1.5 ) {
            return 5;
          } else {
            return -7;
          }
        })
        .attr("text-anchor", function(d){
          if ( (d.startAngle+d.endAngle)/2 < Math.PI ){
            return "beginning";
          } else {
            return "end";
          }
        }).text(function(d){
          var percentage = (d.value/totalOctets)*100;
          return percentage.toFixed(1) + "%";
        });

      This.valueLabels.transition().duration(This.tweenDuration).attrTween("transform", This.textTween);

      This.valueLabels.exit().remove();


      //DRAW LABELS WITH ENTITY NAMES
      This.nameLabels = This.label_group.selectAll("text.units").data(This.filteredPieData)
        .attr("dy", function(d){
          if ((d.startAngle+d.endAngle)/2 > Math.PI/2 && (d.startAngle+d.endAngle)/2 < Math.PI*1.5 ) {
            return 17;
          } else {
            return 5;
          }
        })
        .attr("text-anchor", function(d){
          if ((d.startAngle+d.endAngle)/2 < Math.PI ) {
            return "beginning";
          } else {
            return "end";
          }
        }).text(function(d){
          return d.name;
        });

      This.nameLabels.enter().append("svg:text")
        .attr("class", "units")
        .attr("transform", function(d) {
          return "translate(" + Math.cos(((d.startAngle+d.endAngle - Math.PI)/2)) * (This.r+This.textOffset) + "," + Math.sin((d.startAngle+d.endAngle - Math.PI)/2) * (This.r+This.textOffset) + ")";
        })
        .attr("dy", function(d){
          if ((d.startAngle+d.endAngle)/2 > Math.PI/2 && (d.startAngle+d.endAngle)/2 < Math.PI*1.5 ) {
            return 17;
          } else {
            return 5;
          }
        })
        .attr("text-anchor", function(d){
          if ((d.startAngle+d.endAngle)/2 < Math.PI ) {
            return "beginning";
          } else {
            return "end";
          }
        }).text(function(d){
          return d.name;
        });

      This.nameLabels.transition().duration(This.tweenDuration).attrTween("transform", This.textTween);

      This.nameLabels.exit().remove();
    }  
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
      This.update();
    }
  }
}
