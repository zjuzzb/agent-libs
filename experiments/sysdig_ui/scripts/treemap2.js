function treemap2(data, unit) {
  var This = this;
  This.root = data;
  This.color = d3.scale.category20c();
  This.unit = unit;

  $('#chart')[0].innerHTML = '';

  var margin = {top: 23, right: 0, bottom: 0, left: 0},
      width = 960,
      height = 500 - margin.top - margin.bottom,
      formatNumber = d3.format(",d"),
      transitioning;

  var x = d3.scale.linear()
      .domain([0, width])
      .range([0, width]);

  var y = d3.scale.linear()
      .domain([0, height])
      .range([0, height]);

  var treemap = d3.layout.treemap()
      .children(function(d, depth) { return depth ? null : d._children; })
      .sort(function(a, b) { return a.value - b.value; })
      .ratio(height / width * 0.5 * (1 + Math.sqrt(5)))
      .round(false);

  var svg = d3.select("#chart").append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.bottom + margin.top)
      .style("margin-left", -margin.left + "px")
      .style("margin.right", -margin.right + "px")
    .append("g")
      .attr("transform", "translate(" + margin.left + "," + margin.top + ")")
      .style("shape-rendering", "crispEdges");

  var grandparent = svg.append("g")
      .attr("class", "grandparent");

  var backbutton = d3.select("#backbutton");

  grandparent.append("rect")
      .attr("y", -margin.top)
      .attr("width", width)
      .attr("height", margin.top);

  grandparent.append("text")
      .attr("x", 6)
      .attr("y", 6 - margin.top)
      .attr("dy", ".75em");

  load(data);

  // Disable childs. Each of them will be activated when the user clicks on them
  function hide_childs(d) {
      d._children.forEach(function(c) {
       if(c._children !== undefined) {
        hide_childs(c);
        c._bchildren = c._children;
        c._children = undefined;
      }
    });
  }

  function load(root) {
    initialize(root);
    accumulate(root);
    hide_childs(root);
    layout(root);
    display(root);

    function initialize(root) {
      root.x = root.y = 0;
      root.dx = width;
      root.dy = height;
      root.depth = 0;
    }

    // Aggregate the values for internal nodes. This is normally done by the
    // treemap layout, but not here because of our custom implementation.
    // We also take a snapshot of the original children (_children) to avoid
    // the children being overwritten when when layout is computed.
    function accumulate(d) {
      return (d._children = d.children)
          ? d.value = d.children.reduce(function(p, v) { return p + accumulate(v); }, 0)
          : d.value;
    }
    
    // Compute the treemap layout recursively such that each group of siblings
    // uses the same size (1×1) rather than the dimensions of the parent cell.
    // This optimizes the layout for the current zoom state. Note that a wrapper
    // object is created for the parent node for each group of siblings so that
    // the parent’s dimensions are not discarded as we recurse. Since each group
    // of sibling was laid out in 1×1, we must rescale to fit using absolute
    // coordinates. This lets us use a viewport to zoom.
    function layout(d) {
      if (d._children) {
        treemap.nodes({_children: d._children});
        d._children.forEach(function(c) {
          c.x = d.x + c.x * d.dx;
          c.y = d.y + c.y * d.dy;
          c.dx *= d.dx;
          c.dy *= d.dy;
          c.parent = d;
          layout(c);
        });
      }
    }

    function display(d) {
      grandparent
          .datum(d.parent)
          .on("click", function(d) {
            This.zoomout(d, g1);
          })
        .select("text")
          .text(name(d));

      backbutton
          .datum(d.parent)
          .on("click", function(d) {
            This.zoomout(d, g1);
          });

      var g1 = svg.insert("g", ".grandparent")
          .datum(d)
          .attr("class", "depth");

      var g = g1.selectAll("g")
          .data(d._children)
        .enter().append("g");

      g.filter(function(d) { return (d._children || d._bchildren); })
          .classed("children", true)
          .classed("selectable", true)
          .on("mouseover", function(d) {
            pt = $("#infotext")[0];
            pt.innerHTML = This.unit + ': ' + d.value;

            grandparent
              .select("text")
                .text(name(d));
          })
          .on("mouseout", function(d) {
            grandparent
              .select("text")
                .text(name(d.parent));
          })
          .on("click", function(d) {
              d._children = d._bchildren;
              layout(d);
              transition(d, g);              
          });

      g.filter(function(d) { return !(d._children || d._bchildren); })
          .classed("children", true)
          .classed("unselectable", true)
          .on("mouseover", function(d) {
            pt = $("#infotext")[0];
            pt.innerHTML = This.unit + ': ' + d.value;

            grandparent
              .select("text")
                .text(name(d));
          })
          .on("mouseout", function(d) {
            grandparent
              .select("text")
                .text(name(d.parent));
          });

      g.selectAll(".child")
          .data(function(d) { return d._children || [d]; })
        .enter().append("rect")
          .attr("class", "child")
          .call(rect);

      g.append("rect")
          .attr("class", "parent")
          .call(rect)
        .append("title")
          .text(function(d) { return formatNumber(d.value); });

      g.append("text")
          .attr("dy", ".75em")
          .text(function(d) { return d.name; })
          .call(text);

      return g;
    }

    function transition(d, g1) {
      if (transitioning || !d) return;
      transitioning = true;

      var g2 = display(d),
          t1 = g1.transition().duration(500),
          t2 = g2.transition().duration(500);

      // Update the domain only after entering new elements.
      x.domain([d.x, d.x + d.dx]);
      y.domain([d.y, d.y + d.dy]);

      // Enable anti-aliasing during the transition.
      svg.style("shape-rendering", null);

      // Draw child nodes on top of parent nodes.
      svg.selectAll(".depth").sort(function(a, b) { return a.depth - b.depth; });

      // Fade-in entering text.
      g2.selectAll("text").style("fill-opacity", 0);

      // Transition to the new view.
      t1.selectAll("text").call(text).style("fill-opacity", 0);
      t2.selectAll("text").call(text)
        .attr("font-size", function(d) {
          this.setAttribute("font-size", 14);
          tw = this.getComputedTextLength();

          var boxw = x(d.x + d.dx) - x(d.x);
          var boxh = y(d.y + d.dy) - y(d.y);

          d.fntsize = Math.min(boxw / tw * 12, boxh * 0.666);

          if(d.fntsize > 14) {
            d.fntsize = 14;
          } else if(d.fntsize < 8){
            d.fntsize = 8;
          }

          this.setAttribute("font-size", d.fntsize);
          return d.fntsize;
        })
        .style("fill-opacity", function(d) {
          tw = this.getComputedTextLength();
        
          var boxw = x(d.x + d.dx) - x(d.x);
          var boxh = y(d.y + d.dy) - y(d.y);

          if((tw + 6) >= boxw || boxh < d.fntsize * 1.5) {
            return 0;
          } else {
            return 1;
          }
        });

      t1.selectAll("rect").call(rect);
      t2.selectAll("rect").call(rect);

      // Get rid of the old node when the transition is finished.
      t1.remove().each("end", function() {
        svg.style("shape-rendering", "crispEdges");
        transitioning = false;
      });
    }

    This.zoomout = function(d, g1) {
      hide_childs(d);
      transition(d, g1);
    }

    function text(text) {
      text
          .attr("font-size", function(d) {
            tw = this.getComputedTextLength();
  
            var boxw = x(d.x + d.dx) - x(d.x);
            var boxh = y(d.y + d.dy) - y(d.y);

            d.fntsize = Math.min(boxw / tw * 12, boxh * 0.666);

            if(d.fntsize > 14) {
              d.fntsize = 14;
            } else if(d.fntsize < 8){
              d.fntsize = 8;
            }

            return d.fntsize;
          })
          .attr("x", function(d) { 
            return x(d.x) + 6 * d.fntsize / 18; 
          })
          .attr("y", function(d) { 
            return y(d.y) + 6 * d.fntsize / 18; 
          })
          .style("fill-opacity", function(d) {
            tw = this.getComputedTextLength();
          
            var boxw = x(d.x + d.dx) - x(d.x);
            var boxh = y(d.y + d.dy) - y(d.y);

            if((tw + 6) >= boxw || boxh < d.fntsize * 1.5) {
              return 0;
            } else {
              return 1;
            }
        });
    }

    function rect(rect) {
      rect.attr("x", function(d) { return x(d.x); })
          .attr("y", function(d) { return y(d.y); })
          .attr("width", function(d) { return x(d.x + d.dx) - x(d.x); })
          .attr("height", function(d) { return y(d.y + d.dy) - y(d.y); })
          .style("fill", function(d) {
            var res = This.color(d.name); 
            return res;})
// remove this to go much faster on firefox
          .style("opacity", function(d) {
            return 0;
          })
          .transition().duration(500)
            .style("opacity", function(d) {
              return 0.5;
            })
///////////////////////////////////////////
          ;
    }

    function name(d) {
      return d.parent
          ? name(d.parent) + " > " + d.name
          : d.name;
    }
  }

  return this;
}
