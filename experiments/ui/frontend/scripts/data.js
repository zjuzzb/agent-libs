function on_data_load(json) {
  //
  // Initialize the "show" menu
  //
  document.getElementById('button_objs').innerHTML = json.name + '<span class="caret"></span>';
  document.getElementById('button_metrics').innerHTML = json.metric_alternatives[json.metric_selection][0] + '<span class="caret"></span>';

  //
  // Update the breadcrumb
  //
  if(json.hierarchy_level > 0) {
    breadcrumb_set({name: 'All Machines'}, false);
  }
  
  for(var j = 0; j < json.entity_name.length; j++) {
    breadcrumb_push({name: json.entity_name[j]}, true);    
  }
  
  //
  // Update the entities menu
  //
  var objs_list = $('#show-objs')[0];

  objs_list.innerHTML = '';

  for(var j = 0; j < json.entity_alternatives.length; j++) {
    var tname = json.entity_alternatives[j];
    objs_list.innerHTML += '<li><a href="#" onclick=\"load_data(\'/data/' + json.entity_name + '/' + tname +'.json\');\">' + tname + '</a></li>';
  }

  //
  // Update the metrics menu
  //
  objs_list = $('#show-metrics')[0];

  objs_list.innerHTML = '';

  for(var j = 0; j < json.metric_alternatives.length; j++) {
    var tname = json.metric_alternatives[j][0];
    var col_target = json.metric_alternatives[j][1];
    
    if(typeof(col_target) == 'number') {
      objs_list.innerHTML += '<li><a href="#" onclick=\"g_ChartManager.current().update_viz_data(null, ' + col_target +', UPDATE_ACTION_CHANGE);\">' + tname + '</a></li>';    
    } else {
      objs_list.innerHTML += '<li><a href="#" onclick=\"load_data(\'/data/' + col_target +'\');\">' + tname + '</a></li>';    
    }
  }
  
  //
  // Update the chart
  //
  if(!g_ChartManager.current().is_initialized) {
    g_ChartManager.current().update_viz_data(json, null, UPDATE_ACTION_LOAD);  
    g_ChartManager.current().is_initialized = true;
  }
  else {
    g_ChartManager.current().shownow = true;
    g_ChartManager.current().update_viz_data(json, null, UPDATE_ACTION_REPLACE);      
  }
}

//
// Load json data from the given URL
//
function load_data(url) {
  $.ajax({
    type : 'GET',
    url : url,
    dataType : 'json',
    success : on_data_load,
    data : {},
    async : false
  });
}

//
// Init the time slider in the left panel
//
$("#slider2").timeslider({
  sliderOptions: {
    range: true, 
  min: 420, 
  max: 600, 
  values: [420, 600],
  step:5
  },
  errorMessage: '#max2',
  timeDisplay: '#time2',
  submitButton: '#schedule-submit2',
});

//
// Entry point for the page scripts
//
$(window).load(function() {
  g_ChartManager.push('data/netgraph.json', g_ChartManager.TYPE_DEPENDENCY_GRAPH);
//  g_ChartManager.push('/data/frontend01/Processes.json', g_ChartManager.TYPE_TREEMAP);
//  g_ChartManager.push('/data/app-serv01/Network Apps.json', g_ChartManager.TYPE_TREEMAP);
//  g_ChartManager.push('/data/frontend01/Directories.json', g_ChartManager.TYPE_TREEMAP);
//  g_ChartManager.push('/data/fileops.json', g_ChartManager.TYPE_OPLIST);
});
