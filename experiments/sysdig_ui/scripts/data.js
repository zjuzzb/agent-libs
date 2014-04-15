function on_data_load(json) {
  //
  // Reset the breadcrumb
  //
  breadcrumb_set({name: json.name}, true);    
  
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

function on_data_load_error(jqXHR, textStatus, errorThrown) {
  var a = 0;
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
    error : on_data_load_error,
    data : {},
    async : false
  });
}

//
// Load json data from the given URL
//
function update_viz() {
  url = "/run";
  var key1 = $('#button_key1').attr("selval")
  var key2 = $('#button_key2').attr("selval")
  var key3 = $('#button_key3').attr("selval")
  body = JSON.stringify({"value":g_ChartManager.selected_value, "key1": key1, "key2": key2, "key3": key3})
  
  $.ajax({
    type : 'POST',
    url : url,
    dataType : 'json',
    success : on_data_load,
    error : on_data_load_error,
    data : body,
    async : false,
    processData: false
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
  g_ChartManager.push('data/flare.json', g_ChartManager.TYPE_TREEMAP2);
  g_ChartManager.update_value('disk_rwbytes', 'File System R+W bytes');
});
