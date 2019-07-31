#include "webpage.h"

namespace {

namespace viewer_from_url
{
	std::string generate(const std::string &name,
				    const std::string &url,
				    const std::string &load_type)
	{

		std::string link = "<li style=\"margin: 0 0 10px;padding: 0;list-style: none;font-size: 12px;font-weight: 500;text-transform: uppercase;letter-spacing: 1px;\">"
				   "<a style=\"text-decoration: none;\" class=" + load_type + " val=\"" + url + "\" href=\"#\">";
		link += name;
		link += "</a></li>";
		return link;
	}

	std::string json_loader(const std::string& name,
				       const std::string& url)
	{
		return generate(name, url, "load_json");
	}

	std::string text_loader(const std::string& name,
				       const std::string& url)
	{
		return generate(name, url, "load_text");
	}
};

namespace menu_bar
{
	std::string generate()
	{
		std::string menu;
		menu += "<div id=\"navbar\" style=\"font-family:quicksand,Arial,sans-serif;float:left;width:300px;height:100%;background-color:f2f3f7;text-align:center;\">"
				"<div style=\"padding:40px\">Sysdig Agent</div>"
				"<ul style=\"padding:0px\">";

		menu += viewer_from_url::json_loader("metrics", "/api/protobuf/metrics");
		menu += viewer_from_url::text_loader("dragent config", "/api/file/dragent.yaml");

		menu += "</ul>";
		menu += "</div>";
		menu += "<div style=\"float:left;width:10px;height:100%\"/>";

		return menu;
	}
};

namespace viewer
{
	std::string generate()
	{
		return "<div style=\"float:left;padding:20px;font-family:courier;width:900;white-space:pre-wrap;\" id=\"viewer\"></div>";
	}
};

}

namespace dragent
{

namespace webpage
{

std::string generate()
{
	std::string page;

	page += "<html>"
		"<head>"
		"<title>Sysdig Agent</title>"
		// jquery_min should be copied onto the agent and served via the
		// file api
		"<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js\"></script>";

	page += "<script type=\"text/javascript\">";


	// Add the jquery to grab the data and update the fields
	page += R"(
$(document).ready(function(){
	$(".load_json").click(function(){
		$.get($(this).attr('val'), function(data, status){
			$("#viewer").text(JSON.stringify(data, undefined, 2));
		});
	});
	$(".load_text").click(function(){
		$.get($(this).attr('val'), function(data, status){
			$("#viewer").text(data);
		});
	});
});
		)";

	page += "</script>";
	page += "<body style=\"margin:0px\">";
	page += menu_bar::generate();
	page += viewer::generate();
	page += "</body></html>";
	return page;
}

} // namespace webpage

} // namespace dragent


