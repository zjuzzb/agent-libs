#include <gtest.h>
#include <command_line_manager.h>
#include <command_line_error.h>

TEST(command_line_manager_test, get_commands_json)
{
	command_line_manager mgr;
	{
		command_line_manager::command_info cmd;
		cmd.description = "milk the cow";
		cmd.handler = [](const command_line_manager::argument_list &args) { return "moo";};
		mgr.register_command("barn cow milk", cmd);
	}
	{	
		command_line_manager::command_info cmd;
		cmd.description = "pet the dog";
		cmd.handler = [](const command_line_manager::argument_list &args) { return "woof";};
		mgr.register_command("barn dog pet", cmd);
	}
	mgr.register_folder("goat", "goats are mostly nice but they do have horns");
	{
		command_line_manager::command_info cmd;
		cmd.description = "throw the dog's stick";
		cmd.long_description = "Stick throwing is an ancient custom passed down from olden times where wolves would return bones to enhance the soup of early humans.";
		cmd.handler = [](const command_line_manager::argument_list &args) { return "bark bark bark";};
		mgr.register_command("barn dog throw-stick", cmd);
	}
	{
		command_line_manager::command_info cmd;
		cmd.description = "milk the goat";
		cmd.handler = [](const command_line_manager::argument_list &args) { return "<goat noise>";};
		mgr.register_command("goat milk", cmd);
	}
	{
		command_line_manager::command_info cmd;
		cmd.description = "red rum";
		cmd.handler = [](const command_line_manager::argument_list &args) { return "eww";};
		mgr.register_command("slaughter", cmd);
	}

	mgr.register_folder("barn", "red building where some animals are kept");


	std::string expected = 
R"({
   "commands" : {
      "barn" : {
         "description" : "red building where some animals are kept",
         "subs" : {
            "cow" : {
               "subs" : {
                  "milk" : {
                     "description" : "milk the cow"
                  }
               }
            },
            "dog" : {
               "subs" : {
                  "pet" : {
                     "description" : "pet the dog"
                  },
                  "throw-stick" : {
                     "description" : "throw the dog's stick",
                     "long_description" : "Stick throwing is an ancient custom passed down from olden times where wolves would return bones to enhance the soup of early humans."
                  }
               }
            }
         }
      },
      "goat" : {
         "description" : "goats are mostly nice but they do have horns",
         "subs" : {
            "milk" : {
               "description" : "milk the goat"
            }
         }
      },
      "slaughter" : {
         "description" : "red rum"
      }
   }
}
)";

	ASSERT_EQ(expected, mgr.commands_json());
}

TEST(command_line_manager_test, simple_command)
{
	command_line_manager::command_info cmd1;
	cmd1.description = "tell me hello";
	cmd1.handler = [](const command_line_manager::argument_list &args) { return "hello";};

	command_line_manager mgr;
	mgr.register_command("greeting", cmd1);

	ASSERT_EQ("hello", mgr.handle("greeting").second);
}

TEST(command_line_manager_test, single_arg_with_value)
{
	// Functions using GTest Assertions have to return void, so create an
	// extra lamba for that purpose
	auto check_args = [](const command_line_manager::argument_list &args)
	{
		ASSERT_EQ(1, args.size());
		ASSERT_STREQ("color", args[0].first.c_str());
		ASSERT_STREQ("red", args[0].second.c_str());
	};

	command_line_manager::command_info cmd1;
	cmd1.handler = [&check_args](const command_line_manager::argument_list &args)  -> std::string
	{
		check_args(args);
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("response", mgr.handle("command -color red").second);
	ASSERT_EQ("response", mgr.handle("command   -color   red  ").second);
}

TEST(command_line_manager_test, single_arg_without_value)
{
	// Functions using GTest Assertions have to return void, so create an
	// extra lamba for that purpose
	auto check_args = [](const command_line_manager::argument_list &args)
	{
		ASSERT_EQ(1, args.size());
		ASSERT_STREQ("on", args[0].first.c_str());
		ASSERT_TRUE(args[0].second.empty());
	};

	command_line_manager::command_info cmd1;
	cmd1.handler = [&check_args](const command_line_manager::argument_list &args)  -> std::string
	{
		check_args(args);
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("response", mgr.handle("command -on").second);
	ASSERT_EQ("response", mgr.handle("  command   -on  ").second);
}

TEST(command_line_manager_test, multiple_args)
{
	// Functions using GTest Assertions have to return void, so create an
	// extra lamba for that purpose
	auto check_args = [](const command_line_manager::argument_list &args)
	{
		ASSERT_EQ(3, args.size());
		ASSERT_STREQ("now", args[0].first.c_str());
		ASSERT_TRUE(args[0].second.empty());
		ASSERT_STREQ("item", args[1].first.c_str());
		ASSERT_STREQ("steak", args[1].second.c_str());
		ASSERT_STREQ("done-ness", args[2].first.c_str());
		ASSERT_STREQ("medium-well", args[2].second.c_str());
	};

	command_line_manager::command_info cmd1;
	cmd1.handler = [&check_args](const command_line_manager::argument_list &args)  -> std::string
	{
		check_args(args);
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("response", mgr.handle("command -now -item steak -done-ness medium-well").second);
}

TEST(command_line_manager_test, double_dash)
{
	command_line_manager::command_info cmd1;
	cmd1.handler = [](const command_line_manager::argument_list &args)
	{
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("Error: There should not be a double dash at position 9.", 
		  mgr.handle("command --").second);
}

TEST(command_line_manager_test, space_before_argument_name)
{
	command_line_manager::command_info cmd1;
	cmd1.handler = [](const command_line_manager::argument_list &args)
	{
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("Error: There should not be a space between the dash and argument name at position 11.", 
		  mgr.handle("command   - woot").second);
}

TEST(command_line_manager_test, end_with_dash)
{
	command_line_manager::command_info cmd1;
	cmd1.handler = [](const command_line_manager::argument_list &args)
	{
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("Error: Argument list should not end with a dash.", 
		  mgr.handle("command -woot -").second);
}

TEST(command_line_manager_test, space_in_value)
{
	command_line_manager::command_info cmd1;
	cmd1.handler = [](const command_line_manager::argument_list &args)
	{
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("Error: Expected dash in argument list at position 17.", 
		  mgr.handle("command -foo bar bar").second);
}

TEST(command_line_manager_test, quotes_for_spaces)
{
	command_line_manager::command_info cmd1;
	cmd1.handler = [](const command_line_manager::argument_list &args)
	{
		return "response";
	};

	command_line_manager mgr;
	mgr.register_command("command", cmd1);

	ASSERT_EQ("Error: Quotes aren't supported in argument values at position 13.", 
		  mgr.handle("command -foo \"bar bar\"").second);
}

TEST(command_line_manager_test, unrecognized_command)
{
	command_line_manager mgr;
	ASSERT_EQ("Error: Unrecognized command.", 
		  mgr.handle("command").second);
}

TEST(command_line_manager_test, content_type)
{

	command_line_manager::command_info cmd1;
	cmd1.description = "tell me hello";
	cmd1.type = command_line_manager::content_type::JSON;
	cmd1.handler = [](const command_line_manager::argument_list &args) { return "hello";};

	command_line_manager mgr;
	mgr.register_command("greeting", cmd1);

	auto result = mgr.handle("greeting");

	ASSERT_EQ(command_line_manager::content_type::JSON, result.first);
	ASSERT_EQ("hello", result.second);
}

TEST(command_line_manager_test, throw_error)
{

	command_line_manager::command_info cmd1;
	cmd1.description = "tell me hello";
	cmd1.type = command_line_manager::content_type::JSON;
	cmd1.handler = [](const command_line_manager::argument_list &args) { throw command_line_error("there is a problem"); return "";};

	command_line_manager mgr;
	mgr.register_command("greeting", cmd1);

	auto result = mgr.handle("greeting");

	ASSERT_EQ(command_line_manager::content_type::ERROR, result.first);
	ASSERT_EQ("Error: there is a problem", result.second);
}


