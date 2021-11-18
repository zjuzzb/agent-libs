#include "dragent.h"

int main(int argc, char** argv)
{
	try
	{
		dragent_app app;
		return app.run(argc, argv);
	}
	catch(const Poco::Exception& e)
	{
		std::cerr <<  e.displayText() << std::endl;
		throw;
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		throw;
	}
}
