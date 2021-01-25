#include "common_logger.h"
#include "container_manager.h"
#include "draios.pb.h"

COMMON_LOGGER();

using namespace agentone;

container::container(const std::string& id,
                     const std::string& name,
                     const std::string& image,
                     const std::map<std::string, std::string>& labels)
    : m_id(id),
      m_name(name),
      m_image(image),
      m_labels(labels),
      m_existence_ref(0)
{
}

const std::string& container::get_id() const
{
	return m_id;
}

const std::string& container::get_image() const
{
	return m_image;
}

const std::string& container::get_name() const
{
	return m_name;
}

const std::map<std::string, std::string>& container::get_labels() const
{
	return m_labels;
}

void container::ref()
{
	m_existence_ref++;
}

void container::deref()
{
	m_existence_ref--;
}

uint32_t container::get_ref() const
{
	return m_existence_ref;
}

container_manager::container_manager() {}

void container_manager::build_container(const std::string& id,
                                        const std::string& name,
                                        const std::string& image,
                                        const std::map<std::string, std::string>& labels)
{
	std::lock_guard<std::mutex> lock(m_container_list_lock);
	auto extant_container = m_containers.find(id);
	if (extant_container != m_containers.end())
	{
		extant_container->second->ref();
		return;
	}

	m_containers.insert(std::pair<std::string, std::shared_ptr<container>>(
	    id,
	    std::move(std::make_shared<container>(id, name, image, labels))));
	extant_container = m_containers.find(id);
	extant_container->second->ref();
}

void container_manager::remove_container(const std::string& id)
{
	std::lock_guard<std::mutex> lock(m_container_list_lock);
	auto extant_container = m_containers.find(id);

	// This should not happen
	if (extant_container == m_containers.end())
	{
		LOG_WARNING("Container %s removed but does not exist.", id.c_str());
		return;
	}

	extant_container->second->deref();
	if (extant_container->second->get_ref() == 0)
	{
		m_containers.erase(extant_container);
	}
}

std::map<std::string, std::shared_ptr<container>> container_manager::get_container_list() const
{
	std::lock_guard<std::mutex> lock(m_container_list_lock);
	return m_containers;
}

const std::shared_ptr<container> container_manager::get_container(const std::string& id) const
{
	std::lock_guard<std::mutex> lock(m_container_list_lock);
	auto c = m_containers.find(id);
	if (c != m_containers.end())
	{
		return c->second;
	}

	return nullptr;
}

// For reasons, template specializations must explicitly be in the right namespace
namespace agentone
{
template<>
void container_serializer<draiosproto::metrics>::serialize(const container_manager& cm,
                                                           draiosproto::metrics& message)
{
	auto containers = cm.get_container_list();

	for (auto& i : containers)
	{
		draiosproto::container* c = message.add_containers();
		c->set_id(i.second->get_id());
		c->set_name(i.second->get_name());
		c->set_image(i.second->get_image());
		for (auto& j : i.second->get_labels())
		{
			auto label = c->add_labels();
			label->set_key(j.first);
			label->set_value(j.second);
		}
	}
}

}  // namespace agentone
