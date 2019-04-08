#pragma once

#include <dirent.h>

class scoped_dir
{
public:
        scoped_dir(const std::string& filename) :
                m_directory(opendir(filename.c_str()))
        {
        }

        ~scoped_dir()
        {
                if (m_directory != nullptr)
                {
                        closedir(m_directory);
                }
        }

        DIR* const m_directory;
};

