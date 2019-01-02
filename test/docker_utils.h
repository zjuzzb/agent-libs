#pragma once

bool dutils_check_docker();
void dutils_create_tag(const char *tag, const char *image);
void dutils_kill_container(const char *name);
void dutils_kill_image(const char *image);
