#pragma once
#include "main.h"

struct IPRouteNode
{
	DWORD destIP;
	DWORD mask;
	DWORD nextHop;
};

class IPRouter
{
public:
	IPRouter();
	~IPRouter();

	DWORD localIP;

	std::list<IPRouteNode> routeTable;

};

