#include <stdio.h>

class Trigger
{
public:
	Trigger() {}
	void Init () {}
	void Raise() {}
	void Lower() {}
};

class StdOutTrigger: public Trigger
{
public:
	void Raise();
	void Lower();
};

extern Trigger* trigger;
