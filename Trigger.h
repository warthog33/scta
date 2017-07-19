#include <stdio.h>

class Trigger
{
public:
	Trigger() {}
	virtual void Init () {}
	virtual void Raise() {}
	virtual void Lower() {}
};

class StdOutTrigger: public Trigger
{
public:
	void Raise();
	void Lower();
};

class BeagleBoneTrigger: public Trigger
{
public:
	void Init();
	void Raise();
	void Lower();
};
class SysGpioTrigger: public Trigger
{
public:
	SysGpioTrigger();
	void Raise();
	void Lower();
private:
	int valuefd;
};
extern Trigger* trigger;
