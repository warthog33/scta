#include <stdio.h>

class Trigger
{
public:
	Trigger()
	{
		printf ( "Initialising trigger\n" );
	}
	void Raise()
	{
		printf ( "Trigger.Raise() called\n" );
	}
	void Lower()
	{
		printf ( "Trigger.Lower() called\n" );
	}
};

extern Trigger trigger;
