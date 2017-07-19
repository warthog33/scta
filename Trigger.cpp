#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "Trigger.h"

void StdOutTrigger::Raise()
{
	printf ( "Trigger Raised\n" );
}
void StdOutTrigger::Lower()
{
	printf ( "Trigger Lowered\n" );
}


static unsigned* pinconf1; 
#define OE_ADDR 0x134
#define GPIO_DATAOUT 0x13C
#define GPIO_DATAIN 0x138
#define GPIO0_ADDR 0x44E07000
#define GPIO1_ADDR 0x4804C000
#define GPIO2_ADDR 0x481AC000
#define GPIO3_ADDR 0x481AF000

void BeagleBoneTrigger::Init()
{
 	int fd = open("/dev/mem",O_RDWR | O_SYNC);

	if ( fd <= 0 )
	{
		printf ( "Unable to open /dev/mem, aborting\n" );
		exit(0);
	}
        pinconf1 = (unsigned *) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, GPIO1_ADDR);

        //set all pins to inputs, except pin 28
        pinconf1[OE_ADDR/4] &= (0xFFFFFFFF ^ (1<<28));
}


void BeagleBoneTrigger::Raise(){
        pinconf1[GPIO_DATAOUT/4] |= (1<<28);
        //sleep(1);
}

void BeagleBoneTrigger::Lower(){
        pinconf1[GPIO_DATAOUT/4] ^= (1<<28);
        //sleep(1);
}
