#include <stdio.h>
#include <stdlib.h>


void find_initial_rate_window(int *array, double bw, int time)
{
	
	//int throughput = 0;
	//int delay = 0;
	int rate = 0;
	int window = 0;
	int downlink = 0;
	int whichfile = 0;
	int bw_level = (int)bw;
	char filename[3][1000] = {"./2s_rate_maxThput.txt", "./2s_rate_maxThput.txt", "./2s_rate_maxThput.txt"};

	char line[1000];
	
	if (time == 2)
		whichfile = 0;
	else if (time == 10)
		whichfile = 1;
	else if (time == 120)
		whichfile = 2;
	else {
		printf("please input right time parameter!\n");
		exit(-1);
	}

	FILE *onlyread = fopen(filename[whichfile],"r");

	if (onlyread == NULL) {
		printf("File not open!\n");
		exit(-1);
	}
	
	while (fgets(line, 1000, onlyread) != NULL) {
		sscanf(line, "%d %d %d", &downlink, &rate, &window);
		if (downlink/100000 == bw_level) {
			array[0] = rate;
			array[1] = window;
		}
	}

	fclose(onlyread);

}

int main()
{
	double bw = 7.3;
	int time = 2;
	int array[2] = {0, 0};
	//time is session period
	find_initial_rate_window(array, bw, time);
	printf("rate = %d window = %d\n", array[0], array[1]);

	return 0;
}
