//#include "tables.h"
#include"lmots.h"



void print(int data_len, uint8_t data[]);

clock_t skNowTime, skEndTime;
clock_t pkNowTime, pkEndTime;
clock_t sigNowTime, sigEndTime;
clock_t verNowTime, verEndTime;

int main()
{	
	KupynaInit(256, &param->ctx);

	for (int i = 0;i < 4; i++)
	{
		param->q[i] = 0x00;
	}
	char message[] = "The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.";

	for (int i = 0; i < 31; i++)
	{
		int t = (41 + rand() % (125 - 41));
		param->I[i] = t;
	}
	skNowTime = time(NULL);
	PrivateKeyGenerate();
	skEndTime = time(NULL);
	for (int i = 0; i < 34; i++)
	{
		printf("x[%d]:\t", i);
		for (int j = 0; j < 32; j++)
		{
			printf("%02X", param->sk[i].x[j]);
		}
		printf("\n");
	}
	pkNowTime = time(NULL);
	PublickKeyGenerate();
	pkEndTime = time(NULL);
	printf("Public KEY:\n");
	print(256, param->pubKeyLMOTS);
	//
	uint8_t mes[MessageLen];
	for (int k = 0; k < MessageLen; k++)
	{
		uint8_t tmp = (uint8_t)message[k];//??
		mes[k] = tmp;
	}
	sigNowTime = time(NULL);
	//SignatureLmosts(mes);
	sigEndTime = time(NULL);

	//print signatyre
	printf("Signature\n");
	printf("C:\t");
	for (int j = 0; j < 32; j++)
	{
		printf("%02X", param->C[j]);
	}
	printf("\n");
	printf("I:\t");
	for (int j = 0; j < 32; j++)
	{
		printf("%02X", param->I[j]);
	}
	printf("\n");
	printf("q:\t");
	for (int j = 0; j < 4; j++)
	{
		printf("%02X", param->q[j]);
	}
	printf("\n");
	for (int i = 0; i < 34; i++)
	{
		printf("y[%d]:\t", i);
		for (int j = 0; j < 32; j++)
		{
			printf("%02X", param->pk[i].y[j]);
		}
		printf("\n");
	}


	verNowTime = time(NULL);
	if (VerifyPublickKey(param->pubKeyLMOTS, mes) == 1){
		printf("Signature is true\n");
	}
	else {
		printf("Signature is false\n");
	}
	verEndTime = time(NULL);
	char message1[] = "the right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no warrants shall issue, but upon probable cause, supported by oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized.";
	uint8_t mes1[MessageLen];
	for (int k = 0; k < MessageLen; k++)
	{
		uint8_t tmp = (uint8_t)message1[k];//??
		mes1[k] = tmp;
	}
	if (VerifyPublickKey(param->pubKeyLMOTS, mes1) == 1){
		printf("Signature is true");
	}
	else {
		printf("Signature is false");
	}
	printf("\n*********Statistic************\n");
	printf("Secret keys-\t %f s.\n", difftime(skEndTime, skNowTime));
	printf("Public key-\t %f s.\n", difftime(pkEndTime, pkNowTime));
	printf("Signature-\t %f s.\n", difftime(sigEndTime, sigNowTime));
	printf("Verify signature-\t %f s.\n", difftime(verEndTime, verNowTime));
	return 0;
}


void print(int data_len, uint8_t data[])
{
	int i = 0;
	int data_size = data_len / BITS_IN_BYTE;
	for (i = 0; i < data_size; i++)
	{
		if (!(i % 16)) printf("    ");
		printf("%02X", (unsigned int)data[i]);
		if (!((i + 1) % 16)) printf("\n");
	};
	if (data_len % BITS_IN_BYTE != 0)
	{
		if (!(i % 16)) printf("    ");
		printf("%02X", (unsigned int)((data[i]) & (~((1 << (BITS_IN_BYTE - (data_len % BITS_IN_BYTE))) - 1))));
		if (!((i + 1) % 16)) printf("\n");
	};
	printf("\n");
};

