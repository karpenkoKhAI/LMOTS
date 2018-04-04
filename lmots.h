#include<stdio.h>
#include<memory.h>
#include<time.h>
#include"kupyna.h"



#define MessageLen 333


//struct 
struct PrivetKey
{
	unsigned char x[32];
};
struct PublKey
{
	unsigned char y[32];

};
typedef struct 
{
	kupyna_t ctx;
	struct PublKey pk[34];
	struct PrivetKey sk[34];
	uint8_t I[31];
	uint8_t C[32];	
	uint8_t q[4];
	uint8_t pubKeyLMOTS[512 / 8];
	uint8_t	pubKeyLMOTSGet[512 / 8]; 
}Parameters;

Parameters* param;

int VerifyPublickKey(
			uint8_t a[],
			uint8_t message[]);

void PublicKeyFromSignatureGet(
			uint8_t message[]);

void SignatureGenerate(
			uint8_t message[]);

void CheckSum(
		uint8_t a[],
		uint8_t chk[]);

void PrivateKeyGenerate();

void PublickKeyGenerate();

int ByteConcatTwoArrays(
			uint8_t mainHash[],
			int aOldLen,
			uint8_t b[],
			int bLenArray);

unsigned char uint16ToString(int x);

unsigned char uint8ToString(int x);

unsigned char Chr(int x);