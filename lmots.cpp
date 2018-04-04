#include"lmots.h"

//Verify LMOTS function
//DESCRIPTIONS: verify pub_key
//TAKE:
//		a - array pub_key
//		message -  text 
//RETURN res - cmp pub_key and tmp_pub_key
int VerifyPublickKey(uint8_t a[], uint8_t message[])
{
	int res = 0;
	PublicKeyFromSignatureGet(message);
	if (memcmp(a, param->pubKeyLMOTSGet, 32) == 0)
	{
		res = 1;
	}
	return res;
}

//SigToPubLmost  LMOTS function
//DESCRIPTIONS: get pub_key from signature and message
//TAKE:		
//		message -  text 
//RETURN void

void PublicKeyFromSignatureGet(uint8_t message[])
{
	
	uint8_t destinyArray[MessageLen + 67] = { 0 };
	uint8_t mesHash[512 / 4] = { 0 };
	uint8_t V[64] = { 0 };
	uint8_t chk[2] = { 0 };
	int pointResault = 0;
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, message, MessageLen);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->C, 32);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->I, 31);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->q, 4);
	KupynaHash(&param->ctx, destinyArray, MessageLen + 67, mesHash);
	CheckSum(mesHash, chk);
	memcpy(V, mesHash, 32 * sizeof(unsigned char));
	memcpy(V + 32 * sizeof(unsigned char), chk, 2 * sizeof(unsigned char));
	uint8_t tmp[32] = { 0 };
	uint8_t tmpHashValue[512 / 4];
	uint8_t result[1123] = { 0 };
	uint8_t cosvHash[69] = { 0 };
	int mainPointLen = 0;
	mainPointLen = ByteConcatTwoArrays(result, mainPointLen, param->I, 31);
	mainPointLen = ByteConcatTwoArrays(result, mainPointLen, param->q, 4);
	for (int i = 0; i < 34; i++)
	{
		memcpy(tmp, param->pk[i].y, 32 * sizeof(unsigned char));
		memset(cosvHash, 0, 69);
		for (int j = V[i]; j < 256; j++)
		{
			memcpy(cosvHash, tmp, 32 * sizeof(unsigned char));
			memcpy(cosvHash + 32 * sizeof(unsigned char), param->I, 31 * sizeof(unsigned char));
			memcpy(cosvHash + 63 * sizeof(unsigned char), param->q, 4 * sizeof(unsigned char));
			cosvHash[67] = uint16ToString(i);
			cosvHash[68] = uint8ToString(j);
			KupynaHash(&param->ctx, cosvHash, 69, tmpHashValue);
			memcpy(tmp, tmpHashValue, 32 * sizeof(unsigned char));
		}
		mainPointLen = ByteConcatTwoArrays(result, mainPointLen, tmp, 32);
	}
	KupynaHash(&param->ctx, result, 1123, param->pubKeyLMOTSGet);
}

//SignatureLmosts  LMOTS function
//DESCRIPTIONS: generate signature from message
//TAKE:		
//		message -  text 
//RETURN void
void SignatureGenerate(uint8_t message[])
{

	uint8_t destinyArray[MessageLen + 67] = { 0 };
	uint8_t mesHashValue[512 / 4] = { 0 };
	uint8_t V[64] = { 0 };
	uint8_t chk[2] = { 0 };
	int pointResault = 0;
	for (int i = 0; i < 32; i++)
	{
		int t = (41 + rand() % (125 - 41));
		param->C[i] = t;
	}
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, message, MessageLen);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->C, 32);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->I, 31);
	pointResault = ByteConcatTwoArrays(destinyArray, pointResault, param->q, 4);
	KupynaHash(&param->ctx, destinyArray, MessageLen + 67, mesHashValue);
	CheckSum(mesHashValue, chk);
	memcpy(V, mesHashValue, 32 * sizeof(unsigned char));
	memcpy(V + 32 * sizeof(unsigned char), chk, 2 * sizeof(unsigned char));
	uint8_t tmp[32] = { 0 };
	uint8_t tmpHashValue[512 / 4];
	uint8_t cosvHash[69] = { 0 };
	for (int i = 0; i < 34; i++)
	{
		memcpy(tmp, param->sk[i].x, 32 * sizeof(unsigned char));
		memset(cosvHash, 0, 69);
		for (int j = 0; j < V[i]; j++)
		{
			memcpy(cosvHash, tmp, 32 * sizeof(unsigned char));
			memcpy(cosvHash + 32 * sizeof(unsigned char), param->I, 31 * sizeof(unsigned char));
			memcpy(cosvHash + 63 * sizeof(unsigned char), param->q, 4 * sizeof(unsigned char));
			cosvHash[67] = uint16ToString(i);
			cosvHash[68] = uint8ToString(j);
			KupynaHash(&param->ctx, cosvHash, 69, tmpHashValue);
			memcpy(tmp, tmpHashValue, 32 * sizeof(unsigned char));
		}
		memcpy(param->pk[i].y, tmp, 32 * sizeof(unsigned char));
	}
}
//CheckSum  LMOTS function
//DESCRIPTIONS: computer checksum
//TAKE:		
//		a- hash message 
//		chk - checksum value  
//RETURN void

void CheckSum(uint8_t a[], uint8_t chk[])
{
	int sum = 0;
	for (int i = 0; i < 32; i++)
	{
		sum += (unsigned char)a[i];
	}
	chk[0] = (unsigned char)(sum >> 8);
	chk[1] = (unsigned char)(sum & 0xff);
}

//CheckSum  LMOTS function
//DESCRIPTIONS: generate private key
//TAKE:				 
//RETURN void
void PrivateKeyGenerate()
{
	for (int i = 0; i < 34; i++)
	{
		for (int j = 0; j < 32; j++)
		{
			param->sk[i].x[j] = 41 + rand() % (125 - 41);
		}
	}
}
//CheckSum  LMOTS function
//DESCRIPTIONS: generate public key from private key
//TAKE:				 
//RETURN void
void PublickKeyGenerate()
{

	uint8_t destinyArray[1123];
	uint8_t tmpHashValue[512 / 8] = { 0 };	
	int mainPointLen = 0;
	int cosvPointLen = 0;
	mainPointLen = ByteConcatTwoArrays(destinyArray, mainPointLen, param->I, 31);
	mainPointLen = ByteConcatTwoArrays(destinyArray, mainPointLen, param->q, 4);
	uint8_t tmp[32] = { 0 };
	uint8_t cosvHash[69] = { 0 };
	for (int i = 0; i < 34; i++)
	{
		memcpy(tmp, param->sk[i].x, 32 * sizeof(unsigned char));	
		memset(cosvHash, 0, 69);
		cosvPointLen = 0;
		for (int j = 0; j < 256; j++)
		{
			memcpy(cosvHash, tmp, 32 * sizeof(unsigned char));
			memcpy(cosvHash + 32 * sizeof(unsigned char), param->I, 31 * sizeof(unsigned char));
			memcpy(cosvHash + 63 * sizeof(unsigned char), param->q, 4 * sizeof(unsigned char));
			cosvHash[67] = uint16ToString(i);
			cosvHash[68] = uint8ToString(j);
			KupynaHash(&param->ctx, cosvHash, 69, tmpHashValue);
			memcpy(tmp, tmpHashValue, 32 * sizeof(unsigned char));
		}
		mainPointLen = ByteConcatTwoArrays(destinyArray, mainPointLen, tmp, 32);
	}
	KupynaHash(&param->ctx, destinyArray, 1123, param->pubKeyLMOTS);

}
// ByteConcat  LMOTS function
//DESCRIPTIONS: concatenate arrays
//TAKE:				 
//	destinyArray - first array
//	posIndex - old index 
//	secondArray	- second array
//	secondArrayLen - lenght second array
//
//RETURN tmp - new index
int ByteConcatTwoArrays(uint8_t destinyArray[], int posIndex, uint8_t secondArray[], int secondArrayLen)
{
	int tmp = (posIndex + secondArrayLen)*sizeof(unsigned char);
	memcpy(destinyArray + posIndex*sizeof(unsigned char), secondArray, secondArrayLen*sizeof(unsigned char));
	return tmp;
}

//uint16ToString  LMOTS function
//DESCRIPTIONS: conver uint16 to string
//TAKE:				 
//	x - uint16
//
//RETURN 
unsigned char uint16ToString(int x) 
{
	int c2 = Chr(x & 0xff);
	x = x >> 8;
	int 	c1 = Chr(x & 0xff);
	return c1 + c2;
}
//uint8ToString  LMOTS function
//DESCRIPTIONS: conver uint8 to string
//TAKE:				 
//	x - uint8
//
//RETURN 
unsigned char uint8ToString(int x)
{
	return Chr(x);
}
//uint16ToString  LMOTS function
//DESCRIPTIONS: conver uint16 to string
//TAKE:				 
//	x - uint16
//
//RETURN 
unsigned char Chr(int x)
{
	return (unsigned char)x;//warning overflow!!!
}