/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server.

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"
#include "../isv_enclave/definitions.h" //structs, enums, fixed constants

#ifdef DEBUG
#define DBGprint(...) printf(__VA_ARGS__)
#else
#define DBGprint(...)
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     \
	{                      \
		if (NULL != (ptr)) \
		{                  \
			free(ptr);     \
			(ptr) = NULL;  \
		}                  \
	}
#endif
int rankingsLength = 0, uservisitsLength = 0;
// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"

#define ENCLAVE_FILENAME "isv_enclave.signed.so"
# define TOKEN_FILENAME   "enclave.token"
//use these to keep track of all the structures and their types (added by me, not part of sample code)
int oblivStructureSizes[NUM_STRUCTURES] = {0};
int oblivStructureTypes[NUM_STRUCTURES] = {0};
uint8_t *oblivStructures[NUM_STRUCTURES] = {0}; //hold pointers to start of each oblivious data structure
FILE *readFile = NULL;

uint8_t *msg1_samples[] = {msg1_sample1, msg1_sample2};
uint8_t *msg2_samples[] = {msg2_sample1, msg2_sample2};
uint8_t *msg3_samples[MSG3_BODY_SIZE] = {msg3_sample1, msg3_sample2};
uint8_t *attestation_msg_samples[] =
	{attestation_msg_sample1, attestation_msg_sample2};

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
	FILE *file, void *mem, uint32_t len)
{
	if (!mem || !len)
	{
		fprintf(file, "\n( null %d %d)\n", mem, len);
		return;
	}
	uint8_t *array = (uint8_t *)mem;
	fprintf(file, "%u bytes:\n{\n", len);
	uint32_t i = 0;
	for (i = 0; i < len - 1; i++)
	{
		fprintf(file, "0x%x, ", array[i]);
		if (i % 8 == 7)
			fprintf(file, "\n");
	}
	fprintf(file, "0x%x ", array[i]);
	fprintf(file, "\n}\n");
}

void PRINT_ATTESTATION_SERVICE_RESPONSE(
	FILE *file,
	ra_samp_response_header_t *response)
{
	if (!response)
	{
		fprintf(file, "\t\n( null )\n");
		return;
	}

	fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
	fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
			response->status[1]);
	fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

	if (response->type == TYPE_RA_MSG2)
	{
		sgx_ra_msg2_t *p_msg2_body = (sgx_ra_msg2_t *)(response->body);

		/*
        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
        */
	}
	else if (response->type == TYPE_RA_ATT_RESULT)
	{
		sample_ra_att_result_msg_t *p_att_result =
			(sample_ra_att_result_msg_t *)(response->body);
		/*
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
        */
	}
	else
	{
		fprintf(file, "\nERROR in printing out the response. "
					  "Response of type not supported %d\n",
				response->type);
	}
}

/*
 * Begin Saba's Code
 * OCALLS GO HERE
 *
 * */

void ocall_print(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
	printf("%s", str);
	fflush(stdout);
}

void ocall_read_block(int structureId, int index, int blockSize, void *buffer)
{ //read in to buffer
	if (blockSize == 0)
	{
		printf("unkown oblivious data type\n");
		return;
	} //printf("heer\n");fflush(stdout);
	//printf("index: %d, blockSize: %d structureId: %d\n", index, blockSize, structureId);
	//printf("start %d, addr: %d, expGap: %d\n", oblivStructures[structureId], oblivStructures[structureId]+index*blockSize, index*blockSize);fflush(stdout);
	memcpy(buffer, oblivStructures[structureId] + ((long)index * blockSize), blockSize); //printf("heer\n");fflush(stdout);
																						 //printf("beginning of mac(app)? %d\n", ((Encrypted_Linear_Scan_Block*)(oblivStructures[structureId]+(index*encBlockSize)))->macTag[0]);
																						 //printf("beginning of mac(buf)? %d\n", ((Encrypted_Linear_Scan_Block*)(buffer))->macTag[0]);
}
void ocall_write_block(int structureId, int index, int blockSize, void *buffer)
{ //write out from buffer
	if (blockSize == 0)
	{
		printf("unkown oblivious data type\n");
		return;
	}
	//printf("data: %d %d %d %d\n", structureId, index, blockSize, ((int*)buffer)[0]);fflush(stdout);
	//printf("data: %d %d %d\n", structureId, index, blockSize);fflush(stdout);

	/*if(structureId == 3 && blockSize > 1) {
		blockSize = 8000000;//temp
		printf("in structure 3");fflush(stdout);
	}*/
	//printf("here! blocksize %d, index %d, structureId %d\n", blockSize, index, structureId);
	memcpy(oblivStructures[structureId] + ((long)index * blockSize), buffer, blockSize);
	//printf("here2\n");
	//debug code
	//printf("pointer 1 %p, pointer 2 %p, difference %d\n", oblivStructures[structureId], oblivStructures[structureId]+(index*encBlockSize), (index*encBlockSize));
	//printf("beginning of mac? %d\n", ((Encrypted_Linear_Scan_Block*)(oblivStructures[structureId]+(index*encBlockSize)))->macTag[0]);
}

void ocall_respond(uint8_t *message, size_t message_size, uint8_t *gcm_mac)
{
	printf("ocall response\n");
}

void ocall_newStructure(int newId, Obliv_Type type, int size)
{ //this is actual size, the logical size will be smaller for orams
	//printf("app: initializing structure type %d of capacity %d blocks\n", type, size);
	int encBlockSize = getEncBlockSize(type);
	if (type == TYPE_ORAM || type == TYPE_TREE_ORAM)
		encBlockSize = sizeof(Encrypted_Oram_Bucket);
	printf("Encrypted blocks of this type get %d bytes of storage\n", encBlockSize);
	oblivStructureSizes[newId] = size;
	oblivStructureTypes[newId] = type;
	long val = (long)encBlockSize * size;
	printf("mallocing %ld bytes\n", val);
	oblivStructures[newId] = (uint8_t *)malloc(val);
	if (!oblivStructures[newId])
	{
		printf("failed to allocate space (%ld bytes) for structure\n", val);
		fflush(stdout);
	}
}

void ocall_deleteStructure(int structureId)
{

	oblivStructureSizes[structureId] = 0;
	oblivStructureTypes[structureId] = 0;
	free(oblivStructures[structureId]); //hold pointers to start of each oblivious data structure
}

void ocall_open_read(int tableSize)
{
	char tableName[20];
	sprintf(tableName, "testTable%d", tableSize);
	//printf("table's name is %s\n", tableName);fflush(stdout);
	readFile = fopen((char *)tableName, "r");
	//printf("here a function is called\n");fflush(stdout);
}

void ocall_make_name(void *name, int tableSize)
{
	sprintf((char *)name, "testTable%d", tableSize);
}

void ocall_write_file(const void *src, int dsize, int tableSize)
{
	char tableName[20];
	sprintf(tableName, "testTable%d", tableSize);
	//int t = 0;
	//memcpy(&t, src, 4);
	//printf("ocall writing %d to a file with %d bytes\n", t, dsize);fflush(stdout);
	FILE *outFile = fopen((char *)tableName, "a");
	fwrite(src, dsize, 1, outFile);
	fclose(outFile);
}

void ocall_read_file(void *dest, int dsize)
{
	if (readFile == NULL)
		printf("bad!!\n");
	//printf("b %d\n", dsize);
	int c = fread(dest, dsize, 1, readFile);
	//printf("c %d %d %d\n", c, ferror(readFile), feof(readFile));
	int t = 0;
	memcpy(&t, dest, 4);
	//printf("this funciton prints %d with %d bytes\n", t, dsize);
}


void LoadTables(sgx_enclave_id_t enclave_id, int status, char *rankingsFileName, int rankingsLength, char *uservisitsFileName, int uservisitsLength)
{
    //block size 512
    //I have include all table initialization in this function. rankings.csv need BLOCK_DATA_SIZE = 512, uservisits.csv needs BLOCK_DATA_SIZE=2048.
    //In order to support them together, I simply set BLOCK_DATA_SIZE=2048. If we set different BLOCK_DATA_SIZE for different tables, there can be some performance gains
    // int rankingsLength = 5000000;   //rankings table
    // int uservisitsLength = 5000000; //uservisist table
    DBGprint("rankings schema init\n");

    uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	int structureId1 = -1;
	int structureId2 = -1;
	Schema rankingsSchema;
	rankingsSchema.numFields = 4;
	rankingsSchema.fieldOffsets[0] = 0;
	rankingsSchema.fieldSizes[0] = 1;
	rankingsSchema.fieldTypes[0] = CHAR;
	rankingsSchema.fieldOffsets[1] = 1;
	rankingsSchema.fieldSizes[1] = 255;
	rankingsSchema.fieldTypes[1] = TINYTEXT;
	rankingsSchema.fieldOffsets[2] = 256;
	rankingsSchema.fieldSizes[2] = 4;
	rankingsSchema.fieldTypes[2] = INTEGER;
	rankingsSchema.fieldOffsets[3] = 260;
	rankingsSchema.fieldSizes[3] = 4;
	rankingsSchema.fieldTypes[3] = INTEGER;

    char *tableName = "rankings";
	createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, rankingsLength, &structureId1); //TODO temp really 360010

    std::ifstream file(rankingsFileName);
    char line[BLOCK_DATA_SIZE]; //make this big just in case
    char data[BLOCK_DATA_SIZE];

    //loading rankings.csv file.
    if (file.is_open())
    {
        DBGprint("rankings opened\n");
        for (int i = 0; i < rankingsLength; i++)
        {
            memset(row, 0, BLOCK_DATA_SIZE);
            row[0] = 'a';
            file.getline(line, BLOCK_DATA_SIZE); //get the field
            std::istringstream ss(line);
            for (int j = 0; j < 3; j++)
            {
                if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
                {
                    break;
                }
                if (j == 1 || j == 2)
                { //integer
                    int d = 0;
                    d = atoi(data);
                    memcpy(&row[rankingsSchema.fieldOffsets[j + 1]], &d, 4);
                }
                else
                { //tinytext
                    strncpy((char *)&row[rankingsSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
                }
            }
            //manually insert into the linear scan structure for speed purposes
            opOneLinearScanBlock(enclave_id, (int *)&status, structureId1, i, (Linear_Scan_Block *)row, 1);
			incrementNumRows(enclave_id, (int *)&status, structureId1);
		}
        printf("created rankings table\n\n");
    }
    else
    {
        DBGprint("error open file %s\n", tableName);
    }

    Schema userdataSchema;
	userdataSchema.numFields = 10;
	userdataSchema.fieldOffsets[0] = 0;
	userdataSchema.fieldSizes[0] = 1;
	userdataSchema.fieldTypes[0] = CHAR;
	userdataSchema.fieldOffsets[1] = 1;
	userdataSchema.fieldSizes[1] = 255;
	userdataSchema.fieldTypes[1] = TINYTEXT;
	userdataSchema.fieldOffsets[2] = 256;
	userdataSchema.fieldSizes[2] = 255;
	userdataSchema.fieldTypes[2] = TINYTEXT;
	userdataSchema.fieldOffsets[3] = 511;
	userdataSchema.fieldSizes[3] = 4;
	userdataSchema.fieldTypes[3] = INTEGER;
	userdataSchema.fieldOffsets[4] = 515;
	userdataSchema.fieldSizes[4] = 4;
	userdataSchema.fieldTypes[4] = INTEGER;
	userdataSchema.fieldOffsets[5] = 519;
	userdataSchema.fieldSizes[5] = 255;
	userdataSchema.fieldTypes[5] = TINYTEXT;
	userdataSchema.fieldOffsets[6] = 774;
	userdataSchema.fieldSizes[6] = 255;
	userdataSchema.fieldTypes[6] = TINYTEXT;
	userdataSchema.fieldOffsets[7] = 1029;
	userdataSchema.fieldSizes[7] = 255;
	userdataSchema.fieldTypes[7] = TINYTEXT;
	userdataSchema.fieldOffsets[8] = 1284;
	userdataSchema.fieldSizes[8] = 255;
	userdataSchema.fieldTypes[8] = TINYTEXT;
	userdataSchema.fieldOffsets[9] = 1539;
	userdataSchema.fieldSizes[9] = 4;
	userdataSchema.fieldTypes[9] = INTEGER;

    char *tableName2 = "uservisits";
	createTable(enclave_id, (int *)&status, &userdataSchema, tableName2, strlen(tableName2), TYPE_LINEAR_SCAN, uservisitsLength, &structureId2); //TODO temp really 350010

    std::ifstream file2(uservisitsFileName);
    if (file2.is_open())
    {
        int counter = 0;
        DBGprint("uservisits opened\n");
        for (int i = 0; i < uservisitsLength; i++)
        {
            memset(row, 0, BLOCK_DATA_SIZE);
            row[0] = 'a';
            file2.getline(line, BLOCK_DATA_SIZE); //get the field
            //DBGprint("line : %s\n", line);
            std::istringstream ss(line);
            for (int j = 0; j < 9; j++)
            {
                if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
                {
                    //printf("ERROR: split line\n");
                    break;
                }
                //DBGprint("data : %s\n", data);
                if (j == 2 || j == 3 || j == 8)
                { //integer
                    int d = 0;
                    if (j == 3)
                        d = atof(data) * 100;
                    else if (j == 8)
                        d = atoi(data);
                    else
                    { //j == 2, parse the date 1990-01-01 to integer 19900101
                        std::string str_data(data);
                        int year = stoi(str_data.substr(0, 4));
                        int month = stoi(str_data.substr(5, 6));
                        int day = stoi(str_data.substr(8, 9));
                        //std::cout << str_data << " " << year << " " << month << " " <<day<< std::endl;
                        d = year * 10000 + month * 100 + day;
                    }

                    memcpy(&row[userdataSchema.fieldOffsets[j + 1]], &d, 4);
                }
                else
                { //tinytext
                    strncpy((char *)&row[userdataSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
                }
            }
            //DBGprint("\nrow : %s\n", row);
            //manually insert into the linear scan structure for speed purposes
            opOneLinearScanBlock(enclave_id, (int *)&status, structureId2, i, (Linear_Scan_Block *)row, 1);
			incrementNumRows(enclave_id, (int *)&status, structureId2);
		}

        printf("created uservisits table\n\n");
    }
    else
    {
        DBGprint("error open file %s\n", tableName2);
    }
}

void BDB1Index(sgx_enclave_id_t enclave_id, int status)
{
	//block size needs to be 512

	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema rankingsSchema;
	rankingsSchema.numFields = 4;
	rankingsSchema.fieldOffsets[0] = 0;
	rankingsSchema.fieldSizes[0] = 1;
	rankingsSchema.fieldTypes[0] = CHAR;
	rankingsSchema.fieldOffsets[1] = 1;
	rankingsSchema.fieldSizes[1] = 255;
	rankingsSchema.fieldTypes[1] = TINYTEXT;
	rankingsSchema.fieldOffsets[2] = 256;
	rankingsSchema.fieldSizes[2] = 4;
	rankingsSchema.fieldTypes[2] = INTEGER;
	rankingsSchema.fieldOffsets[3] = 260;
	rankingsSchema.fieldSizes[3] = 4;
	rankingsSchema.fieldTypes[3] = INTEGER;

	Condition cond;
	int val = 1000;
	cond.numClauses = 1;
	cond.fieldNums[0] = 2;
	cond.conditionType[0] = 1;
	cond.values[0] = (uint8_t *)malloc(4);
	memcpy(cond.values[0], &val, 4);
	cond.nextCondition = NULL;

	char *tableName = "rankings";
	createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_TREE_ORAM, 360010, &structureIdIndex); //TODO temp really 360010
	//printTable(enclave_id, (int*)&status, "rankings");

	std::ifstream file("rankings.csv");

	char line[BLOCK_DATA_SIZE]; //make this big just in case
	char data[BLOCK_DATA_SIZE];
	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for (int i = 0; i < 360000; i++)
	{	//TODO temp really 360000
		//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file.getline(line, BLOCK_DATA_SIZE); //get the field

		std::istringstream ss(line);
		for (int j = 0; j < 3; j++)
		{
			if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
			{
				break;
			}
			//printf("data: %s\n", data);
			if (j == 1 || j == 2)
			{ //integer
				int d = 0;
				d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d\n", d);
				memcpy(&row[rankingsSchema.fieldOffsets[j + 1]], &d, 4);
			}
			else
			{ //tinytext
				strncpy((char *)&row[rankingsSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
			}
		}
		//insert the row into the database - index by last sale price
		int indexval = 0;
		memcpy(&indexval, &row[rankingsSchema.fieldOffsets[2]], 4);
		insertIndexRowFast(enclave_id, (int *)&status, "rankings", row, indexval);
		//if (indexval > 1000) printf("indexval %d \n", indexval);
		//printTable(enclave_id, (int*)&status, "rankings");
	}

	printf("created BDB1 table\n");
	time_t startTime, endTime;
	double elapsedTime;
	//printTable(enclave_id, (int*)&status, "rankings");

	startTime = clock();
	indexSelect(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 2, 1000, INT_MAX, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	printf("BDB1 running time (small): %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
	deleteTable(enclave_id, (int *)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 3, 1000, INT_MAX, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	printf("BDB1 running time (hash): %.5f\n", elapsedTime);
	printTable(enclave_id, (int *)&status, "ReturnTable");
	deleteTable(enclave_id, (int *)&status, "ReturnTable");
	startTime = clock();
	indexSelect(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 5, 1000, INT_MAX, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	printf("BDB1 running time (baseline): %.5f\n", elapsedTime);
	printTable(enclave_id, (int *)&status, "ReturnTable");
	deleteTable(enclave_id, (int *)&status, "ReturnTable");

	deleteTable(enclave_id, (int *)&status, "rankings");
}

void BDB1Linear(sgx_enclave_id_t enclave_id, int status)
{
	//block size needs to be 512
	// uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	// int structureId1 = -1;
	// int structureId2 = -1;
	// Schema rankingsSchema;
	// rankingsSchema.numFields = 4;
	// rankingsSchema.fieldOffsets[0] = 0;
	// rankingsSchema.fieldSizes[0] = 1;
	// rankingsSchema.fieldTypes[0] = CHAR;
	// rankingsSchema.fieldOffsets[1] = 1;
	// rankingsSchema.fieldSizes[1] = 255;
	// rankingsSchema.fieldTypes[1] = TINYTEXT;
	// rankingsSchema.fieldOffsets[2] = 256;
	// rankingsSchema.fieldSizes[2] = 4;
	// rankingsSchema.fieldTypes[2] = INTEGER;
	// rankingsSchema.fieldOffsets[3] = 260;
	// rankingsSchema.fieldSizes[3] = 4;
	// rankingsSchema.fieldTypes[3] = INTEGER;

	Condition cond;
	int val = 1000;
	cond.numClauses = 1;
	cond.fieldNums[0] = 2;
	cond.conditionType[0] = 1;
	cond.values[0] = (uint8_t *)malloc(4);
	memcpy(cond.values[0], &val, 4);
	cond.nextCondition = NULL;

	// char *tableName = "rankings";
	// printf("start create table\n");

	// createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 360010, &structureId1); //TODO temp really 360010
	// printf("finish create table\n");

	// std::ifstream file("rankings.csv");

	// char line[BLOCK_DATA_SIZE]; //make this big just in case
	// char data[BLOCK_DATA_SIZE];
	// //file.getline(line, BLOCK_DATA_SIZE);//burn first line
	// row[0] = 'a';
	// printf("start read in data\n");
	// for (int i = 0; i < 360000; i++)
	// {	//TODO temp really 360000
	// 	//for(int i = 0; i < 1000; i++){
	// 	memset(row, 'a', BLOCK_DATA_SIZE);
	// 	file.getline(line, BLOCK_DATA_SIZE); //get the field

	// 	std::istringstream ss(line);
	// 	for (int j = 0; j < 3; j++)
	// 	{
	// 		if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
	// 		{
	// 			break;
	// 		}
	// 		//printf("data: %s\n", data);
	// 		if (j == 1 || j == 2)
	// 		{ //integer
	// 			int d = 0;
	// 			d = atoi(data);
	// 			//printf("data: %s\n", data);
	// 			//printf("d %d\n", d);
	// 			memcpy(&row[rankingsSchema.fieldOffsets[j + 1]], &d, 4);
	// 		}
	// 		else
	// 		{ //tinytext
	// 			strncpy((char *)&row[rankingsSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
	// 		}
	// 	}
	// 	//manually insert into the linear scan structure for speed purposes
	// 	opOneLinearScanBlock(enclave_id, (int *)&status, structureId1, i, (Linear_Scan_Block *)row, 1);
	// 	incrementNumRows(enclave_id, (int *)&status, structureId1);
	// }
	// printf("created BDB1 table - linear\n");
	time_t startTime, endTime;
	double elapsedTime;
	//printTable(enclave_id, (int*)&status, "rankings");

	startTime = clock();
	printf("before enter enclave\n");
	selectRows(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 2, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	printf("BDB1 - %d - running time - %.5f - seconds(ObliDB)\n", rankingsLength, elapsedTime);

	//printTable(enclave_id, (int*)&status, "ReturnTable");
	deleteTable(enclave_id, (int *)&status, "ReturnTable");
	// startTime = clock();
	// selectRows(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 3, 0);
	// //char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	// endTime = clock();
	// elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	// printf("BDB1 running time (hash): %.5f\n", elapsedTime);
	// //printTable(enclave_id, (int*)&status, "ReturnTable");
	// deleteTable(enclave_id, (int *)&status, "ReturnTable");
	// startTime = clock();
	// selectRows(enclave_id, (int *)&status, "rankings", -1, cond, -1, -1, 5, 0);
	// //char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice, int key_start, int key_end
	// endTime = clock();
	// elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	// printf("BDB1 running time (baseline): %.5f\n", elapsedTime);
	//printTable(enclave_id, (int*)&status, "ReturnTable");
	//deleteTable(enclave_id, (int *)&status, "ReturnTable");
	// deleteTable(enclave_id, (int *)&status, "rankings");
}

void BDB2(sgx_enclave_id_t enclave_id, int status, int baseline)
{
	//block size 2048

	// uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	// int structureIdIndex = -1;
	// int structureIdLinear = -1;
	// Schema userdataSchema;
	// userdataSchema.numFields = 10;
	// userdataSchema.fieldOffsets[0] = 0;
	// userdataSchema.fieldSizes[0] = 1;
	// userdataSchema.fieldTypes[0] = CHAR;
	// userdataSchema.fieldOffsets[1] = 1;
	// userdataSchema.fieldSizes[1] = 255;
	// userdataSchema.fieldTypes[1] = TINYTEXT;
	// userdataSchema.fieldOffsets[2] = 256;
	// userdataSchema.fieldSizes[2] = 255;
	// userdataSchema.fieldTypes[2] = TINYTEXT;
	// userdataSchema.fieldOffsets[3] = 511;
	// userdataSchema.fieldSizes[3] = 4;
	// userdataSchema.fieldTypes[3] = INTEGER;
	// userdataSchema.fieldOffsets[4] = 515;
	// userdataSchema.fieldSizes[4] = 4;
	// userdataSchema.fieldTypes[4] = INTEGER;
	// userdataSchema.fieldOffsets[5] = 519;
	// userdataSchema.fieldSizes[5] = 255;
	// userdataSchema.fieldTypes[5] = TINYTEXT;
	// userdataSchema.fieldOffsets[6] = 774;
	// userdataSchema.fieldSizes[6] = 255;
	// userdataSchema.fieldTypes[6] = TINYTEXT;
	// userdataSchema.fieldOffsets[7] = 1029;
	// userdataSchema.fieldSizes[7] = 255;
	// userdataSchema.fieldTypes[7] = TINYTEXT;
	// userdataSchema.fieldOffsets[8] = 1284;
	// userdataSchema.fieldSizes[8] = 255;
	// userdataSchema.fieldTypes[8] = TINYTEXT;
	// userdataSchema.fieldOffsets[9] = 1539;
	// userdataSchema.fieldSizes[9] = 4;
	// userdataSchema.fieldTypes[9] = INTEGER;

	Condition cond;
	cond.numClauses = 0;
	cond.nextCondition = NULL;

	// char *tableName = "uservisits";
	// createTable(enclave_id, (int *)&status, &userdataSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 350010, &structureIdLinear); //TODO temp really 350010

	// std::ifstream file2("uservisits.csv");
	// char line[BLOCK_DATA_SIZE]; //make this big just in case
	// char data[BLOCK_DATA_SIZE];
	// //file.getline(line, BLOCK_DATA_SIZE);//burn first line
	// row[0] = 'a';
	// for (int i = 0; i < 350000; i++)
	// {	//TODO temp really 350000
	// 	//for(int i = 0; i < 1000; i++){
	// 	memset(row, 'a', BLOCK_DATA_SIZE);
	// 	file2.getline(line, BLOCK_DATA_SIZE); //get the field

	// 	std::istringstream ss(line);
	// 	for (int j = 0; j < 9; j++)
	// 	{
	// 		if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
	// 		{
	// 			break;
	// 		}
	// 		//printf("data: %s\n", data);
	// 		if (j == 2 || j == 3 || j == 8)
	// 		{ //integer
	// 			int d = 0;
	// 			if (j == 3)
	// 				d = atof(data) * 100;
	// 			else
	// 				d = atoi(data);
	// 			//printf("data: %s\n", data);
	// 			//printf("d %d ", d);
	// 			memcpy(&row[userdataSchema.fieldOffsets[j + 1]], &d, 4);
	// 		}
	// 		else
	// 		{ //tinytext
	// 			strncpy((char *)&row[userdataSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
	// 		}
	// 	}
	// 	//manually insert into the linear scan structure for speed purposes
	// 	opOneLinearScanBlock(enclave_id, (int *)&status, structureIdLinear, i, (Linear_Scan_Block *)row, 1);
	// 	incrementNumRows(enclave_id, (int *)&status, structureIdLinear);
	// }

	// printf("created BDB2 table\n");
	time_t startTime, endTime;
	double elapsedTime;
	//printTable(enclave_id, (int*)&status, "uservisits");
	startTime = clock();
	if (baseline == 1)
		selectRows(enclave_id, (int *)&status, "uservisits", 4, cond, 1, 1, -2, 2);
	else
		highCardLinGroupBy(enclave_id, (int *)&status, "uservisits", 4, cond, 1, 1, -2, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	//printf("BDB2 running time: %.5f\n", elapsedTime);
	//printTable(enclave_id, (int *)&status, "ReturnTable");
	printf("BDB2 - %d - running time - %.5f - seconds(ObliDB)\n", rankingsLength, elapsedTime);
	deleteTable(enclave_id, (int *)&status, "ReturnTable");

	// deleteTable(enclave_id, (int *)&status, "uservisits");
}

void BDB2Index(sgx_enclave_id_t enclave_id, int status, int baseline)
{
	//block size 2048

	uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	int structureIdIndex = -1;
	int structureIdLinear = -1;
	Schema userdataSchema;
	userdataSchema.numFields = 10;
	userdataSchema.fieldOffsets[0] = 0;
	userdataSchema.fieldSizes[0] = 1;
	userdataSchema.fieldTypes[0] = CHAR;
	userdataSchema.fieldOffsets[1] = 1;
	userdataSchema.fieldSizes[1] = 255;
	userdataSchema.fieldTypes[1] = TINYTEXT;
	userdataSchema.fieldOffsets[2] = 256;
	userdataSchema.fieldSizes[2] = 255;
	userdataSchema.fieldTypes[2] = TINYTEXT;
	userdataSchema.fieldOffsets[3] = 511;
	userdataSchema.fieldSizes[3] = 4;
	userdataSchema.fieldTypes[3] = INTEGER;
	userdataSchema.fieldOffsets[4] = 515;
	userdataSchema.fieldSizes[4] = 4;
	userdataSchema.fieldTypes[4] = INTEGER;
	userdataSchema.fieldOffsets[5] = 519;
	userdataSchema.fieldSizes[5] = 255;
	userdataSchema.fieldTypes[5] = TINYTEXT;
	userdataSchema.fieldOffsets[6] = 774;
	userdataSchema.fieldSizes[6] = 255;
	userdataSchema.fieldTypes[6] = TINYTEXT;
	userdataSchema.fieldOffsets[7] = 1029;
	userdataSchema.fieldSizes[7] = 255;
	userdataSchema.fieldTypes[7] = TINYTEXT;
	userdataSchema.fieldOffsets[8] = 1284;
	userdataSchema.fieldSizes[8] = 255;
	userdataSchema.fieldTypes[8] = TINYTEXT;
	userdataSchema.fieldOffsets[9] = 1539;
	userdataSchema.fieldSizes[9] = 4;
	userdataSchema.fieldTypes[9] = INTEGER;

	Condition cond;
	cond.numClauses = 0;
	cond.nextCondition = NULL;

	char *tableName = "uservisits";
	createTable(enclave_id, (int *)&status, &userdataSchema, tableName, strlen(tableName), TYPE_TREE_ORAM, 350010, &structureIdIndex); //TODO temp really 350010

	std::ifstream file2("uservisits.csv");
	char line[BLOCK_DATA_SIZE]; //make this big just in case
	char data[BLOCK_DATA_SIZE];
	//file.getline(line, BLOCK_DATA_SIZE);//burn first line
	row[0] = 'a';
	for (int i = 0; i < 350000; i++)
	{	//TODO temp really 350000
		//for(int i = 0; i < 1000; i++){
		memset(row, 'a', BLOCK_DATA_SIZE);
		file2.getline(line, BLOCK_DATA_SIZE); //get the field

		std::istringstream ss(line);
		for (int j = 0; j < 9; j++)
		{
			if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
			{
				break;
			}
			//printf("data: %s\n", data);
			if (j == 2 || j == 3 || j == 8)
			{ //integer
				int d = 0;
				if (j == 3)
					d = atof(data) * 100;
				else
					d = atoi(data);
				//printf("data: %s\n", data);
				//printf("d %d ", d);
				memcpy(&row[userdataSchema.fieldOffsets[j + 1]], &d, 4);
			}
			else
			{ //tinytext
				strncpy((char *)&row[userdataSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
			}
		}
		int indexval = 0;
		memcpy(&indexval, &row[userdataSchema.fieldOffsets[9]], 4); //doesn't matter the column for this, we're doing linear scans anyway
		insertIndexRowFast(enclave_id, (int *)&status, "uservisits", row, indexval);
	}

	printf("created BDB2 table\n");
	time_t startTime, endTime;
	double elapsedTime;
	//printTable(enclave_id, (int*)&status, "uservisits");
	startTime = clock();
	highCardLinGroupBy(enclave_id, (int *)&status, "uservisits", 4, cond, 1, 1, -2, 0);
	//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	//printf("BDB2 running time: %.5f\n", elapsedTime);
	printf("BDB2 running time: %.5f\n", elapsedTime);
	printTable(enclave_id, (int *)&status, "ReturnTable");

	deleteTable(enclave_id, (int *)&status, "ReturnTable");

	deleteTable(enclave_id, (int *)&status, "uservisits");
}

void BDB3(sgx_enclave_id_t enclave_id, int status, int baseline)
{

	// //block size 2048
	// uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
	// int structureId1 = -1;
	// int structureId2 = -1;
	// Schema rankingsSchema;
	// rankingsSchema.numFields = 4;
	// rankingsSchema.fieldOffsets[0] = 0;
	// rankingsSchema.fieldSizes[0] = 1;
	// rankingsSchema.fieldTypes[0] = CHAR;
	// rankingsSchema.fieldOffsets[1] = 1;
	// rankingsSchema.fieldSizes[1] = 255;
	// rankingsSchema.fieldTypes[1] = TINYTEXT;
	// rankingsSchema.fieldOffsets[2] = 256;
	// rankingsSchema.fieldSizes[2] = 4;
	// rankingsSchema.fieldTypes[2] = INTEGER;
	// rankingsSchema.fieldOffsets[3] = 260;
	// rankingsSchema.fieldSizes[3] = 4;
	// rankingsSchema.fieldTypes[3] = INTEGER;

	// char *tableName = "rankings";
	// createTable(enclave_id, (int *)&status, &rankingsSchema, tableName, strlen(tableName), TYPE_LINEAR_SCAN, 360010, &structureId1); //TODO temp really 360010

	// std::ifstream file("rankings.csv");

	// char line[BLOCK_DATA_SIZE]; //make this big just in case
	// char data[BLOCK_DATA_SIZE];
	// //file.getline(line, BLOCK_DATA_SIZE);//burn first line
	// row[0] = 'a';
	// for (int i = 0; i < 360000; i++)
	// {	//TODO temp really 360000
	// 	//for(int i = 0; i < 1000; i++){
	// 	memset(row, 'a', BLOCK_DATA_SIZE);
	// 	file.getline(line, BLOCK_DATA_SIZE); //get the field

	// 	std::istringstream ss(line);
	// 	for (int j = 0; j < 3; j++)
	// 	{
	// 		if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
	// 		{
	// 			break;
	// 		}
	// 		//printf("data: %s\n", data);
	// 		if (j == 1 || j == 2)
	// 		{ //integer
	// 			int d = 0;
	// 			d = atoi(data);
	// 			//printf("data: %s\n", data);
	// 			//printf("d %d\n", d);
	// 			memcpy(&row[rankingsSchema.fieldOffsets[j + 1]], &d, 4);
	// 		}
	// 		else
	// 		{ //tinytext
	// 			strncpy((char *)&row[rankingsSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
	// 		}
	// 	}
	// 	//manually insert into the linear scan structure for speed purposes
	// 	opOneLinearScanBlock(enclave_id, (int *)&status, structureId1, i, (Linear_Scan_Block *)row, 1);
	// 	incrementNumRows(enclave_id, (int *)&status, structureId1);
	// }
	// printf("created rankings table\n");

	// Schema userdataSchema;
	// userdataSchema.numFields = 10;
	// userdataSchema.fieldOffsets[0] = 0;
	// userdataSchema.fieldSizes[0] = 1;
	// userdataSchema.fieldTypes[0] = CHAR;
	// userdataSchema.fieldOffsets[1] = 1;
	// userdataSchema.fieldSizes[1] = 255;
	// userdataSchema.fieldTypes[1] = TINYTEXT;
	// userdataSchema.fieldOffsets[2] = 256;
	// userdataSchema.fieldSizes[2] = 255;
	// userdataSchema.fieldTypes[2] = TINYTEXT;
	// userdataSchema.fieldOffsets[3] = 511;
	// userdataSchema.fieldSizes[3] = 4;
	// userdataSchema.fieldTypes[3] = INTEGER;
	// userdataSchema.fieldOffsets[4] = 515;
	// userdataSchema.fieldSizes[4] = 4;
	// userdataSchema.fieldTypes[4] = INTEGER;
	// userdataSchema.fieldOffsets[5] = 519;
	// userdataSchema.fieldSizes[5] = 255;
	// userdataSchema.fieldTypes[5] = TINYTEXT;
	// userdataSchema.fieldOffsets[6] = 774;
	// userdataSchema.fieldSizes[6] = 255;
	// userdataSchema.fieldTypes[6] = TINYTEXT;
	// userdataSchema.fieldOffsets[7] = 1029;
	// userdataSchema.fieldSizes[7] = 255;
	// userdataSchema.fieldTypes[7] = TINYTEXT;
	// userdataSchema.fieldOffsets[8] = 1284;
	// userdataSchema.fieldSizes[8] = 255;
	// userdataSchema.fieldTypes[8] = TINYTEXT;
	// userdataSchema.fieldOffsets[9] = 1539;
	// userdataSchema.fieldSizes[9] = 4;
	// userdataSchema.fieldTypes[9] = INTEGER;

	// Condition cond;
	// cond.numClauses = 0;
	// cond.nextCondition = NULL;

	// char *tableName2 = "uservisits";
	// createTable(enclave_id, (int *)&status, &userdataSchema, tableName2, strlen(tableName2), TYPE_LINEAR_SCAN, 350010, &structureId2); //TODO temp really 350010

	// std::ifstream file2("uservisits.csv");

	// //file.getline(line, BLOCK_DATA_SIZE);//burn first line
	// row[0] = 'a';
	// for (int i = 0; i < 350000; i++)
	// {	//TODO temp really 350000
	// 	//for(int i = 0; i < 1000; i++){
	// 	memset(row, 'a', BLOCK_DATA_SIZE);
	// 	file2.getline(line, BLOCK_DATA_SIZE); //get the field

	// 	std::istringstream ss(line);
	// 	for (int j = 0; j < 9; j++)
	// 	{
	// 		if (!ss.getline(data, BLOCK_DATA_SIZE, ','))
	// 		{
	// 			break;
	// 		}
	// 		//printf("data: %s\n", data);
	// 		if (j == 2 || j == 3 || j == 8)
	// 		{ //integer
	// 			int d = 0;
	// 			if (j == 3)
	// 				d = atof(data) * 100;
	// 			else
	// 				d = atoi(data);
	// 			//printf("data: %s\n", data);
	// 			//printf("d %d ", d);
	// 			memcpy(&row[userdataSchema.fieldOffsets[j + 1]], &d, 4);
	// 		}
	// 		else
	// 		{ //tinytext
	// 			strncpy((char *)&row[userdataSchema.fieldOffsets[j + 1]], data, strlen(data) + 1);
	// 		}
	// 	}
	// 	//manually insert into the linear scan structure for speed purposes
	// 	opOneLinearScanBlock(enclave_id, (int *)&status, structureId2, i, (Linear_Scan_Block *)row, 1);
	// 	incrementNumRows(enclave_id, (int *)&status, structureId2);
	// }

	// printf("created uservisits table\n");
	time_t startTime, endTime;
	double elapsedTime;

	Condition cond1, cond2;
	int l = 19800101, h = 19830101;
	cond1.numClauses = 1;
	cond1.fieldNums[0] = 3;
	cond1.conditionType[0] = 1;
	cond1.values[0] = (uint8_t *)malloc(4);
	memcpy(cond1.values[0], &l, 4);
	cond1.nextCondition = &cond2;
	cond2.numClauses = 1;
	cond2.fieldNums[0] = 3;
	cond2.conditionType[0] = 2;
	cond2.values[0] = (uint8_t *)malloc(4);
	memcpy(cond2.values[0], &h, 4);
	cond2.nextCondition = NULL;
	Condition noCond;
	noCond.numClauses = 0;
	noCond.nextCondition = NULL;

	startTime = clock();
	if (baseline == 1)
	{
		selectRows(enclave_id, (int *)&status, "uservisits", -1, cond1, -1, -1, 5, 0);
		renameTable(enclave_id, (int *)&status, "ReturnTable", "uvJ");
		//printTable(enclave_id, (int*)&status, "uvJ");
		joinTables(enclave_id, (int *)&status, "uvJ", "rankings", 2, 1, -1, -1);
		//int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey) {//put the smaller table first for
		renameTable(enclave_id, (int *)&status, "JoinReturn", "jr");
		//printTable(enclave_id, (int*)&status, "jr");
		selectRows(enclave_id, (int *)&status, "jr", 10, noCond, 4, 1, 4, 2);
		renameTable(enclave_id, (int *)&status, "ReturnTable", "last");
		//printTable(enclave_id, (int*)&status, "last");
		selectRows(enclave_id, (int *)&status, "last", 2, noCond, 3, -1, 0, 0);
	}
	else
	{
		selectRows(enclave_id, (int *)&status, "uservisits", -1, cond1, -1, -1, 2, 0);
		//indexSelect(enclave_id, (int*)&status, "uservisits", -1, cond1, -1, -1, 2, l, h);
		renameTable(enclave_id, (int *)&status, "ReturnTable", "uvJ");
		//printTable(enclave_id, (int*)&status, "uvJ");
		joinTables(enclave_id, (int *)&status, "uvJ", "rankings", 2, 1, -1, -1);
		//int joinTables(char* tableName1, char* tableName2, int joinCol1, int joinCol2, int startKey, int endKey) {//put the smaller table first for
		renameTable(enclave_id, (int *)&status, "JoinReturn", "jr");
		//printTable(enclave_id, (int*)&status, "jr");
		selectRows(enclave_id, (int *)&status, "jr", 10, noCond, 4, 1, 4, 0);
		renameTable(enclave_id, (int *)&status, "ReturnTable", "last");
		//printTable(enclave_id, (int*)&status, "last");
		selectRows(enclave_id, (int *)&status, "last", 2, noCond, 3, -1, -1, 0);
		//select from index
		//join
		//fancy group by
		//select max
		//char* tableName, int colChoice, Condition c, int aggregate, int groupCol, int algChoice
	}
	endTime = clock();
	elapsedTime = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
	printf("BDB3 - %d - running time - %.5f - seconds(ObliDB)\n", rankingsLength, elapsedTime);

	//printTable(enclave_id, (int*)&status, "ReturnTable");
	deleteTable(enclave_id, (int *)&status, "ReturnTable");

	// deleteTable(enclave_id, (int *)&status, "uservisits");
	// deleteTable(enclave_id, (int *)&status, "rankings");
}

void joinTests(sgx_enclave_id_t enclave_id, int status)
{
	//comparing our original join and sort merge join for linear tables
	//using same schema as used for synthetic data in FabTests

	int testSizes[] = {5000, 10000, 25000};
	int numTests = 3;

	//for testing
	//int testSizes[] = {5000};
	//int numTests = 1;

	//confusingly, thi sis the first table
	int table2Sizes[] = {1000, 5000, 10000};
	int num2Tests = 3;

	for (int k = 0; k < num2Tests; k++)
	{

		int table2Size = table2Sizes[k];
		createTestTable(enclave_id, (int *)&status, "jTable", table2Size); //decide what to do with the size of this one
		//createTestTableIndex(enclave_id, (int*)&status, "jTableIndex", 10000);//decide what to do with the size of this one
		//deleteRows(enclave_id, (int*)&status, "jTable", condition1, -1, -1);

		printf("created tables\n");
		for (int i = 0; i < numTests; i++)
		{
			int testSize = testSizes[i];
			createTestTable(enclave_id, (int *)&status, "testTable", testSize);
			//createTestTableIndex(enclave_id, (int*)&status, "testTableIndex", testSize);
			printf("\n|Test Sizes %d %d:\n", table2Size, testSize);

			double join1Times[6] = {0};
			double join2Times[6] = {0};
			double join3Times[6] = {0};
			double join4Times[6] = {0};
			time_t startTime, endTime;
			uint8_t *row = (uint8_t *)malloc(BLOCK_DATA_SIZE);
			const char *text = "You would measure time the measureless and the immeasurable.";

			for (int j = 0; j < 5; j++)
			{ //want to average 5 trials

				//join 1
				startTime = clock();
				joinTables(enclave_id, (int *)&status, "jTable", "testTable", 1, 1, -1, -1);
				endTime = clock();
				join1Times[j] = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
				//printTableCheating(enclave_id, (int*)&status, "JoinReturn");
				deleteTable(enclave_id, (int *)&status, "JoinReturn");

				//join 2
				startTime = clock();
				joinTables(enclave_id, (int *)&status, "jTable", "testTable", 1, 1, -1, -248);
				endTime = clock();
				join2Times[j] = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
				//printTableCheating(enclave_id, (int*)&status, "JoinReturn");
				deleteTable(enclave_id, (int *)&status, "JoinReturn");

				//join 3
				startTime = clock();
				joinTables(enclave_id, (int *)&status, "jTable", "testTable", 1, 1, -249, -248);
				endTime = clock();
				join3Times[j] = (double)(endTime - startTime) / (CLOCKS_PER_SEC);
				//printTableCheating(enclave_id, (int*)&status, "JoinReturn");
				deleteTable(enclave_id, (int *)&status, "JoinReturn");
				/*
                //join 4
                startTime = clock();
                joinTables(enclave_id, (int*)&status, "jTableIndex", "testTableIndex", 1, 1, 1, testSize);
                endTime = clock();
                join4Times[j] = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
                deleteTable(enclave_id, (int*)&status, "JoinReturn");
		*/
			}
			free(row);
			for (int j = 0; j < 5; j++)
			{
				join1Times[5] += join1Times[j];
				join2Times[5] += join2Times[j];
				join3Times[5] += join3Times[j];
				join4Times[5] += join4Times[j];
			}
			join1Times[5] /= 5;
			join2Times[5] /= 5;
			join3Times[5] /= 5;
			join4Times[5] /= 5;
			printf("\njoin1Times | %.5f %.5f %.5f %.5f %.5f : %.5f\n", join1Times[0], join1Times[1], join1Times[2], join1Times[3], join1Times[4], join1Times[5]);
			printf("join2Times | %.5f %.5f %.5f %.5f %.5f : %.5f\n", join2Times[0], join2Times[1], join2Times[2], join2Times[3], join2Times[4], join2Times[5]);
			printf("join3Times | %.5f %.5f %.5f %.5f %.5f : %.5f\n", join3Times[0], join3Times[1], join3Times[2], join3Times[3], join3Times[4], join3Times[5]);
			printf("(not in use) join4Times | %.5f %.5f %.5f %.5f %.5f : %.5f\n", join4Times[0], join4Times[1], join4Times[2], join4Times[3], join4Times[4], join4Times[5]);

			deleteTable(enclave_id, (int *)&status, "testTable");
			//deleteTable(enclave_id, (int*)&status, "testTableIndex");
		}
		deleteTable(enclave_id, (int *)&status, "jTable");
		//deleteTable(enclave_id, (int*)&status, "jTableIndex");
	}
}

//helpers

sgx_enclave_id_t enclave_id = 0;
sgx_status_t status;
typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;
/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE,
     "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }
    //printf("enclave creation success, eid is %d \n", global_eid);
    return 0;
}
// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x
int main(int argc, char *argv[])
{
	int ret = 0;
	(void)(argc);
    (void)(argv);
    char *rankingFilename = (char *)(argv[1]);
    char *uservisitsFilename = (char *)(argv[2]);
    rankingsLength = atoi(argv[3]);
    uservisitsLength = atoi(argv[4]);
    std::cout << "read rankings table " << rankingsLength << " rows, and uservisits " << uservisitsLength <<"rows"<< std::endl;

    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }


	total_init(enclave_id, &status);
	if (status != SGX_SUCCESS)
	{
		printf("key initialization failed %d.\n", status);
	}
    LoadTables(enclave_id, status, rankingFilename, rankingsLength, uservisitsFilename, uservisitsLength);


	//now use the request in oramInitMsg to initialize oram

	unsigned int *oramCapacity = (unsigned int *)malloc(sizeof(int));

	//real world query tests
	//PICK EXPERIMENT TO RUN HERE

	//nasdaqTables(enclave_id, status); //2048
	//complaintTables(enclave_id, status); //4096
	//flightTables(enclave_id, status); //512 (could be less, but we require 512 minimum)
	//BDB1Index(enclave_id, status);//512
	//BDB1Linear(enclave_id, status); //512
	//BDB2(enclave_id, status, 0);//2048
	//BDB2Index(enclave_id, status, 0);//2048
	BDB3(enclave_id, status, 0);//2048
	// BDB2(enclave_id, status, 1);//2048 (baseline)
	// BDB3(enclave_id, status, 1);//2048 (baseline)
	//basicTests(enclave_id, status);//512
	//fabTests(enclave_id, status);//512
	//joinTests(enclave_id, status);//512
	//workloadTests(enclave_id, status);//512
	//insdelScaling(enclave_id, status);//512




sgx_destroy_enclave(enclave_id);

return ret;
}
