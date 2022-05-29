/* Copyright (c) 2000, 2021, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/*
** example file of UDF (user definable functions) that are dynamicly loaded
** into the standard mysqld core.
**
** The functions name, type and shared library is saved in the new system
** table 'func'.  To be able to create new functions one must have write
** privilege for the database 'mysql'.	If one starts MySQL with
** --skip-grant-tables, then UDF initialization will also be skipped.
**
** Syntax for the new commands are:
** create function <function_name> returns {string|real|integer}
**		  soname <name_of_shared_library>
** drop function <function_name>
**
** Each defined function may have a xxxx_init function and a xxxx_deinit
** function.  The init function should alloc memory for the function
** and tell the main function about the max length of the result
** (for string functions), number of decimals (for double functions) and
** if the result may be a null value.
**
** If a function sets the 'error' argument to 1 the function will not be
** called anymore and mysqld will return NULL for all calls to this copy
** of the function.
**
** All strings arguments to functions are given as string pointer + length
** to allow handling of binary data.
** Remember that all functions must be thread safe. This means that one is not
** allowed to alloc any global or static variables that changes!
** If one needs memory one should alloc this in the init function and free
** this on the __deinit function.
**
** Note that the init and __deinit functions are only called once per
** SQL statement while the value function may be called many times
**
** Function 'metaphon' returns a metaphon string of the string argument.
** This is something like a soundex string, but it's more tuned for English.
**
** Function 'myfunc_double' returns summary of codes of all letters
** of arguments divided by summary length of all its arguments.
**
** Function 'myfunc_int' returns summary length of all its arguments.
**
** Function 'sequence' returns an sequence starting from a certain number.
**
** Function 'myfunc_argument_name' returns name of argument.
**
** On the end is a couple of functions that converts hostnames to ip and
** vice versa.
**
** A dynamicly loadable file should be compiled shared.
** (something like: gcc -shared -o my_func.so myfunc.cc).
** You can easily get all switches right by doing:
** cd sql ; make udf_example.o
** Take the compile line that make writes, remove the '-c' near the end of
** the line and add -shared -o udf_example.so to the end of the compile line.
** The resulting library (udf_example.so) should be copied to some dir
** searched by ld. (/usr/lib ?)
** If you are using gcc, then you should be able to create the udf_example.so
** by simply doing 'make udf_example.so'.
**
** After the library is made one must notify mysqld about the new
** functions with the commands:
**
** CREATE FUNCTION metaphon RETURNS STRING SONAME "udf_example.so";
** CREATE FUNCTION myfunc_double RETURNS REAL SONAME "udf_example.so";
** CREATE FUNCTION myfunc_int RETURNS INTEGER SONAME "udf_example.so";
** CREATE FUNCTION sequence RETURNS INTEGER SONAME "udf_example.so";
** CREATE FUNCTION lookup RETURNS STRING SONAME "udf_example.so";
** CREATE FUNCTION reverse_lookup RETURNS STRING SONAME "udf_example.so";
** CREATE AGGREGATE FUNCTION avgcost RETURNS REAL SONAME "udf_example.so";
** CREATE FUNCTION myfunc_argument_name RETURNS STRING SONAME "udf_example.so";
**
** After this the functions will work exactly like native MySQL functions.
** Functions should be created only once.
**
** The functions can be deleted by:
**
** DROP FUNCTION metaphon;
** DROP FUNCTION myfunc_double;
** DROP FUNCTION myfunc_int;
** DROP FUNCTION lookup;
** DROP FUNCTION reverse_lookup;
** DROP FUNCTION avgcost;
** DROP FUNCTION myfunc_argument_name;
**
** The CREATE FUNCTION and DROP FUNCTION update the func@mysql table. All
** Active function will be reloaded on every restart of server
** (if --skip-grant-tables is not given)
**
** If you ge problems with undefined symbols when loading the shared
** library, you should verify that mysqld is compiled with the -rdynamic
** option.
**
** If you can't get AGGREGATES to work, check that you have the column
** 'type' in the mysql.func table.  If not, run 'mysql_upgrade'.
**
*/

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <mutex>
#include <new>
#include <regex>
#include <string>
#include <vector>

#include "mysql.h"
#include "my_dbug.h"
#include "mysql/udf_registration_types.h"

#include "sql/server_component/kms_imp.h"
#include <mysql/components/services/log_builtins.h>
#include "mysqld_error.h"

#include "shrong_sm4_api.h"
#include "shrong_des_api.h"  //须保证主程序链接了ssl和crypto动态库
#include "my_aes.h"

#define LOG_COMPONENT_TAG
extern SERVICE_TYPE(log_builtins) *log_bi;
/*
  Not all platforms have gethostbyaddr_r, so we use a global lock here instead.
  Production-quality code should use getaddrinfo where available.
*/
static std::mutex *LOCK_hostname{nullptr};

/* All function signatures must be right or mysqld will not find the symbol! */

/*************************************************************************
** Example of init function
** Arguments:
** initid	Points to a structure that the init function should fill.
**		This argument is given to all other functions.
**	bool maybe_null	1 if function can return NULL
**				Default value is 1 if any of the arguments
**				is declared maybe_null.
**	unsigned int decimals	Number of decimals.
**				Default value is max decimals in any of the
**				arguments.
**	unsigned int max_length  Length of string result.
**				The default value for integer functions is 21
**				The default value for real functions is 13+
**				default number of decimals.
**				The default value for string functions is
**				the longest string argument.
**	char *ptr;		A pointer that the function can use.
**
** args		Points to a structure which contains:
**	unsigned int arg_count		Number of arguments
**	enum Item_result *arg_type	Types for each argument.
**					Types are STRING_RESULT, REAL_RESULT
**					and INT_RESULT.
**	char **args			Pointer to constant arguments.
**					Contains 0 for not constant argument.
**	unsigned long *lengths;		max string length for each argument
**	char *maybe_null		Information of which arguments
**					may be NULL
**
** message	Error message that should be passed to the user on fail.
**		The message buffer is MYSQL_ERRMSG_SIZE big, but one should
**		try to keep the error message less than 80 bytes long!
**
** This function should return 1 if something goes wrong. In this case
** message should contain something usefull!
**************************************************************************/



/*
  At least one of _init/_deinit is needed unless the server is started
  with --allow_suspicious_udfs.
*/

/****************************************************************************
** Some functions that handles IP and hostname conversions
** The orignal function was from Zeev Suraski.
**
** CREATE FUNCTION lookup RETURNS STRING SONAME "udf_example.so";
**
****************************************************************************/

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

/****************************************************************************
** lookup IP for an hostname.
**
** This code assumes that inet_ntoa() is thread safe (As it is in Solaris)
****************************************************************************/

extern "C" bool lookup_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
    strcpy(message, "Wrong arguments to lookup;  Use the source");
    return true;
  }
  initid->max_length = 11;
  initid->maybe_null = true;
  LOCK_hostname = new std::mutex;
  return false;
}

extern "C" void lookup_deinit(UDF_INIT *) {
  delete LOCK_hostname;
  LOCK_hostname = nullptr;
}

extern "C" char *lookup(UDF_INIT *, UDF_ARGS *args, char *result,
                        unsigned long *res_length, unsigned char *null_value,
                        unsigned char *) {
  unsigned length;
  char name_buff[256];
  struct hostent *hostent;
  struct in_addr in;

  if (!args->args[0] || !(length = args->lengths[0])) {
    *null_value = 1;
    return nullptr;
  }
  if (length >= sizeof(name_buff)) length = sizeof(name_buff) - 1;
  memcpy(name_buff, args->args[0], length);
  name_buff[length] = 0;
  {
    std::lock_guard<std::mutex> lock(*LOCK_hostname);
    if (!(hostent = gethostbyname((char *)name_buff))) {
      *null_value = 1;
      return nullptr;
    }
  }
  memcpy(&in, *hostent->h_addr_list, sizeof(in.s_addr));
  strcpy(result, inet_ntoa(in));
  *res_length = strlen(result);
  return result;
}

/****************************************************************************
****************************************************************************/


extern "C" bool sm4d_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT) {
    strcpy(message, "Error, wrong arguments to sm4d, use as sm4d('0x + cipher','keyID')");
    return true;
  }
  initid->max_length = 2048;
  initid->maybe_null = false;
  return false;
}

extern "C" void sm4d_deinit(UDF_INIT *) {
  return;
}

extern "C" char *sm4d(UDF_INIT *, UDF_ARGS *args, char *result,
                        unsigned long *res_length, unsigned char *null_value,
                        unsigned char *) {
    (void)null_value;
    if (!args) {
        return nullptr;
    }
    if (args->arg_count!=2) {
        int errlen=strlen("Error, wrong arguments to sm4d, use as sm4d('0x + cipher','keyID')");
        memcpy(result,"Error, wrong arguments to sm4d, use as sm4d('0x + cipher','keyID')",errlen);
        *res_length = errlen;
	return result;
    }

    std::string cipher(args->args[0],args->lengths[0]);
    if(cipher.size()>=2 && cipher[0]=='0' && (cipher[1]=='x' || cipher[1]=='X')) {
        cipher=cipher.substr(2);
    }
    std::string binaryCipher=kms_imp::hexPrintableToBinary(cipher);
    std::string keyID(args->args[1],args->lengths[1]);

    std::string msg="sm4 decrypt: sm4d inputCipher=0x" + cipher + ", keyID=" + keyID;
    kms_imp::log(msg.c_str());
    //DBUG_PRINT("ib_log", ("sm4 decrypt: sm4d cipher=0x%s, keyID=%s", cipher.data(), keyID.data()));

    //LogPluginErrV()

    //kms_imp::test_udf_method_1();
    
    char key[256]={0};
    unsigned int keyLen=0;
    kms_imp::get_kms_key(0, const_cast<char*>(keyID.data()), (char*)key, &keyLen);

    std::string origin;
    unsigned originLen=0;
    std::string data;
    unsigned dataLen=0;

    data.resize(cipher.length()+32);
    origin.resize(cipher.length()+32);

    int r1;
    r1 = sr_sm4_encrypt( (unsigned char*)key, keyLen, 0, 2, 0, 0, const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), const_cast<unsigned char*>((const unsigned char*)data.data()), &dataLen);

    data.resize(dataLen);
    std::string hexOutput1=kms_imp::binaryToHexPrintable(data);
      
    kms_imp::log(("sm4 encrypt output: 0x"+hexOutput1).c_str());

    int r2;
    r2 = sr_sm4_decrypt1( (unsigned char*)key, keyLen, 0, 2, 0, 0, const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), const_cast<unsigned char*>((const unsigned char*)origin.data()), &originLen);

    origin.resize(originLen);

    if (r2!=0) {
      kms_imp::log("sm4 decrypt failed");
      const char* fail_str="error: sm4 decryption failed";
      *res_length = strlen(fail_str);
      memcpy(result, fail_str, *res_length);
      return result;
    }

    *res_length = origin.size();
    memcpy(result, origin.data(), origin.size());

    std::string hexOutput=kms_imp::binaryToHexPrintable(origin);
    kms_imp::log(("sm4 decrypt output: 0x"+hexOutput).c_str());

    return result;
}


extern "C" bool aes128d_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT) {
    strcpy(message, "Error, wrong arguments to aes128d, use as aes128d('0x + cipher','keyID')");
    return true;
  }
  initid->max_length = 2048;
  initid->maybe_null = false;
  return false;
}


extern "C" char *aes128d(UDF_INIT *, UDF_ARGS *args, char *result,
                        unsigned long *res_length, unsigned char *null_value,
                        unsigned char *) {
    (void)null_value;
    if (!args) {
        return nullptr;
    }
    if (args->arg_count!=2) {
        int errlen=strlen("Error, wrong arguments to aes128d, use as aes128d('0x + cipher','keyID')");
        memcpy(result,"Error, wrong arguments to aes128d, use as aes128d('0x + cipher','keyID')",errlen);
        *res_length = errlen;
        return result;
    }

    std::string cipher(args->args[0],args->lengths[0]);
    if(cipher.size()>=2 && cipher[0]=='0' && (cipher[1]=='x' || cipher[1]=='X')) {
        cipher=cipher.substr(2);
    }
    std::string binaryCipher=kms_imp::hexPrintableToBinary(cipher);
    std::string keyID(args->args[1],args->lengths[1]);

    std::string msg="aes decrypt: aes128d inputCipher=0x" + cipher + ", keyID=" + keyID;
    kms_imp::log(msg.c_str());
    //DBUG_PRINT("ib_log", ("aes decrypt: aes128d cipher=0x%s, keyID=%s", cipher.data(), keyID.data()));

    char key[256]={0};
    char iv[256]={0};
    unsigned int keyLen=0;
    kms_imp::get_kms_key(0, const_cast<char*>(keyID.data()), (char*)key, &keyLen);

    std::string origin;
    unsigned originLen=0;
    std::string data;
    unsigned dataLen=0;

    data.resize(cipher.length()+32);
    origin.resize(cipher.length()+32);

#if 0
    int r1 = my_aes_encrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(),
                        const_cast<unsigned char*>((const unsigned char*)data.data()), (unsigned char*)key,
                        keyLen, my_aes_128_ecb,
                        (unsigned char*)iv, true);

    dataLen = r1;
    data.resize(dataLen);
    std::string hexOutput1=kms_imp::binaryToHexPrintable(data);

    kms_imp::log(("aes encrypt output: 0x"+hexOutput1).c_str());
#endif

    int r2 = my_aes_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                        const_cast<unsigned char*>((const unsigned char*)origin.data()), (unsigned char*)key,
                        keyLen, my_aes_128_ecb,
                        (unsigned char*)iv, true);

    originLen = r2;
    origin.resize(originLen);

    if (r2<=0) {
      kms_imp::log("aes decrypt failed");
      const char* fail_str="error: aes decryption failed";
      *res_length = strlen(fail_str);
      memcpy(result, fail_str, *res_length);
      return result;
    }

    *res_length = origin.size();
    memcpy(result, origin.data(), origin.size());

    std::string hexOutput=kms_imp::binaryToHexPrintable(origin);
    kms_imp::log(("aes decrypt output: 0x"+hexOutput).c_str());

    return result;
}


extern "C" bool srdec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 3 
    || args->arg_type[0] != STRING_RESULT
    || args->arg_type[1] != STRING_RESULT
    || args->arg_type[2] != STRING_RESULT) {
    strcpy(message, "Error, wrong arguments to srdec, use as srdec('0x + cipher','keyID','algorithm')");
    return true;
  }
  initid->max_length = 2048;
  initid->maybe_null = false;
  return false;
}


extern "C" char *srdec(UDF_INIT *, UDF_ARGS *args, char *result,
                        unsigned long *res_length, unsigned char *null_value,
                        unsigned char *) {
    (void)null_value;
    if (!args) {
        return nullptr;
    }
    if (args->arg_count != 3 
        || args->arg_type[0] != STRING_RESULT
        || args->arg_type[1] != STRING_RESULT
        || args->arg_type[2] != STRING_RESULT) {
        char* msg = "Error, wrong arguments to srdec, use as srdec('0x + cipher','keyID','algorithm')";
        int errlen=strlen(msg);
        memcpy(result, msg, errlen);
        *res_length = errlen;
        return result;
    }

    std::string cipher(args->args[0],args->lengths[0]);
    if(cipher.size()>=2 && cipher[0]=='0' && (cipher[1]=='x' || cipher[1]=='X')) {
      cipher=cipher.substr(2);
    }
    std::string binaryCipher=kms_imp::hexPrintableToBinary(cipher);
    std::string keyID(args->args[1],args->lengths[1]);
    std::string decAlgorithm(args->args[2],args->lengths[2]);

    std::string msg="srdec: inputCipher=0x" + cipher + ", keyID=" + keyID + ", algorithm=" + decAlgorithm;
    kms_imp::log(msg.c_str());
    //DBUG_PRINT("ib_log", ("aes decrypt: aes256d cipher=0x%s, keyID=%s", cipher.data(), keyID.data()));

    char key[256]={0};
    char iv[256]={0};
    unsigned int keyLen=0;
    kms_imp::get_kms_key(0, const_cast<char*>(keyID.data()), (char*)key, &keyLen);

    std::string origin;
    unsigned originLen=0;
    int iOriginLen=0;
    std::string data;
    unsigned dataLen=0;

    data.resize(cipher.length()+32);
    origin.resize(cipher.length()+32);

    int r2 = 0;
    std::string failReason("");
    
    if(decAlgorithm=="AES128") {
      r2 = my_aes_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          const_cast<unsigned char*>((const unsigned char*)origin.data()), (unsigned char*)key,
                          keyLen, my_aes_128_ecb,
                          (unsigned char*)iv, true);
      originLen = r2;
      origin.resize(originLen);
    } else if (decAlgorithm=="AES192") {
      r2 = my_aes_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          const_cast<unsigned char*>((const unsigned char*)origin.data()), (unsigned char*)key,
                          keyLen, my_aes_192_ecb,
                          (unsigned char*)iv, true);
      originLen = r2;
      origin.resize(originLen);
    } else if (decAlgorithm=="AES256") {
      r2 = my_aes_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          const_cast<unsigned char*>((const unsigned char*)origin.data()), (unsigned char*)key,
                          keyLen, my_aes_256_ecb,
                          (unsigned char*)iv, true);
      originLen = r2;
      origin.resize(originLen);
    } else if (decAlgorithm=="DES") {
      int ret = shrong_des_ecb_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          (unsigned char*)key, keyLen, 
                          (unsigned char*)origin.data(), &iOriginLen);
      kms_imp::log(("outlen: "+std::to_string(iOriginLen)).c_str());
      kms_imp::log(("outlen data: "+ origin).data());
      origin.resize(iOriginLen);
      r2 = iOriginLen;
    } else if (decAlgorithm=="3DES_2KEY") {
      int ret = shrong_3des_ecb_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          (unsigned char*)key, keyLen, 
                          1,
                          (unsigned char*)origin.data(), &iOriginLen);
      kms_imp::log(("outlen: "+std::to_string(iOriginLen)).c_str());
      kms_imp::log(("outlen data: "+ origin).data());
      origin.resize(iOriginLen);
      r2 = iOriginLen;
    } else if (decAlgorithm=="3DES_3KEY") {
      int ret = shrong_3des_ecb_decrypt(const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(), 
                          (unsigned char*)key, keyLen, 
                          2,
                          (unsigned char*)origin.data(), &iOriginLen);
      kms_imp::log(("outlen: "+std::to_string(iOriginLen)).c_str());
      kms_imp::log(("outlen data: "+ origin).data());
      origin.resize(iOriginLen);
      r2 = iOriginLen;
    } else if (decAlgorithm=="SM4") {
      int ret = sr_sm4_decrypt1( (unsigned char*)key, keyLen, 0, 2, 0, 0,
              const_cast<unsigned char*>((const unsigned char*)binaryCipher.data()), binaryCipher.length(),
              const_cast<unsigned char*>((const unsigned char*)origin.data()), &originLen);
      r2 = originLen;
      origin.resize(originLen);
    } else {
      r2 = -2;
      failReason=":unsupported algorithm";
    }

    if (r2<=0) {
      kms_imp::log("decrypt failed");
      std::string failStr("error: decryption failed");
      failStr+=failReason;
      *res_length = failStr.size();
      memcpy(result, failStr.data(), *res_length);
      return result;
    }

    *res_length = origin.size();
    memcpy(result, origin.data(), origin.size());

    std::string hexOutput=kms_imp::binaryToHexPrintable(origin);
    kms_imp::log(("decrypt output: 0x"+hexOutput).c_str());

    return result;
}


