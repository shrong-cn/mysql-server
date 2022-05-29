/* Copyright (c) 2016, 2021, Oracle and/or its affiliates.

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

#include "kms_imp.h"
#include <mysql/components/service_implementation.h>
#include <mysql/components/services/log_builtins.h>
#include <mysql/components/my_service.h>
#include "sql/kms_agent/kms_agent.h"
#include "mysqld_error.h"
#include <string>
#include <cstring>
#include <iomanip>
#include <map>
#include <mutex>
#include <utility>
#include <sstream>

#define LOG_COMPONENT_TAG

struct kms_sm4_key_class {
  std::map<std::string,std::string> map_;
  std::mutex lock_;
};

static kms_sm4_key_class kms_sm4_key_cache;

static int kms_sm4_key_get(const std::string& key,std::string& content) {
  auto& c=kms_sm4_key_cache;
  std::lock_guard<std::mutex> l(c.lock_);
  auto iter = c.map_.find(key);
  if(iter==c.map_.end()) {
    return -1;
  }
  content=iter->second;
  return 0;
}
static void kms_sm4_key_put(const std::string& key,const std::string& content) {
  auto& c=kms_sm4_key_cache;
  std::lock_guard<std::mutex> l(c.lock_);
  c.map_[key]=content;
}



std::string kms_imp::hexPrintableToBinary(const std::string& s)
{
  std::string out;
  if (s.length()%2==1) {
    LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "hexPrintableToBinary unexpected input: ", s.data());
    //TLOGERROR(MessageIDKit::Log() << "hexPrintableToBinary unexpected input:" << s << endl);
    return "";
  }
  char h=0,l=0;
  for (size_t i=0; i<s.length(); i+=2)
  {
    h=s[i],l=s[i+1];
    if(h=='0' && toupper(l=='X'))
      continue;
  
    if(h>='0' && h<='9')
      h = h-'0';
    else if(h>='a' && h<='f')
      h = h-'a'+10;
    else if(h>='A' && h<='F')
      h = h-'A'+10;
    else {
      LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "hexPrintableToBinary unexpected input: ", s.data());
      return "";
    }
  
    if(l>='0' && l<='9')
      l = l-'0';
    else if(l>='a' && l<='f')
      l = l-'a'+10;
    else if(l>='A' && l<='F')
      l = l-'A'+10;
    else {
      LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "hexPrintableToBinary unexpected input: ", s.data());
      return "";
    }
    out.push_back(h*16+l);
  }
  return out;
}


std::string kms_imp::binaryToHexPrintable(const std::string& s)
{ 
  std::ostringstream out;
  for (size_t i=0; i<s.length(); ++i)
  { 
    out << std::hex << std::setfill('0') << std::setw(2);
    out << (static_cast<unsigned short>(s[i]) & 0xff);
  }
  return out.str();
}


std::string kms_imp::binaryToHexPrintableSep(const std::string& s)
{
	std::ostringstream out;
	// out << std::hex << std::setfill('0') << std::setw(2);
	for (size_t i=0; i<s.length(); ++i)
	{
		if (i!=0 && i%8==0) {out << "  ";}
		out << std::hex << std::setfill('0') << std::setw(2) << (static_cast<unsigned short>(s[i]) & 0xff);
	}
	return out.str();
}


DEFINE_BOOL_METHOD(kms_imp::test_udf_method_1,()) {
  LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, " +++++++++++++++ test_udf_method_1 ++++++++++++++++ ");
  return false;
}


DEFINE_BOOL_METHOD(kms_imp::get_kms_key,(int keyType, char* keyID, char* key, unsigned int* keyLen)) {
  (void)keyType;
  if (!keyID||!key||!keyLen)
    return true;

  //return false;

  std::string cachedKey;
  if(keyID[0]==0) {
//kms.generate()
#if 0
    static int ID=10;
    strcpy(keyID, std::to_string(ID).data());
    ID++;
#else
    int cipherID=0;
    int ret=::generate_kms_key(32,cipherID,cachedKey);
    if(ret)
        return true;
#endif
    strcpy(keyID, std::to_string(cipherID).data());
    kms_sm4_key_put(keyID, cachedKey);
  } else {
    int ret = kms_sm4_key_get(keyID, cachedKey);
    if(ret) {
//kms.get()
#if 0
      cachedKey.resize(32);
      memset(const_cast<char*>(cachedKey.data()), 0x01, 32);
#else
      int cipherID=atoi(keyID);
      int ret=::get_kms_key(cipherID,cachedKey);
      if(ret)
          return true;
#endif
      kms_sm4_key_put(keyID, cachedKey);
    }
  }

  memcpy(key,cachedKey.data(),cachedKey.size());
  *keyLen=cachedKey.size();

  std::string msg="kms_imp::get_kms_key |id: " + std::string(keyID) + "|key: " + binaryToHexPrintableSep(std::string(key,*keyLen));
  LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, msg.c_str());
  return false;
}


DEFINE_BOOL_METHOD(kms_imp::log, (const char* msg)) {
  LogErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, msg);
  return false;
}
