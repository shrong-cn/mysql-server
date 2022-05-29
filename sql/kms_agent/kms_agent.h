#ifndef KMS_AGENT

#define KMS_AGENT


#ifndef __cplusplus
extern "C" {
#endif
int start_kms_agent(int argc, char *argv[]);
int generate_kms_key(int cipherLength,int& cipherID,std::string& cipher);
int get_kms_key(int cipherID,std::string& cipher);


#ifndef __cplusplus
}
#endif

#endif
