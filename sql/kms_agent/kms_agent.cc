#include <iostream>
#include <string>
#include <mutex>
#include "Application.h"
#include "tc_option.h"
#include "Cipher.h"
#include "sql/server_component/kms_imp.h"

using namespace tars;


struct Param
{
	SR5000::CipherPrx pPrx;
	int started=0;
};

static Communicator *_comm;
static Param param;
static std::mutex _agent_lock;

static SR5000::CipherPrx& getCipherPrx() {
	std::lock_guard<std::mutex> lc(_agent_lock);
	return param.pPrx;
}

//virtual tars::Int32 DestroyCipher(SR5000::Ctx && ctx,SR5000::DestroyCipherReq && req,tars::TarsCurrentPtr _current_) 
//virtual tars::Int32 GenerateCipher(SR5000::Ctx && ctx,SR5000::GenerateCipherReq && req,SR5000::GenerateCipherRsq &rsp,tars::TarsCurrentPtr _current_) 
//virtual tars::Int32 GetCipher(SR5000::Ctx && ctx,SR5000::GetCipherReq && req,SR5000::GetCipherRsq &rsp,tars::TarsCurrentPtr _current_)

int start_kms_agent(int argc, char *argv[])
{
        SR5000::Ctx ctx;
	ctx.ip="0.0.0.0";
	ctx.serverName="Extended Index";
        SR5000::GenerateSecretKeyReq req;
	req.length = 32;
        SR5000::GenerateSecretKeyRsq rsp;

        int retCode=0;
	try
	{
		TC_Option option;
		option.decode(argc, argv);

		std::lock_guard<std::mutex> lc(_agent_lock);
		cout << "starting kms agent..." << endl;

		if (param.started) {
			cout << "kms agent already started." << endl;
			return 0;
		}

		_comm = new Communicator();

//		LocalRollLogger::getInstance()->logger()->setLogLevel(6);

		_comm->setProperty("sendqueuelimit", "1000000");
		_comm->setProperty("asyncqueuecap", "1000000");

		std::string matchObj = "SR5000.CipherServer.CipherObj@tcp -h 192.168.50.124 -p 20001";
		param.pPrx = _comm->stringToProxy<SR5000::CipherPrx>(matchObj);

		param.pPrx->tars_connect_timeout(50000);
		param.pPrx->tars_set_timeout(60 * 1000);
		param.pPrx->tars_async_timeout(60*1000);

		//retCode = param.pPrx->GenerateCipher(ctx, req, rsp);
		//std::cout << "start_kms_agent:ret " << retCode << "; cipherID:" << rsp.cipherInfo.cipherId << "\n";
		param.started = 1;
	
		cout << "kms agent started." << endl;
	}
	catch(exception &ex)
	{
		cout << ex.what() << endl;
	}

	return 0;
}



int generate_kms_key(int cipherLength,int& cipherID,std::string& cipher)
{
        SR5000::Ctx ctx;
        ctx.ip="0.0.0.0";
        ctx.serverName="Extended Index";
        SR5000::GenerateSecretKeyReq req;
        req.length = cipherLength>0?cipherLength:32;
        SR5000::GenerateSecretKeyRsq rsp;

        int retCode=0;
        try
        {
                retCode = getCipherPrx()->GenerateSecretKey(ctx, req, rsp);
                //std::cout << "generate_kms_key:ret " << retCode << "; keyID:" << rsp.secretKeyInfo.keyId << " key:" << kms_imp::binaryToHexPrintableSep(rsp.secretKeyInfo.content) << "\n";
        }
        catch(exception &ex)
        {
                cout << ex.what() << endl;
                return -1;
        }
        //cout << "generate_kms_key return." << endl;
        cipherID=rsp.secretKeyInfo.keyId;
        auto &c = rsp.secretKeyInfo.content;
        cipher=std::string((const char*)&c[0],c.size());
        return retCode;
}

int get_kms_key(int cipherID,std::string& cipher) {
        SR5000::Ctx ctx;
        ctx.ip="0.0.0.0";
        ctx.serverName="Extended Index";
        SR5000::GetSecretKeyReq req;
        req.keyId = cipherID;
        SR5000::GetSecretKeyRsq rsp;

        int retCode=0;
        try
        {
                retCode = getCipherPrx()->GetSecretKey(ctx, req, rsp);
                //std::cout << "get_kms_key:ret " << retCode << "; keyID:" << rsp.secretKeyInfo.keyId << " key:" << kms_imp::binaryToHexPrintableSep(rsp.secretKeyInfo.content) << "\n";
        }
        catch(exception &ex)
        {
                cout << ex.what() << endl;
                return -1;
        }
        //cout << "get_kms_key return." << endl;
        auto &c = rsp.secretKeyInfo.content;
        cipher=std::string((const char*)&c[0],c.size());
        return retCode;
}
