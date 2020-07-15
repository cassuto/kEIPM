#ifndef API_H_
#define API_H_

#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rootCa_inf{
    const char* Root_Common_name;
    const char* Root_Org_name;
    const char* Root_Local;
    const char* Root_State;
    const char* Root_Country;
    int days;
}RootCa;

typedef struct UserCa_inf{
    const char* User_Common_name;
    const char* User_Org_name;
    const char* User_Local;
    const char* User_State;
    const char* User_Country;
    const char* User_input_RootCA_Path;
    int days;
}UserCa;


/**
 * @brief 进行证书签名
 * @param [in] UserCA_Path 用户证书路径文件名
 * @param [in] elf_Path elf路径文件名
*/
extern keipm_err_t keipm_set_UserCA(const char* UserCA_Path,const char* elf_Path);

/**
 * @brief 进行秘钥签名
 * @param [in] prikey_path 用户私钥文件路径名
 * @param [in] elf_path elf路径文件名
*/
extern keipm_err_t keipm_set_Key(const char* prikey_path,const char* elf_path);

/**
 * @brief 生成私钥
 * @param [in] const char* 私钥文件路径地址名
 * @return [out] error 错误结构体
*/
extern keipm_err_t keipm_create_PrivateKey(const char *privateKeyPath);

/**
 * @brief 生成公钥
 * @param [in] error 错误结构体
 * @param [in] privateKeyPath 私钥文件路径地址名
 * @return [out] const char* 公钥文件路径地址名
*/
extern keipm_err_t keipm_create_PublicKey(const char* publicKeyPath, const char* privateKeyPath);

/**
 * @brief 生成根证书
 * @param [in] error 错误结构体
 * @param [in] rootca 根证书信息结构体
 * @return [out] const char* 根证书文件路径地址名
*/
extern keipm_err_t keipm_create_rootCA(const char *rootCA_Path, const RootCa *rootca);

/**
 * @brief 生成用户证书
 * @param [in] const char* 用户证书文件路径地址名
 * @param [in] rootca 用户证书信息结构体
 * @return [out] error 错误结构体
*/
extern keipm_err_t keipm_create_userCA(const char *out_cert_path, const char *ca_key_path, const UserCa *userca);


#ifdef __cplusplus
}
#endif

#endif // API_H_
