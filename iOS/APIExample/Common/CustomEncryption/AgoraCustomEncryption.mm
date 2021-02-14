//
//  AgoraCustomEncryption.m
//  AgoraRtcCustomizedEncryptionTutorial
//
//  Created by suleyu on 2018/7/6.
//  Copyright © 2018 Agora.io. All rights reserved.
//

#import "AgoraCustomEncryption.h"

#include <AgoraRtcKit/IAgoraRtcEngine.h>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>

static const unsigned char gcm_key[] = {
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
        0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
        0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_aad[] = {
        0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
        0x7f, 0xec, 0x78, 0xde
};

static const unsigned char gcm_tag[] = {
        0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
        0x98, 0xf7, 0x7e, 0x0c
};

class AgoraCustomEncryptionObserver : public agora::rtc::IPacketObserver
{
public:
    AgoraCustomEncryptionObserver()
    {
        m_txAudioBuffer.resize(2048);
        m_rxAudioBuffer.resize(2048);
        m_txVideoBuffer.resize(2048);
        m_rxVideoBuffer.resize(2048);
    }
    virtual bool onSendAudioPacket(Packet& packet)
    {
        EVP_CIPHER_CTX *ctx;
        int outlen;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Initialise key and IV */
        EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Encrypt plaintext */
        EVP_EncryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        /* Output encrypted block */

        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
        /* Get tag */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    virtual bool onSendVideoPacket(Packet& packet)
    {
        EVP_CIPHER_CTX *ctx;
        int outlen;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Initialise key and IV */
        EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Encrypt plaintext */
        EVP_EncryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        /* Output encrypted block */

        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
        /* Get tag */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    virtual bool onReceiveAudioPacket(Packet& packet)
    {
        EVP_CIPHER_CTX *ctx;
        int outlen, tmplen, rv;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Select cipher */
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag),
                            (void *)gcm_tag);
        rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    virtual bool onReceiveVideoPacket(Packet& packet)
    {
        EVP_CIPHER_CTX *ctx;
        int outlen, tmplen, rv;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Select cipher */
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(gcm_tag),
                            (void *)gcm_tag);
        rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
private:
    std::vector<unsigned char> m_txAudioBuffer; //buffer for sending audio data
    std::vector<unsigned char> m_txVideoBuffer; //buffer for sending video data
    
    std::vector<unsigned char> m_rxAudioBuffer; //buffer for receiving audio data
    std::vector<unsigned char> m_rxVideoBuffer; //buffer for receiving video data
};

static AgoraCustomEncryptionObserver s_packetObserver;

@implementation AgoraCustomEncryption

+ (void)registerPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit {
    if (!rtcEngineKit) {
        return;
    }
    
    agora::rtc::IRtcEngine* rtc_engine = (agora::rtc::IRtcEngine*)rtcEngineKit.getNativeHandle;
    rtc_engine->registerPacketObserver(&s_packetObserver);
}

+ (void)deregisterPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit {
    if (!rtcEngineKit) {
        return;
    }
    
    agora::rtc::IRtcEngine* rtc_engine = (agora::rtc::IRtcEngine*)rtcEngineKit.getNativeHandle;
    rtc_engine->registerPacketObserver(NULL);
}

@end
