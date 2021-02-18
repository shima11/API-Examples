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

class AgoraCustomEncryptionObserver : public agora::rtc::IPacketObserver
{
public:
    EVP_CIPHER_CTX *ctx_audio_send;
    EVP_CIPHER_CTX *ctx_audio_receive;
    EVP_CIPHER_CTX *ctx_video_send;
    EVP_CIPHER_CTX *ctx_video_receive;
    AgoraCustomEncryptionObserver()
    {
    }
    virtual bool onSendAudioPacket(Packet& packet)
    {

        int outlen;
        unsigned char outbuf[2048];
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx_audio_send, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx_audio_send, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Initialise key and IV */
        EVP_EncryptInit_ex(ctx_audio_send, NULL, NULL, gcm_key, gcm_iv);
        /* Encrypt plaintext */
        EVP_EncryptUpdate(ctx_audio_send, outbuf, &outlen, packet.buffer, packet.size);
        return true;
    }

    virtual bool onSendVideoPacket(Packet& packet)
    {

        int outlen;
        unsigned char outbuf[2048];
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx_video_send, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx_video_send, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Initialise key and IV */
        EVP_EncryptInit_ex(ctx_video_send, NULL, NULL, gcm_key, gcm_iv);
        EVP_EncryptUpdate(ctx_video_send, outbuf, &outlen, packet.buffer, packet.size);
        return true;
    }

    virtual bool onReceiveAudioPacket(Packet& packet)
    {
        int outlen;
        unsigned char outbuf[2048];
        /* Select cipher */
        EVP_DecryptInit_ex(ctx_audio_receive, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx_audio_receive, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx_audio_receive, NULL, NULL, gcm_key, gcm_iv);
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx_audio_receive, outbuf, &outlen, packet.buffer, packet.size);
        return true;
    }

    virtual bool onReceiveVideoPacket(Packet& packet)
    {
        int outlen;
        unsigned char outbuf[2048];
        /* Select cipher */
        EVP_DecryptInit_ex(ctx_video_receive, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx_video_receive, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx_video_receive, NULL, NULL, gcm_key, gcm_iv);
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx_video_receive, outbuf, &outlen, packet.buffer, packet.size);
        return true;
    }

};

static AgoraCustomEncryptionObserver s_packetObserver;

@implementation AgoraCustomEncryption

+ (void)registerPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit {
    if (!rtcEngineKit) {
        return;
    }

    agora::rtc::IRtcEngine* rtc_engine = (agora::rtc::IRtcEngine*)rtcEngineKit.getNativeHandle;
    rtc_engine->registerPacketObserver(&s_packetObserver);
    s_packetObserver.ctx_audio_send = EVP_CIPHER_CTX_new();
    s_packetObserver.ctx_video_send = EVP_CIPHER_CTX_new();
    s_packetObserver.ctx_audio_receive = EVP_CIPHER_CTX_new();
    s_packetObserver.ctx_video_receive = EVP_CIPHER_CTX_new();
}

+ (void)deregisterPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit {
    if (!rtcEngineKit) {
        return;
    }

    agora::rtc::IRtcEngine* rtc_engine = (agora::rtc::IRtcEngine*)rtcEngineKit.getNativeHandle;
    rtc_engine->registerPacketObserver(NULL);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_receive);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_receive);
}

@end
