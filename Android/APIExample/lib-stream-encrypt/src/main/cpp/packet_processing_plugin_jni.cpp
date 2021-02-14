#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <vector>
#include <algorithm>

#include "./include/agora/IAgoraMediaEngine.h"
#include "./include/agora/IAgoraRtcEngine.h"

#include "./include/packet_processing_plugin_jni.h"

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

/**stream data frame listener*/
class AgoraRTCPacketObserver : public agora::rtc::IPacketObserver
{
public:
    AgoraRTCPacketObserver()
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "AgoraRTCPacketObserver0");
        m_txAudioBuffer.resize(2048);
        m_rxAudioBuffer.resize(2048);
        m_txVideoBuffer.resize(2048);
        m_rxVideoBuffer.resize(2048);
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "AgoraRTCPacketObserver1");
    }

    /**Occurs when the local user sends an audio packet.
     * @param packet The sent audio packet.
     * @return
     *   true: The audio packet is sent successfully.
     *   false: The audio packet is discarded.*/
    virtual bool onSendAudioPacket(Packet &packet)
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "onSendAudioPacket0");
        EVP_CIPHER_CTX *ctx;
        int outlen;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
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
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    /**Occurs when the local user sends a video packet.
     * @param packet The sent video packet.
     * @return
     *   true: The video packet is sent successfully.
     *   false: The video packet is discarded.*/
    virtual bool onSendVideoPacket(Packet &packet)
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "onSendAudioPacket1%d", 1);
        EVP_CIPHER_CTX *ctx;
        int outlen;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Set cipher type and mode */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length if default 96 bits is not appropriate */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
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
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    /**Occurs when the local user receives an audio packet.
     * @param packet The received audio packet.
     * @return
     *   true: The audio packet is received successfully.
     *   false: The audio packet is discarded.*/
    virtual bool onReceiveAudioPacket(Packet &packet)
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "onReceiveAudioPacket0");
        EVP_CIPHER_CTX *ctx;
        int outlen, tmplen, rv;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Select cipher */
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag),
                            (void *)gcm_tag);
        rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    /**Occurs when the local user receives a video packet.
     * @param packet The received video packet.
     * @return
     *   true: The video packet is received successfully.
     *   false: The video packet is discarded.*/
    virtual bool onReceiveVideoPacket(Packet &packet)
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "onReceiveAudioPacket1");
        EVP_CIPHER_CTX *ctx;
        int outlen, tmplen, rv;
        unsigned char outbuf[2048];
        ctx = EVP_CIPHER_CTX_new();
        /* Select cipher */
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        /* Set IV length, omit for 96 bits */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
        /* Specify key and IV */
        EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
        /* Zero or more calls to specify any AAD */
        EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad));
        /* Decrypt plaintext */
        EVP_DecryptUpdate(ctx, outbuf, &outlen, packet.buffer, packet.size);
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(gcm_tag),
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

static AgoraRTCPacketObserver s_packetObserver;

static agora::rtc::IRtcEngine *rtcEngine = NULL;

#ifdef __cplusplus
extern "C" {
#endif

/**When the so package is successfully loaded, the SDK will automatically find and load this function;
 * therefore, the function name, parameters, and return value cannot be changed at will.*/
int __attribute__((visibility("default"))) loadAgoraRtcEnginePlugin(agora::rtc::IRtcEngine *engine)
{
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "loadAgoraRtcEnginePlugin");
    rtcEngine = engine;
    // if do registerPacketObserver here, SDK may return -7(ERR_NOT_INITIALIZED)
    return 0;
}

void __attribute__((visibility("default")))
unloadAgoraRtcEnginePlugin(agora::rtc::IRtcEngine *engine)
{
    rtcEngine = NULL;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK)
    {
        return result;
    }

    assert(env != NULL);
    result = JNI_VERSION_1_6;
    return result;
}

JNIEXPORT void JNICALL
Java_io_agora_api_streamencrypt_PacketProcessor_doRegisterProcessing
        (JNIEnv *env, jobject obj)
{
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "doRegisterProcessing0");
    if (!rtcEngine) return;
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "doRegisterProcessing1");
    /**Registers a packet observer.
     * The Agora SDK allows your application to register a packet observer to receive callbacks for
     * voice or video packet transmission.
     * @param obsrver Pointer to the registered packet observer.
     * @return
     *   0: Success.
     *   < 0: Failure.
     * PS:
     *   The size of the packet sent to the network after processing should not exceed 1200 bytes,
     *      otherwise, the packet may fail to be sent.
     *   Ensure that both receivers and senders call this method, otherwise, you may meet undefined
     *      behaviors such as no voice and black screen.
     *   When you use CDN live streaming, recording or storage functions, Agora doesn't recommend
     *      calling this method.*/
    int code = rtcEngine->registerPacketObserver(&s_packetObserver);
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "%d", code);
}

JNIEXPORT void JNICALL
Java_io_agora_api_streamencrypt_PacketProcessor_doUnregisterProcessing
        (JNIEnv *env, jobject obj)
{
    if (!rtcEngine) return;
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "doUnregisterProcessing");
    rtcEngine->registerPacketObserver(nullptr);
}

#ifdef __cplusplus
}
#endif