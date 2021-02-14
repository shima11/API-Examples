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

/**stream data frame listener*/
class AgoraRTCPacketObserver : public agora::rtc::IPacketObserver
{
public:
    EVP_CIPHER_CTX *ctx_audio_send;
    EVP_CIPHER_CTX *ctx_audio_receive;
    EVP_CIPHER_CTX *ctx_video_send;
    EVP_CIPHER_CTX *ctx_video_receive;
    AgoraRTCPacketObserver()
    {
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "AgoraRTCPacketObserver0");
        m_txAudioBuffer.resize(2048);
        m_rxAudioBuffer.resize(2048);
        m_txVideoBuffer.resize(2048);
        m_rxVideoBuffer.resize(2048);
        __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "AgoraRTCPacketObserver1");
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
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
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
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
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
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
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
        //assign new buffer and the length back to SDK
        packet.buffer = outbuf;
        packet.size = outlen;
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
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_receive);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_receive);
}

JNIEXPORT void JNICALL
Java_io_agora_api_streamencrypt_PacketProcessor_doUnregisterProcessing
        (JNIEnv *env, jobject obj)
{
    if (!rtcEngine) return;
    __android_log_print(ANDROID_LOG_INFO, "agoraencryption", "doUnregisterProcessing");
    rtcEngine->registerPacketObserver(nullptr);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_send);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_audio_receive);
    EVP_CIPHER_CTX_free(s_packetObserver.ctx_video_receive);
}

#ifdef __cplusplus
}
#endif