//
//  AgoraCustomEncryption.h
//  AgoraRtcCustomizedEncryptionTutorial
//
//  Created by suleyu on 2018/7/6.
//  Copyright © 2018 Agora.io. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AgoraRtcKit/AgoraRtcEngineKit.h>

#include <openssl/bio.h>
#include <openssl/evp.h>


@interface AgoraCustomEncryption : NSObject

+ (void)registerPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit;

+ (void)deregisterPacketProcessing:(AgoraRtcEngineKit *)rtcEngineKit;

@end
