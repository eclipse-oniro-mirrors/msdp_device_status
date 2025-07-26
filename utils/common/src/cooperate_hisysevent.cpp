/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
    
#include "cooperate_hisysevent.h"
    
#include "hisysevent.h"
#include "fi_log.h"
    
#undef LOG_TAG
#define LOG_TAG "CooperateHisysevent"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    const std::string COOPERTATE_BEHAVIOR { "COOPERTATE_BEHAVIOR" };
    const std::string ORG_PKG_NAME { "device_status" };
} // namespace
    
void CooperateRadar::ReportCooperateRadarInfo(struct CooperateRadarInfo &cooperateRadarInfo)
{
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        COOPERTATE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORG_PKG_NAME,
        "FUNC", cooperateRadarInfo.funcName,
        "BIZ_STATE", cooperateRadarInfo.bizState,
        "BIZ_STAGE", cooperateRadarInfo.bizStage,
        "STAGE_RES", cooperateRadarInfo.stageRes,
        "BIZ_SCENE", cooperateRadarInfo.bizScene,
        "ERROR_CODE", cooperateRadarInfo.errCode,
        "HOST_PKG", cooperateRadarInfo.hostName,
        "LOCAL_NET_ID", cooperateRadarInfo.localNetId,
        "PEER_NET_ID", cooperateRadarInfo.peerNetId,
        "TO_CALL_PKG", cooperateRadarInfo.toCallPkg,
        "LOCAL_DEV_TYPE", cooperateRadarInfo.localDeviceType,
        "PEER_DEV_TYPE", cooperateRadarInfo.peerDeviceType);
}

void CooperateRadar::ReportTransmissionLatencyRadarInfo(
    struct TransmissionLatencyRadarInfo &transmissionLatencyRadarInfo)
{
    if (transmissionLatencyRadarInfo.stageRes < 0) {
        FI_HILOGE("Transmission latency HiSysEventWrite fail");
        return;
    } else {
        FI_HILOGD("Transmission latency HiSysEventWrite success");
    }
    HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        COOPERTATE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORG_PKG_NAME,
        "FUNC", transmissionLatencyRadarInfo.funcName,
        "BIZ_STATE", transmissionLatencyRadarInfo.bizState,
        "BIZ_STAGE", transmissionLatencyRadarInfo.bizStage,
        "STAGE_RES", transmissionLatencyRadarInfo.stageRes,
        "BIZ_SCENE", transmissionLatencyRadarInfo.bizScene,
        "LOCAL_NET_ID", transmissionLatencyRadarInfo.localNetId,
        "PEER_NET_ID", transmissionLatencyRadarInfo.peerNetId,
        "DRIVE_EVENT_DT", transmissionLatencyRadarInfo.driveEventTimeDT,
        "COOPERATE_INTERCEPTOR_EVENT_DT", transmissionLatencyRadarInfo.cooperateInterceptorTimeDT,
        "CROSS_PLATFORM_EVENT", transmissionLatencyRadarInfo.crossPlatformTimeDT,
        "POINTER_SPEED_EVENT", transmissionLatencyRadarInfo.pointerSpeed,
        "TOUCHPAD_SPEED_EVET", transmissionLatencyRadarInfo.touchPadSpeed);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
