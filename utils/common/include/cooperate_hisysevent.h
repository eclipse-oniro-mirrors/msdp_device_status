/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

    
#ifndef COOPERATE_HISYSEVENT_H
#define COOPERATE_HISYSEVENT_H
    
#include <string>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
    
enum class BizCooperateScene {
    SCENE_ACTIVE = 1,
    SCENE_PASSIVE
};
    
    
enum class BizCooperateStageRes {
    RES_IDLE = 0,
    RES_SUCCESS,
    RES_FAIL
};
    
enum class BizCooperateStage {
    STAGE_CALLING_COOPERATE = 0,
    STAGE_CHECK_SAME_ACCOUNT,
    STAGE_CHECK_LOCAL_SWITCH,
    STAGE_CHECK_ALLOW_COOPERATE,
    STAGE_OPEN_DSOFTBUS_SESSION,
    STAGE_CHECK_UNECPECTED_CALLING,
    STAGE_SERIALIZE_INSTRUCTION,
    STAGE_SEND_INSTRUCTION_TO_REMOTE,
    STAGE_ADD_MMI_EVENT_INTERCEPOR,
    STAGE_SWITCH_STATE_MACHINE,
    STAGE_SET_CURSOR_VISIBILITY,
    STAGE_SRV_EVENT_MGR_NOTIFY,
    STAGE_CLIENT_ON_MESSAGE_RCVD
};
    
enum class CooperateRadarErrCode {
    CALLING_COOPERATE_SUCCESS = 0,
    CHECK_SAME_ACCOUNT_FAILED = 20900006,
    CHECK_LOCAL_SWITCH_FAILED,
    CHECK_ALLOW_COOPERATE_FAILED,
    OPEN_DSOFTBUS_SESSION_FAILED,
    CHECK_UNECPECTED_CALLING_FAILED,
    SERIALIZE_INSTRUCTION_FAILED,
    SEND_INSTRUCTION_TO_REMOTE_FAILED,
    ADD_MMI_EVENT_INTERCEPOR_FAILED,
    SWITCH_STATE_MACHINE_FAILED,
    SET_CURSOR_VISIBILITY_FAILED,
    SRV_EVENT_MGR_NOTIFY_FAILED,
    CLIENT_ON_MESSAGE_RCVD_FAILED
};
    
struct CooperateRadarInfo {
    std::string funcName;
    int32_t bizScene { -1 };
    int32_t bizState { -1 };
    int32_t bizStage { -1 };
    int32_t stageRes { -1 };
    int32_t errCode { -1 };
    std::string hostName;
    std::string localNetId;
    std::string peerNetId;
};

class CooperateRadar {
public:
    static void ReportCooperateRadarInfo(struct CooperateRadarInfo &cooperateRadarInfo);
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_HISYSEVENT_H
