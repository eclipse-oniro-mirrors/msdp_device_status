/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "motion_napi.h"

#include <mutex>
#include "devicestatus_define.h"
#include "fi_log.h"
#ifdef MOTION_ENABLE
#include "motion_client.h"
#include "napi_event_utils.h"
#endif
#include "motion_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "DeviceMotionNapi"

namespace OHOS {
namespace Msdp {
namespace {
#ifdef MOTION_ENABLE
auto &g_motionClient = MotionClient::GetInstance();
constexpr int32_t PERMISSION_DENIED = 201;
static constexpr uint8_t ARG_1 = 1;
constexpr int32_t HOLDING_HAND_FEATURE_DISABLE = 11;
constexpr int32_t EVENT_NOT_SUPPORT = -200;
constexpr int32_t EVENT_NO_INITIALIZE = -1;
static int64_t processorId = -1;
#endif
static constexpr uint8_t ARG_0 = 0;
static constexpr uint8_t ARG_2 = 2;
constexpr int32_t INVALID_MOTION_TYPE = -1;
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t MOTION_TYPE_OPERATING_HAND = 3601;
constexpr int32_t MOTION_TYPE_STAND = 3602;
constexpr int32_t MOTION_TYPE_REMOTE_PHOTO = 3604;
constexpr int32_t MOTION_TYPE_HOLDING_HAND_STATUS = 3605;
constexpr int32_t BASE_HAND = 0;
constexpr int32_t LEFT_HAND = 1;
constexpr int32_t RIGHT_HAND = 2;
enum HoldPostureStatus : int32_t {
    NOT_HELD = 0,
    LEFT_HAND_HELD,
    RIGHT_HAND_HELD,
    BOTH_HAND_HELD,
    UNKNOWN = 16,
};
const std::vector<std::string> EXPECTED_SUB_ARG_TYPES = { "string", "function" };
const std::vector<std::string> EXPECTED_UNSUB_ONE_ARG_TYPES = { "string" };
const std::vector<std::string> EXPECTED_UNSUB_TWO_ARG_TYPES = { "string", "function" };
const std::map<const std::string, int32_t> MOTION_TYPE_MAP = {
    { "operatingHandChanged", MOTION_TYPE_OPERATING_HAND },
    { "steadyStandingDetect", MOTION_TYPE_STAND },
    { "remotePhotoStandingDetect", MOTION_TYPE_REMOTE_PHOTO },
    { "holdingHandChanged", MOTION_TYPE_HOLDING_HAND_STATUS },
};
MotionNapi *g_motionObj = nullptr;
} // namespace

std::mutex g_mutex;

#ifdef MOTION_ENABLE
void MotionCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> guard(g_mutex);
    auto* data = new (std::nothrow) MotionEvent();
    CHKPV(data);
    data->type = event.type;
    data->status = event.status;
    data->dataLen = event.dataLen;
    data->data = event.data;

    auto task = [data]() {
        FI_HILOGI("Execute lamdba");
        EmitOnEvent(data);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
        delete data;
    }
    FI_HILOGD("Exit");
}

void MotionCallback::EmitOnEvent(MotionEvent* data)
{
    if (data == nullptr) {
        FI_HILOGE("data is nullptr");
        return;
    }

    if (g_motionObj == nullptr) {
        FI_HILOGE("Failed to get g_motionObj");
        delete data;
        return;
    }
    g_motionObj->OnEventOperatingHand(data->type, 1, *data);
    delete data;
}
#endif

MotionNapi::MotionNapi(napi_env env, napi_value thisVar) : MotionEventNapi(env, thisVar)
{
    env_ = env;
}

MotionNapi::~MotionNapi()
{}

int32_t MotionNapi::GetMotionType(const std::string &type)
{
    FI_HILOGD("Enter");
    auto iter = MOTION_TYPE_MAP.find(type);
    if (iter == MOTION_TYPE_MAP.end()) {
        FI_HILOGD("Don't find this type");
        return INVALID_MOTION_TYPE;
    }
    FI_HILOGD("Exit");
    return iter->second;
}

#ifdef MOTION_ENABLE
bool MotionNapi::SubscribeCallback(napi_env env, int32_t type)
{
    if (g_motionObj == nullptr) {
        ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "g_motionObj is nullptr");
        return false;
    }

    auto iter = g_motionObj->callbacks_.find(type);
    if (iter == g_motionObj->callbacks_.end()) {
        FI_HILOGD("Don't find callback, to create");
        sptr<IMotionCallback> callback = new (std::nothrow) MotionCallback(env);
        int32_t ret = g_motionClient.SubscribeCallback(type, callback);
        if (ret == RET_OK) {
            g_motionObj->callbacks_.insert(std::make_pair(type, callback));
            return true;
        }

        if (ret == PERMISSION_DENIED) {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, PERMISSION_EXCEPTION, "Permission denined");
            return false;
        } else if (ret == DEVICE_EXCEPTION || ret == HOLDING_HAND_FEATURE_DISABLE) {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
            return false;
        } else {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
            return false;
        }
    }
    return true;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value MotionInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = MotionNapi::Init(env, exports);
    if (ret == nullptr) {
        FI_HILOGE("Failed to init");
        return ret;
    }
    FI_HILOGD("Exit");
    return ret;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.motion",
    .nm_register_func = MotionInit,
    .nm_modname = "multimodalAwareness.motion",
    .nm_priv = (static_cast<void *>(nullptr)),
    .reserved = { nullptr }
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace Msdp
} // namespace OHOS
