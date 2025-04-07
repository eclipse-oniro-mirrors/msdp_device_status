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

#include "device_status_napi.h"

#include <mutex>

#include "devicestatus_define.h"
#include "device_status_napi_error.h"
#include "fi_log.h"
#include "stationary_manager.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusV1Napi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
namespace {
static constexpr uint8_t ARG_0 = 0;
static constexpr uint8_t ARG_1 = 1;
static constexpr uint8_t ARG_2 = 2;
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t STATUS_ENTER = 1;
constexpr int32_t STATUS_EXIT = 0;
const std::vector<std::string> EXPECTED_SUB_ARG_TYPES = { "string", "function" };
const std::vector<std::string> EXPECTED_UNSUB_ONE_ARG_TYPES = { "string" };
const std::vector<std::string> EXPECTED_UNSUB_TWO_ARG_TYPES = { "string", "function" };
const std::map<const std::string, DeviceStatus::Type> DEVICE_STATUS_TYPE_MAP = {
    { "steadyStandingDetect", DeviceStatus::Type::TYPE_STAND },
};
DeviceStatusNapi *g_deviceStatusObj = nullptr;
std::mutex g_mutex;
} // namespace

void DeviceStatusCallback::OnDeviceStatusChanged(const DeviceStatus::Data &event)
{
    FI_HILOGD("Enter");
    DeviceStatus::Data data;
    // 这里只用类型和当前回调值
    data.type = event.type;
    data.value = event.value;

    auto task = [data]() {
        FI_HILOGI("Execute lamdba");
        EmitOnEvent(data);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to SendEvent");
    }
    FI_HILOGD("Exit");
}

void DeviceStatusCallback::EmitOnEvent(DeviceStatus::Data data)
{
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_deviceStatusObj == nullptr) {
        FI_HILOGE("Failed to get g_deviceStatusObj");
        return;
    }
    g_deviceStatusObj->OnEvent(data.type, 1, data);
}

DeviceStatusNapi::DeviceStatusNapi(napi_env env, napi_value thisVar) : DeviceStatusNapiEvent(env, thisVar)
{
    env_ = env;
}

DeviceStatusNapi::~DeviceStatusNapi()
{}

DeviceStatus::Type DeviceStatusNapi::GetDeviceStatusType(const std::string &type)
{
    FI_HILOGD("Enter");
    auto iter = DEVICE_STATUS_TYPE_MAP.find(type);
    if (iter == DEVICE_STATUS_TYPE_MAP.end()) {
        FI_HILOGD("Don't find this type");
        return DeviceStatus::Type::TYPE_INVALID;
    }
    FI_HILOGD("Exit");
    return iter->second;
}

bool DeviceStatusNapi::SubscribeCallback(napi_env env, DeviceStatus::Type type)
{
    if (g_deviceStatusObj == nullptr) {
        ThrowDeviceStatusErr(env, SUBSCRIBE_EXCEPTION, "g_deviceStatusObj is nullptr");
        return false;
    }

    auto iter = g_deviceStatusObj->callbacks_.find(type);
    int32_t ret = RET_OK;
    if (iter == g_deviceStatusObj->callbacks_.end()) {
        FI_HILOGD("Don't find callback, to create");
        sptr<DeviceStatus::IRemoteDevStaCallback> callback = new (std::nothrow) DeviceStatusCallback(env);
        ret = DeviceStatus::StationaryManager::GetInstance()->SubscribeCallback(type,
            DeviceStatus::ActivityEvent::EVENT_INVALID, DeviceStatus::ReportLatencyNs::Latency_INVALID, callback);
        if (ret == RET_OK) {
            g_deviceStatusObj->callbacks_.insert(std::make_pair(type, callback));
            return true;
        }
    } else {
        ret = DeviceStatus::StationaryManager::GetInstance()->SubscribeCallback(type,
            DeviceStatus::ActivityEvent::EVENT_INVALID, DeviceStatus::ReportLatencyNs::Latency_INVALID, iter->second);
        if (ret == RET_OK) {
            FI_HILOGI("repeat invoke motion to report cache data");
            return true;
        }
    }
    if (ret == DEVICE_EXCEPTION) {
        FI_HILOGE("failed to subscribe");
        ThrowDeviceStatusErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    } else {
        FI_HILOGE("failed to subscribe");
        ThrowDeviceStatusErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
        return false;
    }
    return true;
}

bool DeviceStatusNapi::UnsubscribeCallback(napi_env env, DeviceStatus::Type type)
{
    if (g_deviceStatusObj == nullptr) {
        ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "g_deviceStatusObj is nullptr");
        return false;
    }

    if (g_deviceStatusObj->CheckEvents(type)) {
        auto iter = g_deviceStatusObj->callbacks_.find(type);
        if (iter == g_deviceStatusObj->callbacks_.end()) {
            FI_HILOGE("faild to find callback");
            ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
            return false;
        }
        int32_t ret = DeviceStatus::StationaryManager::GetInstance()->UnsubscribeCallback(
            type, DeviceStatus::ActivityEvent::EVENT_INVALID, iter->second);
        if (ret == RET_OK) {
            g_deviceStatusObj->callbacks_.erase(iter);
            return true;
        }

        if (ret == DEVICE_EXCEPTION) {
            FI_HILOGE("failed to unsubscribe");
            ThrowDeviceStatusErr(env, DEVICE_EXCEPTION, "Device not support");
            return false;
        } else {
            FI_HILOGE("failed to unsubscribe");
            ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
            return false;
        }
    }
    return false;
}

bool DeviceStatusNapi::ConstructDeviceStatus(napi_env env, napi_value jsThis)
{
    if (g_deviceStatusObj == nullptr) {
        g_deviceStatusObj = new (std::nothrow) DeviceStatusNapi(env, jsThis);
        if (g_deviceStatusObj == nullptr) {
            FI_HILOGE("faild to get g_deviceStatusObj");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_deviceStatusObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    DeviceStatusNapi *deviceStatus = reinterpret_cast<DeviceStatusNapi *>(data);
                    delete deviceStatus;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_deviceStatusObj;
            g_deviceStatusObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

napi_value DeviceStatusNapi::SubscribeDeviceStatus(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowDeviceStatusErr(env, SUBSCRIBE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

    if (!ValidateArgsType(env, args, argc, EXPECTED_SUB_ARG_TYPES)) {
        ThrowDeviceStatusErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }

    std::string typeStr;
    if (!TransJsToStr(env, args[ARG_0], typeStr)) {
        ThrowDeviceStatusErr(env, SUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }

    DeviceStatus::Type type = GetDeviceStatusType(typeStr);
    if (type == DeviceStatus::Type::TYPE_INVALID) {
        ThrowDeviceStatusErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        if (!ConstructDeviceStatus(env, jsThis)) {
            ThrowDeviceStatusErr(env, SUBSCRIBE_EXCEPTION, "Failed to get g_deviceStatusObj");
            return nullptr;
        }

        if (!SubscribeCallback(env, type)) {
            return nullptr;
        }

        if (!g_deviceStatusObj->AddCallback(type, args[ARG_1])) {
            ThrowDeviceStatusErr(env, SERVICE_EXCEPTION, "AddCallback failed, probably repeat subscribe");
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceStatusNapi::UnsubscribeDeviceStatus(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    if (g_deviceStatusObj == nullptr) {
        ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "g_deviceStatusObj is nullptr");
        return nullptr;
    }

    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_cb_info is failed");
        return nullptr;
    }

    auto expectedArgs = EXPECTED_UNSUB_TWO_ARG_TYPES;
    if (argc != ARG_2) {
        expectedArgs = EXPECTED_UNSUB_ONE_ARG_TYPES;
    }
    if (!ValidateArgsType(env, args, argc, expectedArgs)) {
        ThrowDeviceStatusErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }

    std::string typeStr;
    if (!TransJsToStr(env, args[ARG_0], typeStr)) {
        ThrowDeviceStatusErr(env, UNSUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }

    DeviceStatus::Type type = GetDeviceStatusType(typeStr);
    if (type == DeviceStatus::Type::TYPE_INVALID) {
        ThrowDeviceStatusErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        bool retRemove = argc == ARG_2 ?
            g_deviceStatusObj->RemoveCallback(type, args[ARG_1]) : g_deviceStatusObj->RemoveCallback(type);
        if (!retRemove) {
            ThrowDeviceStatusErr(env, SERVICE_EXCEPTION, "RemoveCallback failed");
            return nullptr;
        }

        if (!UnsubscribeCallback(env, type)) {
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
}

napi_value DeviceStatusNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", SubscribeDeviceStatus),
        DECLARE_NAPI_STATIC_FUNCTION("off", UnsubscribeDeviceStatus),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc)/sizeof(desc[0]), desc));

    napi_value napiStatus;
    napi_status status = napi_create_object(env, &napiStatus);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return exports;
    }

    SetInt32Property(env, napiStatus, STATUS_ENTER, "STATUS_ENTER");
    SetInt32Property(env, napiStatus, STATUS_EXIT, "STATUS_EXIT");
    SetPropertyName(env, exports, "SteadyStandingStatus", napiStatus);
    FI_HILOGD("Exit");
    return exports;
}

void DeviceStatusNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DeviceStatusNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return;
    }
}

bool DeviceStatusNapi::ValidateArgsType(napi_env env, napi_value *args, size_t argc,
    const std::vector<std::string> &expectedTypes)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;

    if (argc != expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }

    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking arguments types");
            return false;
        }
        std::string expectedType = expectedTypes[i];
        if ((expectedType == "string" && valueType != napi_string) ||
            (expectedType == "function" && valueType != napi_function)) {
                FI_HILOGE("Wrong argument type");
                return false;
        }
    }
    return true;
}

bool DeviceStatusNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen < 0 || strlen > MAX_ARG_STRING_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strlen + 1);
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen+1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str = buf.data();
    return true;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value DeviceStatusInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = DeviceStatusNapi::Init(env, exports);
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
    .nm_filename = "multimodalAwareness.deviceStatus",
    .nm_register_func = DeviceStatusInit,
    .nm_modname = "multimodalAwareness.deviceStatus",
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
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
