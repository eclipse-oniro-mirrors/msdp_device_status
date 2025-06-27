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

#include <vector>
#include <ipc_skeleton.h>
#include "bundle_mgr_proxy.h"
#include <bundle_mgr_interface.h>
#include "iservice_registry.h"

#include "fi_log.h"
#include "room_location_napi.h"
#include "room_location_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "RoomLocationNapi"

namespace OHOS {
namespace Msdp {
namespace {
RoomLocationNapi* g_RoomLocationNapi; // RoomLocationNapi manager
const std::vector<std::string> EXPECTED_ON_ARG_TYPES_R1 = {"string"};
const std::vector<std::string> EXPECTED_ON_ARG_TYPES_R2 = {"string", "function"};
const std::string_view GETROOMRESDATA_FUNC_NAME = { "GetRoomResData" };
const std::string_view SETDEVICEINFOS_FUNC_NAME = { "SetDeviceInfos" };
const std::string_view SUBSCRIBE_FUNC_NAME = { "SubscribeRoomLocation" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "UnsubscribeRoomLocation" };
const std::string ROOM_LOCATION_CLIENT_SO_PATH = "libspatial_awareness_client.z.so";
const std::string INVALID_ID = "-1";
const int32_t INVALID_ID_ERRCODE = -1;
const std::string ROOM_LOCATION_TYPE = "onRoomLocated";
const int32_t SUCCESS_FLAG = 1;
constexpr size_t MAX_ARG_STRING_LEN = 512;
const size_t KEEP_LEFT = 2;
const size_t KEEP_RIGHT = 4;
const char STR_MASK_CHAR = '*';
constexpr int32_t NAPI_INDEX_ZERO = 0;
constexpr int32_t NAPI_INDEX_ONE = 1;
constexpr int32_t NAPI_INDEX_TWO = 2;
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
} // namespace

std::mutex g_mutex;
std::shared_ptr<OHOS::Msdp::IRoomLocationListener> RoomLocationNapi::roomCallback_ = nullptr;

std::string MaskId(const char* inputChar)
{
    std::string inputStr(inputChar);
    size_t len = inputStr.length();
    if (len <= KEEP_LEFT + KEEP_RIGHT) {
        FI_HILOGI("inputStr len < KEEP_LEFT + KEEP_RIGHT, all are masked");
        return std::string(len, STR_MASK_CHAR);
    }

    size_t maskLength = len - KEEP_LEFT - KEEP_RIGHT;
    return inputStr.substr(0, KEEP_LEFT) +
           std::string(maskLength, STR_MASK_CHAR) +
           inputStr.substr(len - KEEP_RIGHT);
}

bool RoomLocationNapi::LoadLibrary()
{
    if (g_RoomLocationNapi->g_roomLocationHandle == nullptr) {
        g_RoomLocationNapi->g_roomLocationHandle = dlopen(ROOM_LOCATION_CLIENT_SO_PATH.c_str(), RTLD_LAZY);
        if (g_RoomLocationNapi->g_roomLocationHandle == nullptr) {
            FI_HILOGE("Load failed, error after: %{public}s", dlerror());
            return false;
        }
    }
    FI_HILOGI("Load library success");
    return true;
}

RoomLocationNapi *RoomLocationNapi::GetRoomLocationNapi()
{
    return g_RoomLocationNapi;
}

napi_value RoomLocationNapi::ModeInit(napi_env env, napi_value exports)
{
    FI_HILOGI("Enter");
    napi_value obj = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &obj);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create object");
        return result;
    }
    status = napi_set_named_property(env, exports, "RoomLocation", obj);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return result;
    }
    FI_HILOGI("Exit");
    return exports;
}

void RoomLocationNapi::SetValueUtf8String(const napi_env &env,
    const std::string &fieldStr, const std::string &str, napi_value &result)
{
    napi_handle_scope scope = nullptr;
    RoomLocationNapiFuncScope napiFuncHand(env, scope);
    napi_value value = nullptr;
    if (napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &value) == napi_ok) {
        napi_status status = napi_set_named_property(env, result, fieldStr.c_str(), value);
        if (status != napi_ok) {
            FI_HILOGE("Failed to set the named property");
            return;
        }
    }
}

void RoomLocationNapi::SetValueInt32(const napi_env &env, const std::string &fieldStr,
    const int32_t intValue, napi_value &result)
{
    napi_handle_scope scope = nullptr;
    RoomLocationNapiFuncScope napiFuncHand(env, scope);
    napi_value value = nullptr;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create int32");
        return;
    }
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the fieldStr named property");
        return;
    }
}

bool RoomLocationNapi::ConstructRoomLocation(napi_env env, napi_value jsThis) __attribute__((no_sanitize("cfi")))
{
    if (g_RoomLocationNapi == nullptr) {
        g_RoomLocationNapi = new(std::nothrow) RoomLocationNapi(env, jsThis);
        if (g_RoomLocationNapi == nullptr) {
            FI_HILOGE("g_RoomLocationNapi is nullptr");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_RoomLocationNapi),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    RoomLocationNapi *spatial = static_cast<RoomLocationNapi *>(data);
                    g_RoomLocationNapi->ClearEnv();
                    delete spatial;
                    g_RoomLocationNapi = nullptr;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_RoomLocationNapi;
            g_RoomLocationNapi = nullptr;
            FI_HILOGE("Failed to napi_wrap");
            return false;
        }
    }
    return true;
}

bool RoomLocationNapi::GetInfos(napi_env env, napi_value strValue, std::string &strInfos)
{
    size_t count = 0;
    napi_status status = napi_get_value_string_utf8(env, strValue, nullptr, 0, &count);
    if (status != napi_ok) {
        FI_HILOGE("strInfos get string length failed");
        return false;
    }

    char* str = new char[count + 1];
    status = napi_get_value_string_utf8(env, strValue, str, count + 1, &count);
    if (status != napi_ok) {
        FI_HILOGE("str get element failed");
        delete[] str;
        return false;
    }
    strInfos = std::string(str);
    delete[] str;

    if (strInfos.length() == 0) {
        FI_HILOGE("strInfos str invalid");
        return false;
    }
    return true;
}

bool RoomLocationNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen > MAX_ARG_STRING_LEN) {
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

bool RoomLocationNapi::GetRoomLocationType(const std::string &type)
{
    FI_HILOGD("Enter");
    if (type == ROOM_LOCATION_TYPE) {
        return true;
    }
    FI_HILOGE("Don't find this type");
    return false;
}

bool RoomLocationNapi::ValidateArgsTypeRoom(napi_env env, napi_value *args, size_t argc)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;
    std::vector<std::string> expectedTypes;

    if (argc == NAPI_INDEX_ONE) {
        expectedTypes = EXPECTED_ON_ARG_TYPES_R1;
    } else if (argc == NAPI_INDEX_TWO) {
        expectedTypes = EXPECTED_ON_ARG_TYPES_R2;
    }

    if (argc != expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }

    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking argument types");
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

void RoomLocationNapi::DeviceExecuteCB(napi_env env, void* data)
{
    FI_HILOGD("Enter");
    int32_t ret = 0;
    DevicesInfosCallbackData* devicesInfosCallbackData = static_cast<DevicesInfosCallbackData*>(data);
    std::string deviceInfos = devicesInfosCallbackData->deviceInfos;

    if (g_RoomLocationNapi == nullptr) {
        ThrowErr(env, SETINOFS_EXCEPTION, "g_RoomLocationNapi is nullptr");
        return;
    }

    if (g_RoomLocationNapi->g_setDeviceInfosFunc == nullptr) {
        g_RoomLocationNapi->g_setDeviceInfosFunc = reinterpret_cast<SetDeviceInfosFunc>(
            dlsym(g_RoomLocationNapi->g_roomLocationHandle, SETDEVICEINFOS_FUNC_NAME.data()));
        if (g_RoomLocationNapi->g_setDeviceInfosFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s",
                SETDEVICEINFOS_FUNC_NAME.data(), dlerror());
            return;
        }
    }
    ret = g_RoomLocationNapi->g_setDeviceInfosFunc(deviceInfos.c_str());
    if (ret != napi_ok) {
        FI_HILOGE("napi error, ret is %{public}d", ret);
    } else {
        devicesInfosCallbackData->isSuccess = SUCCESS_FLAG;
    }
    FI_HILOGI("devicesInfosCallbackData->isSuccess = %{public}s",
        devicesInfosCallbackData->isSuccess == SUCCESS_FLAG ? "true" : "false");
}

void RoomLocationNapi::DeviceCompleteCB(napi_env env, napi_status status, void* data)
{
    FI_HILOGD("Enter");
    DevicesInfosCallbackData* devicesInfosCallbackData = static_cast<DevicesInfosCallbackData*>(data);
    napi_value res = nullptr;
    napi_status sts;
    bool isSuccess = static_cast<bool>(devicesInfosCallbackData->isSuccess);
    FI_HILOGI("DeviceCompleteCB, isSuccess=%{public}s", isSuccess ? "success" : "fail");
    sts = napi_get_boolean(env, isSuccess, &res);
    if (sts != napi_ok) {
        FI_HILOGE("napi_get_boolean failed");
    }
    sts = napi_resolve_deferred(env, devicesInfosCallbackData->deferred, res);
    if (sts != napi_ok) {
        FI_HILOGE("napi_resolve_deferred failed");
    }
    sts = napi_delete_async_work(env, devicesInfosCallbackData->asyncWork);
    if (sts != napi_ok) {
        FI_HILOGE("napi_delete_async_work failed");
    }
    FI_HILOGD("Exit");
    delete devicesInfosCallbackData;
}

bool RoomLocationNapi::CreateAsynchronousExecution(napi_env env, napi_deferred deferred,
    std::string deviceInfos)
{
    FI_HILOGD("Enter");
    auto devicesInfosCallbackData = new DevicesInfosCallbackData{
        .asyncWork = nullptr,
        .deferred = deferred,
        .deviceInfos = deviceInfos,
    };

    napi_value resourceName;
    napi_status status = napi_create_string_utf8(env, "setDeviceInfos", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed");
        delete devicesInfosCallbackData;
        return false;
    }

    status = napi_create_async_work(env, nullptr, resourceName, DeviceExecuteCB, DeviceCompleteCB,
        static_cast<void*>(devicesInfosCallbackData), &devicesInfosCallbackData->asyncWork);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_async_work failed");
        delete devicesInfosCallbackData;
        return false;
    }

    status = napi_queue_async_work_with_qos(env, devicesInfosCallbackData->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        FI_HILOGE("napi_queue_async_work_with_qos failed");
        napi_delete_async_work(env, devicesInfosCallbackData->asyncWork);
        delete devicesInfosCallbackData;
        return false;
    }
    return true;
}

napi_value RoomLocationNapi::SetDeviceInfos(napi_env env, napi_callback_info info)
{
    FI_HILOGI("Enter");
    size_t argc = NAPI_INDEX_ONE;
    napi_value args[NAPI_INDEX_ONE] = { nullptr };
    napi_value jsThis = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowErr(env, SETINOFS_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

    if (!ValidateArgsTypeRoom(env, args, argc)) {
        ThrowErr(env, SETINOFS_EXCEPTION, "ValidateArgsTypeRoom failed");
        return nullptr;
    }

    std::lock_guard<std::mutex> guard(g_mutex);
    if (!ConstructRoomLocation(env, jsThis)) {
        ThrowErr(env, SETINOFS_EXCEPTION, "Failed to get g_RoomLocationNapi");
        return nullptr;
    }

    if (g_RoomLocationNapi->g_roomLocationHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }

    std::string deviceInfos;
    FI_HILOGI("get deviceInfos start");
    if (!GetInfos(env, args[0], deviceInfos)) {
        ThrowErr(env, SETINOFS_EXCEPTION, "get deviceInfos failed");
        return nullptr;
    }

    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_status ret = napi_create_promise(env, &deferred, &promise);
    if (ret != napi_ok) {
        ThrowErr(env, SETINOFS_EXCEPTION, "napi_create_promise failed");
        return nullptr;
    }
    if (!CreateAsynchronousExecution(env, deferred, deviceInfos)) {
        napi_value intValue;
        napi_create_int32(env, SETINOFS_EXCEPTION, &intValue);
        napi_reject_deferred(env, deferred, intValue);
        ThrowErr(env, SETINOFS_EXCEPTION, "CreateAsynchronousExecution failed");
        return nullptr;
    }
    FI_HILOGI("Exit");
    return promise;
}

void RoomLocationNapi::OnRoomChangedDone(const CRoomLocationResult &room)
{
    FI_HILOGI("Enter");
    napi_handle_scope scope = nullptr;
    RoomLocationNapiFuncScope napiFuncHand(env_, scope);
    napi_value roomObj = nullptr;
    napi_status status = napi_create_object(env_, &roomObj);
    if (status != napi_ok) {
        FI_HILOGE("failed to create object");
        return;
    }

    std::string roomId(room.roomId);
    SetValueUtf8String(env_, "roomId", roomId, roomObj);
    SetValueInt32(env_, "errorCode", room.errorCode, roomObj);
    OnRoomEvent(NAPI_INDEX_ONE, &roomObj);
}

void RoomLocListener::UpdateEnv(const napi_env &env)
{
    env_ = env;
}

void RoomLocListener::OnRoomChanged(const char* roomId, int32_t errorCode) const
{
    FI_HILOGI("OnRoomChanged, predId=%{public}s, errorCode=%{public}d",
        MaskId(roomId).c_str(), errorCode);
    static CRoomLocationResult staticRoomRes;
    staticRoomRes.roomId = roomId;
    staticRoomRes.errorCode = errorCode;

    napi_env env = env_;
    auto task = [env]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            FI_HILOGE("Failed to open scope");
            return;
        }
        do {
            RoomLocationNapi *RoomLocationNapi = RoomLocationNapi::GetRoomLocationNapi();
            if (RoomLocationNapi == nullptr) {
                FI_HILOGE("RoomLocationNapi is nullptr");
                return;
            }
            RoomLocationNapi->OnRoomChangedDone(staticRoomRes);
        } while (0);
        napi_close_handle_scope(env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to send event for auth");
        return;
    }
}

napi_value RoomLocationNapi::OnRoomLocation(napi_env env, napi_callback_info info)
{
    FI_HILOGI("Enter");
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!ValidateArgsTypeRoom(env, args, argc)) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "ValidateArgsTypeRoom failed");
        return nullptr;
    }
    std::string typeStr;
    if (!TransJsToStr(env, args[0], typeStr)) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }
    if (!GetRoomLocationType(typeStr)) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(g_mutex);
    if (!ConstructRoomLocation(env, jsThis)) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "Failed to get g_RoomLocationNapi");
        return nullptr;
    }
    if (g_RoomLocationNapi->g_roomLocationHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    std::string pkgName = GetAppPackageName();
    if (!CreateRoomLocateCallback(env, pkgName, args[1], argc)) {
        ThrowErr(env, SERVICE_EXCEPTION, "create room callback failed");
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("Exit");
    return result;
}

bool RoomLocationNapi::CreateRoomLocateCallback(napi_env env,
    const std::string pkgName, napi_value callback, size_t argSize)
{
    if (!g_RoomLocationNapi->AddCallback(pkgName, callback)) {
        return false;
    }
    if (g_RoomLocationNapi == nullptr) {
        return false;
    }

    if (roomCallback_ == nullptr) {
        FI_HILOGI("Don't find callback, to create");
        if (g_RoomLocationNapi->g_subscribeRoomLocationFunc == nullptr) {
            g_RoomLocationNapi->g_subscribeRoomLocationFunc = reinterpret_cast<SubscribeRoomLocationFunc>(
                dlsym(g_RoomLocationNapi->g_roomLocationHandle, SUBSCRIBE_FUNC_NAME.data()));
            if (g_RoomLocationNapi->g_subscribeRoomLocationFunc == nullptr) {
                FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
                return false;
            }
        }
    } else {
        roomCallback_->UpdateEnv(env);
    }
    std::shared_ptr<OHOS::Msdp::IRoomLocationListener> listener
        = std::make_shared<RoomLocListener>(env);
    int32_t ret = g_RoomLocationNapi->g_subscribeRoomLocationFunc(pkgName.c_str(), listener);
    if (ret != 0) {
        FI_HILOGE("Subscribe room Callback failed");
        g_RoomLocationNapi->RemoveCallback(pkgName);
        return false;
    }
    roomCallback_ = listener;
    return true;
}

bool RoomLocationNapi::DeleteRoomLocateCallback(const std::string pkgName,
    napi_value callback, size_t argSize)
{
    if (roomCallback_ == nullptr) {
        FI_HILOGI("never before Subscribe room Callback");
        return true;
    }
    if (g_RoomLocationNapi == nullptr) {
        return false;
    }

    if (g_RoomLocationNapi->g_unsubscribeRoomLocationFunc == nullptr) {
        g_RoomLocationNapi->g_unsubscribeRoomLocationFunc = reinterpret_cast<UnsubscribeRoomLocationFunc>(
            dlsym(g_RoomLocationNapi->g_roomLocationHandle, UNSUBSCRIBE_FUNC_NAME.data()));
        if (g_RoomLocationNapi->g_unsubscribeRoomLocationFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
            return false;
        }
    }
    int32_t ret = g_RoomLocationNapi->g_unsubscribeRoomLocationFunc(pkgName.c_str());
    if (ret != 0) {
        FI_HILOGE("Unsubscribe room Callback failed");
        return false;
    }
    g_RoomLocationNapi->RemoveCallback(pkgName);
    return true;
}

napi_value RoomLocationNapi::OffRoomLocation(napi_env env, napi_callback_info info)
{
    FI_HILOGI("Enter");
    if (g_RoomLocationNapi == nullptr) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "g_RoomLocationNapi is nullptr");
        return nullptr;
    }
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!ValidateArgsTypeRoom(env, args, argc)) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "ValidateArgsTypeRoom failed");
        return nullptr;
    }
    std::string typeStr;
    if (!TransJsToStr(env, args[0], typeStr)) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }
    if (!GetRoomLocationType(typeStr)) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "Type is illegal");
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_RoomLocationNapi->g_roomLocationHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    std::string pkgName = GetAppPackageName();
    if (!DeleteRoomLocateCallback(pkgName, args[1], argc)) {
        ThrowErr(env, SERVICE_EXCEPTION, "delete room callback failed");
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("Exit");
    return result;
}

CRoomLocationResult RoomLocationNapi::GetRoomLocationResultInner(napi_env env)
{
    FI_HILOGI("Enter");
    CRoomLocationResult roomRes = {INVALID_ID.c_str(), INVALID_ID_ERRCODE};
    if (g_RoomLocationNapi == nullptr) {
        ThrowErr(env, GETRES_EXCEPTION, "g_RoomLocationNapi is nullptr");
        return roomRes;
    }
    if (g_RoomLocationNapi->g_getRoomResDataFunc == nullptr) {
        g_RoomLocationNapi->g_getRoomResDataFunc = reinterpret_cast<GetRoomResDataFunc>(
            dlsym(g_RoomLocationNapi->g_roomLocationHandle, GETROOMRESDATA_FUNC_NAME.data()));
        if (g_RoomLocationNapi->g_getRoomResDataFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", GETROOMRESDATA_FUNC_NAME.data(), dlerror());
            return roomRes;
        }
    }
    g_RoomLocationNapi->g_getRoomResDataFunc(&roomRes);
    return roomRes;
}

std::string RoomLocationNapi::GetAppPackageName()
{
    FI_HILOGD("Enter");
    std::string pkgName;
    int32_t uid = IPCSkeleton::GetCallingUid();
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgr = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    auto ret = bundleMgr->GetNameForUid(uid, pkgName);
    if (ret != ERR_OK) {
        pkgName = std::to_string(uid);
    }
    FI_HILOGI("pkgName=%{public}s", pkgName.c_str());
    return pkgName;
}

napi_value RoomLocationNapi::GetRoomLocationResult(napi_env env, napi_callback_info info)
{
    FI_HILOGI("Enter");
    napi_value result = nullptr;
    size_t argc = NAPI_INDEX_ZERO;
    napi_value jsThis;

    napi_status status = napi_get_cb_info(env, info, &argc, NULL, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowErr(env, GETRES_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(g_mutex);
    if (!ConstructRoomLocation(env, jsThis)) {
        ThrowErr(env, GETRES_EXCEPTION, "Failed to get g_RoomLocationNapi");
        return nullptr;
    }
    if (g_RoomLocationNapi->g_roomLocationHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }

    FI_HILOGI("Start room-level location");
    CRoomLocationResult roomLocationRes = GetRoomLocationResultInner(env);
    std::string roomId(roomLocationRes.roomId);
    if (roomId.empty()) {
        ThrowErr(env, GETRES_EXCEPTION, "empty result");
        return nullptr;
    }

    napi_status objStatus = napi_create_object(env, &result);
    if (objStatus != napi_ok) {
        ThrowErr(env, GETRES_EXCEPTION, "napi_create_object failed");
        return nullptr;
    }

    SetValueUtf8String(env, "roomId", roomId, result);
    SetValueInt32(env, "errorCode", roomLocationRes.errorCode, result);
    FI_HILOGI("GetRoomLocationResult, predId=%{public}s, errorCode=%{public}d",
        MaskId(roomLocationRes.roomId).c_str(), roomLocationRes.errorCode);
    FI_HILOGI("Exit");
    return result;
}

napi_value RoomLocationNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", OnRoomLocation),
        DECLARE_NAPI_STATIC_FUNCTION("off", OffRoomLocation),
        DECLARE_NAPI_STATIC_FUNCTION("setDeviceInfos", SetDeviceInfos),
        DECLARE_NAPI_STATIC_FUNCTION("getRoomLocationResult", GetRoomLocationResult)
    };

    FI_HILOGI("RoomLocationNapi init is called");
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    ModeInit(env, exports);
    return exports;
}

RoomLocationNapi::RoomLocationNapi(napi_env env, napi_value thisVar) : RoomLocationEventNapi(env, thisVar) {}

RoomLocationNapi::~RoomLocationNapi()
{
    if (g_roomLocationHandle != nullptr) {
        dlclose(g_roomLocationHandle);
        g_roomLocationHandle = nullptr;
        FI_HILOGI("Remove g_roomLocationHandle");
    }
    g_getRoomResDataFunc = nullptr;
    g_setDeviceInfosFunc = nullptr;
    g_subscribeRoomLocationFunc = nullptr;
    g_unsubscribeRoomLocationFunc = nullptr;
}

RoomLocationNapiFuncScope::RoomLocationNapiFuncScope(napi_env env, napi_handle_scope scope)
{
    napi_status status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok) {
        isOpen = false;
        FI_HILOGE("Failed to create napi_open_handle_scope");
        return;
    }
    isOpen = true;
    env_ = env;
    scope_ = scope;
}

RoomLocationNapiFuncScope::~RoomLocationNapiFuncScope()
{
    if (!isOpen) {
        FI_HILOGE("Handle_scope is not opened");
        return;
    }
    napi_status status = napi_close_handle_scope(env_, scope_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to napi_close_handle_scope end");
    }
}

/*
 * Function registering all props and functions of ohos.msdp
 */
static napi_value Export(napi_env env, napi_value exports)
{
    FI_HILOGI("Export is called");
    RoomLocationNapi::Init(env, exports);
    return exports;
}

/*
 * Module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.roomLocation",
    .nm_register_func = Export,
    .nm_modname = "multimodalAwareness.roomLocation",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModuleRoom(void)
{
    FI_HILOGI("RegisterModuleRoom is called");
    napi_module_register(&g_module);
}
} // namespace Msdp
} // namespace OHOS
