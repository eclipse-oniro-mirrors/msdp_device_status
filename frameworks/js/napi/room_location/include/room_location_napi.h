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

#ifndef ROOM_LOCATION_NAPI_H
#define ROOM_LOCATION_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "room_location_event_napi.h"
#include "room_location_callback.h"

namespace OHOS {
namespace Msdp {
struct CRoomLocationResult {
    const char* roomId;
    int32_t errorCode = -1;
};

typedef void (*GetRoomResDataFunc)(CRoomLocationResult* roomRes);
typedef int32_t (*SetDeviceInfosFunc)(const char* deviceInfos);
typedef int32_t (*SubscribeRoomLocationFunc)(const char* pkgName,
    std::shared_ptr<OHOS::Msdp::IRoomLocationListener> listener);
typedef int32_t (*UnsubscribeRoomLocationFunc)(const char* pkgName);

class RoomLocListener : public IRoomLocationListener {
public:
    explicit RoomLocListener(napi_env env) : env_(env) {}
    virtual ~RoomLocListener() = default;
    void OnRoomChanged(const char* roomId, int32_t errorCode) const;
    void UpdateEnv(const napi_env &env);
private:
    std::atomic<napi_env> env_;
};

class RoomLocationNapi : public RoomLocationEventNapi {
public:
    explicit RoomLocationNapi(napi_env env, napi_value thisVar);
    virtual ~RoomLocationNapi();

    static RoomLocationNapi *GetRoomLocationNapi();
    static napi_value ModeInit(napi_env env, napi_value exports);
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value OnRoomLocation(napi_env env, napi_callback_info info);
    static napi_value OffRoomLocation(napi_env env, napi_callback_info info);
    static napi_value SetDeviceInfos(napi_env env, napi_callback_info info);
    static napi_value GetRoomLocationResult(napi_env env, napi_callback_info info);
    void OnRoomChangedDone(const CRoomLocationResult &room);
    void OnRoomChanged(const std::string roomId, const int32_t errorCode);

private:
    static bool LoadLibrary();
    static void SetValueUtf8String(const napi_env &env, const std::string &fieldStr, const std::string &str,
        napi_value &result);
    static void SetValueInt32(const napi_env &env, const std::string &fieldStr, const int32_t intValue,
        napi_value &result);
    static bool ConstructRoomLocation(napi_env env, napi_value jsThis);
    static bool GetRoomLocationType(const std::string &type);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static bool ValidateArgsTypeRoom(napi_env env, napi_value *args, size_t argc);
    static bool GetInfos(napi_env env, napi_value strValue, std::string &strInfos);
    static std::string GetAppPackageName();
    static CRoomLocationResult GetRoomLocationResultInner(napi_env env);
    static void DeviceExecuteCB(napi_env env, void* data);
    static void DeviceCompleteCB(napi_env env, napi_status status, void* data);
    static bool CreateAsynchronousExecution(napi_env env, napi_deferred deferred,
        std::string deviceInfos);
    static bool CreateRoomLocateCallback(napi_env env, const std::string pkgName,
        napi_value callback, size_t argSize);
    static bool DeleteRoomLocateCallback(const std::string pkgName,
        napi_value callback, size_t argSize);

private:
    void* g_roomLocationHandle = nullptr;
    GetRoomResDataFunc g_getRoomResDataFunc = nullptr;
    SetDeviceInfosFunc g_setDeviceInfosFunc = nullptr;
    SubscribeRoomLocationFunc g_subscribeRoomLocationFunc = nullptr;
    UnsubscribeRoomLocationFunc g_unsubscribeRoomLocationFunc = nullptr;
    struct DevicesInfosCallbackData {
        napi_async_work asyncWork;
        napi_deferred deferred;
        std::string deviceInfos;
        int32_t isSuccess = 0;
    };
    static std::shared_ptr<OHOS::Msdp::IRoomLocationListener> roomCallback_;
};

class RoomLocationNapiFuncScope {
public:
    explicit RoomLocationNapiFuncScope(napi_env env, napi_handle_scope scope);
    ~RoomLocationNapiFuncScope();
private:
    bool isOpen = {false};
    napi_env env_ { nullptr };
    napi_handle_scope scope_ { nullptr };
};
} // namespace Msdp
} // namespace OHOS
#endif // ROOM_LOCATION_NAPI_H