/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_status_event_napi.h"

#include <dlfcn.h>

#include <string_view>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "motion_napi_error.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "MotionUserStatusEventNapi"

namespace OHOS {
namespace Msdp {
constexpr uint32_t HOVER_HAND_FEATURE_ID = 14;
constexpr int32_t MAX_ERROR_CODE = 1000;
constexpr int32_t UNSUPP_FRATURE_ERR = 0x3A1000D;
constexpr int32_t DEVICE_UNSUPPORT_ERR = 0x3A10028;
constexpr int32_t NOT_SYSTEM_ERR = 0x3A10006;
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t POINTER_ACTION_DOWN = 2;
constexpr int32_t POINTER_ACTION_MOVE = 3;
constexpr int32_t POINTER_ACTION_UP = 4;
const constexpr char *HOVER_HAND_EVENT_NAME = "hoverHandChanged";
const constexpr char *USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view SUBSCRIBE_CALLBACK_FUNC_NAME = { "SubscribeCallback" };
const std::string_view SUBSCRIBE_HOVER_HAND_FUNC_NAME = { "SubscribeHoverHandEvent" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "Unsubscribe" };
const std::map<const std::string, int32_t> FEATURE_ID_MAP = {
    { "hoverHandChanged", HOVER_HAND_FEATURE_ID },
};
std::mutex g_mutex; // mutex:Subscribe/Unsubscribe/OnListener
UserStatusEventNapi *g_userStatusEventObj = nullptr;
napi_value JsHoverEventData::Write(napi_env env, const HoverHandEventData &eventData)
{
    napi_value jsObject = nullptr;
    CHKRP(napi_create_object(env, &jsObject), "create object");

    napi_value coordinateX = nullptr;
    CHKRP(napi_create_int32(env, eventData.coordinateX, &coordinateX), "create coordinateX");
    CHKRP(napi_set_named_property(env, jsObject, "coordinateX", coordinateX), "set coordinateX property");

    napi_value coordinateY = nullptr;
    CHKRP(napi_create_int32(env, eventData.coordinateY, &coordinateY), "create coordinateY");
    CHKRP(napi_set_named_property(env, jsObject, "coordinateY", coordinateY), "set coordinateY property");

    napi_value action = nullptr;
    CHKRP(napi_create_int32(env, static_cast<int32_t>(eventData.action), &action), "create action");
    CHKRP(napi_set_named_property(env, jsObject, "action", action), "set action property");

    return jsObject;
}

bool JsHoverHandDetectionArea::Read(napi_env env, napi_value object, HoverHandDetectionArea &area)
{
    napi_value leftProp = nullptr;
    CHKRF(napi_get_named_property(env, object, "left", &leftProp), "read left property");
    CHKRF(napi_get_value_int32(env, leftProp, &area.left), "get left value");

    napi_value topProp = nullptr;
    CHKRF(napi_get_named_property(env, object, "top", &topProp), "read top property");
    CHKRF(napi_get_value_int32(env, topProp, &area.top), "get top value");

    napi_value widthProp = nullptr;
    CHKRF(napi_get_named_property(env, object, "width", &widthProp), "read width property");
    CHKRF(napi_get_value_uint32(env, widthProp, &area.width), "get width value");

    napi_value heightProp = nullptr;
    CHKRF(napi_get_named_property(env, object, "height", &heightProp), "read height property");
    CHKRF(napi_get_value_uint32(env, heightProp, &area.height), "get height value");

    return true;
}

void UserStatusDataCallback::OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData)
{
    auto task = [callbackId, userStatusData]() {
        std::lock_guard<std::mutex> guard(g_mutex);
        CHKPV(g_userStatusEventObj);
        g_userStatusEventObj->OnReceiveData(callbackId, userStatusData);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate, "userStatus.listener") != napi_status::napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
}

UserStatusEventNapi::UserStatusEventNapi(napi_env env, napi_value thisVar)
{
    env_ = env;
    thisVarRef_ = nullptr;
    napi_create_reference(env, thisVar, 1, &thisVarRef_);
}

UserStatusEventNapi::~UserStatusEventNapi()
{
    if (env_ == nullptr) {
        FI_HILOGW("env_ is nullptr");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
        for (auto &iter : jsCallbacks_) {
            if (iter.second == nullptr) {
                continue;
            }
            for (auto it = iter.second->onRefSets.begin(); it != iter.second->onRefSets.end();) {
                if (*it == nullptr) {
                    ++it;
                    continue;
                }
                napi_status status = napi_delete_reference(env_, *it);
                if (status != napi_ok) {
                    FI_HILOGE("napi_delete_reference failed");
                }
                it = iter.second->onRefSets.erase(it);
            }
            iter.second = nullptr;
        }
        jsCallbacks_.clear();
    }
    if (env_ != nullptr && thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
    }
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    registerListenerFunc_ = nullptr;
    subscribeHoverHandFunc_ = nullptr;
    unsubscribeFunc_ = nullptr;
}

napi_value UserStatusEventNapi::GetHoverHandAction(napi_env env)
{
    napi_value hoverHandAction = nullptr;
    napi_value actionDown = nullptr;
    napi_value actionMove = nullptr;
    napi_value actionUp = nullptr;
    MSDP_CALL(napi_create_int32(env, static_cast<int32_t>(HoverHandAction::DOWN), &actionDown));
    MSDP_CALL(napi_create_int32(env, static_cast<int32_t>(HoverHandAction::MOVE), &actionMove));
    MSDP_CALL(napi_create_int32(env, static_cast<int32_t>(HoverHandAction::UP), &actionUp));
    MSDP_CALL(napi_create_object(env, &hoverHandAction));
    MSDP_CALL(napi_set_named_property(env, hoverHandAction, "DOWN", actionDown));
    MSDP_CALL(napi_set_named_property(env, hoverHandAction, "MOVE", actionMove));
    MSDP_CALL(napi_set_named_property(env, hoverHandAction, "UP", actionUp));
    return hoverHandAction;
}

bool UserStatusEventNapi::Construct(napi_env env, napi_value jsThis)
{
    if (g_userStatusEventObj == nullptr) {
        g_userStatusEventObj = new (std::nothrow) UserStatusEventNapi(env, jsThis);
        if (g_userStatusEventObj == nullptr) {
            FI_HILOGE("faild to get g_userStatusEventObj");
            return false;
        }
        napi_status status = napi_wrap(
            env, jsThis, reinterpret_cast<void *>(g_userStatusEventObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    UserStatusEventNapi *userStatusEvent = reinterpret_cast<UserStatusEventNapi *>(data);
                    delete userStatusEvent;
                    userStatusEvent = nullptr;
                }
            },
            nullptr, nullptr);
        if (status != napi_ok) {
            delete g_userStatusEventObj;
            g_userStatusEventObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

bool UserStatusEventNapi::InitializeCallback(napi_env env, const std::string &eventType)
{
    if (g_userStatusEventObj->userStatusCallback_ != nullptr) {
        FI_HILOGD("userStatusCallback_ not nullptr");
        return true;
    }
    auto userStatusDataCallback = std::make_shared<UserStatusDataCallback>(env);
    g_userStatusEventObj->userStatusCallback_ = [userStatusDataCallback](
                                                    int32_t callbackId, std::shared_ptr<UserStatusData> data) -> void {
        if (userStatusDataCallback == nullptr) {
            FI_HILOGE("userStatusDataCallback is nullptr");
            return;
        }
        userStatusDataCallback->OnReceiveData(callbackId, data);
    };
    // init registerListenerFunc_
    if (g_userStatusEventObj->registerListenerFunc_ == nullptr) {
        g_userStatusEventObj->registerListenerFunc_ = reinterpret_cast<SubscribeCallbackFunc>(
            dlsym(g_userStatusEventObj->handle_, SUBSCRIBE_CALLBACK_FUNC_NAME.data()));
        if (g_userStatusEventObj->registerListenerFunc_ == nullptr) {
            FI_HILOGE(
                "%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_CALLBACK_FUNC_NAME.data(), dlerror());
            ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    // call registerListenerFunc_
    int32_t featureId = GetFeatureId(eventType);
    if (featureId == -1) {
        return false;
    }
    int32_t ret = std::abs(g_userStatusEventObj->registerListenerFunc_(
        static_cast<uint32_t>(featureId), g_userStatusEventObj->userStatusCallback_));
    if (ret < MAX_ERROR_CODE) {
        FI_HILOGE("Subscribe Callback failed, ret:%{public}d", ret);
        g_userStatusEventObj->userStatusCallback_ = nullptr;
        ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
        return false;
    } else if (ret == NOT_SYSTEM_ERR) {
        FI_HILOGE("Not system app, ret:%{public}d", ret);
        g_userStatusEventObj->userStatusCallback_ = nullptr;
        ThrowMotionErr(env, NO_SYSTEM_API, "Not system app");
        return false;
    }
    g_userStatusEventObj->callbackId_ = ret;
    return true;
}

napi_value UserStatusEventNapi::SubscribeHoverHandEvent(napi_env env, napi_callback_info info)
{
    FI_HILOGI("enter");
    // 4 means four parameters at most
    size_t argc = 4;
    napi_value args[4] = { nullptr };
    napi_value jsThis = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    // check parameters
    HoverHandOptions options;
    CHKRN_PARAM(env, ParseHoverHandParams(env, args, argc, options), "Invalid arguments");
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        // load library
        CHKRN_THROW(env, Construct(env, jsThis), SERVICE_EXCEPTION, "Failed to get g_userStatusEventObj");
        CHKRN_THROW(env, LoadLibrary(), DEVICE_EXCEPTION, "Device not support");
        // do subscribe
        CHKRN_THROW(env, InitializeCallback(env, HOVER_HAND_EVENT_NAME), SUBSCRIBE_EXCEPTION, "Subscription failed");
        CHKRN_THROW(env, SubscribeToUserStatus(env, options), SUBSCRIBE_EXCEPTION, "Subscription failed");
        CHKRN_THROW(env, g_userStatusEventObj->AddCallback(HOVER_HAND_FEATURE_ID, args[1]), SUBSCRIBE_EXCEPTION,
            "Add callback failed");
    }

    return UtilNapi::GetNull(env);
}

napi_value UserStatusEventNapi::UnsubscribeHoverHandEvent(napi_env env, napi_callback_info info)
{
    FI_HILOGI("enter");
    CHKRN_THROW(env, (g_userStatusEventObj != nullptr), UNSUBSCRIBE_EXCEPTION, "g_userStatusEventObj is nullptr");
    // 1 means one parameter at most
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr), "napi_get_cb_info fail");
    // validate params, 1 means one parameter at most
    CHKRN_PARAM(env, (argc <= 1), "Wrong number of arguments");
    // 1 means parse the parameter if exits
    if (argc == 1) {
        CHKRN_PARAM(env, UtilNapi::TypeOf(env, args[0], napi_function), "The callback must be a function");
    }
    {
        std::lock_guard<std::mutex> guard(g_mutex);
        // load so
        CHKRN_THROW(env, LoadLibrary(), DEVICE_EXCEPTION, "Device not support");
        // do unsubscribe
        bool result = argc > 0 ? g_userStatusEventObj->RemoveCallback(HOVER_HAND_FEATURE_ID, args[0])
                               : g_userStatusEventObj->RemoveAllCallback(HOVER_HAND_FEATURE_ID);
        CHKRN_THROW(env, result, SERVICE_EXCEPTION, "RemoveCallback failed");
        CHKRN_THROW(
            env, UnsubscribeFromUserStatus(env, HOVER_HAND_EVENT_NAME), SERVICE_EXCEPTION, "RemoveCallback failed");

        if (g_userStatusEventObj->IsEmptyEvents()) {
            g_userStatusEventObj->userStatusCallback_ = nullptr;
            g_userStatusEventObj->callbackId_ = 0;
        }
    }
    return UtilNapi::GetNull(env);
}

bool UserStatusEventNapi::LoadLibrary()
{
    if (g_userStatusEventObj->handle_ == nullptr) {
        g_userStatusEventObj->handle_ = dlopen(USER_STATUS_CLIENT_SO_PATH, RTLD_LAZY);
        if (g_userStatusEventObj->handle_ == nullptr) {
            FI_HILOGE(
                "Load failed, path is %{private}s, error after: %{public}s", USER_STATUS_CLIENT_SO_PATH, dlerror());
            return false;
        }
    }
    return true;
}

bool UserStatusEventNapi::SubscribeToUserStatus(napi_env env, const HoverHandOptions &options)
{
    // init subscribeHoverHandFunc_
    if (g_userStatusEventObj->subscribeHoverHandFunc_ == nullptr) {
        g_userStatusEventObj->subscribeHoverHandFunc_ = reinterpret_cast<SubscribeHoverHandFunc>(
            dlsym(g_userStatusEventObj->handle_, SUBSCRIBE_HOVER_HAND_FUNC_NAME.data()));
        if (g_userStatusEventObj->subscribeHoverHandFunc_ == nullptr) {
            FI_HILOGE(
                "%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_HOVER_HAND_FUNC_NAME.data(), dlerror());
            ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }

    // call subscribeHoverHandFunc_
    int32_t ret = g_userStatusEventObj->subscribeHoverHandFunc_(HOVER_HAND_FEATURE_ID, options.area, options.duration);
    if (ret == RET_OK) {
        FI_HILOGI("call SubscribeHoverHandEvent success");
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
        FI_HILOGE("failed to subscribe");
        ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    } else if (ret == NOT_SYSTEM_ERR) {
        FI_HILOGE("Not system app, ret:%{public}d", ret);
        ThrowMotionErr(env, NO_SYSTEM_API, "Not system app");
        return false;
    }
    FI_HILOGE("failed to subscribe, ret: %{public}d", ret);
    ThrowMotionErr(env, SERVICE_EXCEPTION, "Subscribe failed");
    return false;
}

bool UserStatusEventNapi::UnsubscribeFromUserStatus(napi_env env, const std::string &eventType)
{
    if (g_userStatusEventObj == nullptr) {
        ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "g_userStatusEventObj is nullptr");
        return false;
    }
    // init unsubscribeFunc_
    if (g_userStatusEventObj->unsubscribeFunc_ == nullptr) {
        g_userStatusEventObj->unsubscribeFunc_ =
            reinterpret_cast<UnsubscribeFunc>(dlsym(g_userStatusEventObj->handle_, UNSUBSCRIBE_FUNC_NAME.data()));
        if (g_userStatusEventObj->unsubscribeFunc_ == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
            ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    // call unsubscribeFunc_
    int32_t featureId = GetFeatureId(eventType);
    if (featureId == -1) {
        return false;
    }
    auto ret = g_userStatusEventObj->unsubscribeFunc_(static_cast<uint32_t>(featureId));
    if (ret == RET_OK) {
        FI_HILOGI("call Unsubscribe success");
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
        FI_HILOGE("failed to unsubscribe");
        ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    } else if (ret == NOT_SYSTEM_ERR) {
        FI_HILOGE("Not system app, ret:%{public}d", ret);
        ThrowMotionErr(env, NO_SYSTEM_API, "Not system app");
        return false;
    }
    FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
    ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
    return false;
}

bool UserStatusEventNapi::AddCallback(uint32_t featureId, napi_value handler)
{
    std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
    auto iter = jsCallbacks_.find(featureId);
    if (iter == jsCallbacks_.end()) {
        FI_HILOGD("found event:%{public}d", featureId);
        napi_ref onHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, handler, 1, &onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        auto callback = std::make_shared<JsUserStatusEventCallback>();
        std::set<napi_ref> onRefSets;
        callback->onRefSets = onRefSets;
        auto ret = callback->onRefSets.insert(onHandlerRef);
        if (!ret.second) {
            FI_HILOGE("Failed to insert refs");
            return false;
        }
        jsCallbacks_.insert(std::make_pair(featureId, callback));
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("found event: %{public}d", featureId);
    if (iter->second == nullptr || iter->second->onRefSets.empty()) {
        FI_HILOGE("listener or onRefSets is nullptr");
        jsCallbacks_.erase(iter);
        return false;
    }
    FI_HILOGD("Check type: %{public}d same handle", featureId);
    if (!InsertRef(iter->second, handler)) {
        FI_HILOGE("Failed to insert ref");
        jsCallbacks_.erase(iter);
        return false;
    }
    FI_HILOGD("feature: %{public}u", featureId);
    return true;
}

bool UserStatusEventNapi::RemoveCallback(uint32_t featureId, napi_value handler)
{
    std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
    auto iter = jsCallbacks_.find(featureId);
    if (iter == jsCallbacks_.end()) {
        FI_HILOGE("EventType %{public}d not found", featureId);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        jsCallbacks_.erase(iter);
        return false;
    }
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (*it == nullptr) {
            ++it;
            continue;
        }
        napi_value deleteHandler;
        napi_status status = napi_get_reference_value(env_, *it, &deleteHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            ++it;
            continue;
        }
        if (IsSameValue(env_, handler, deleteHandler)) {
            status = napi_delete_reference(env_, *it);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
            }
            it = iter->second->onRefSets.erase(it);
            break;
        }
        ++it;
    }
    if (iter->second->onRefSets.empty()) {
        jsCallbacks_.erase(featureId);
    }
    FI_HILOGD("feature: %{public}u", featureId);
    return true;
}

bool UserStatusEventNapi::RemoveAllCallback(uint32_t featureId)
{
    std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
    auto iter = jsCallbacks_.find(featureId);
    if (iter == jsCallbacks_.end()) {
        FI_HILOGE("EventType %{public}d not found", featureId);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (*it == nullptr) {
            ++it;
            continue;
        }
        napi_status status = napi_delete_reference(env_, *it);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        it = iter->second->onRefSets.erase(it);
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("onRefSets is empty");
        jsCallbacks_.erase(iter);
    }
    FI_HILOGD("feature: %{public}u", featureId);
    return true;
}

bool UserStatusEventNapi::IsEmptyEvents()
{
    std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
    return jsCallbacks_.empty();
}

void UserStatusEventNapi::OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData)
{
    std::lock_guard<std::mutex> lock(jsCallbacksMutex_);
    uint32_t featureId = userStatusData->GetFeature();
    auto typeIter = jsCallbacks_.find(featureId);
    if (typeIter == jsCallbacks_.end()) {
        FI_HILOGE("featureId: %{public}d not found", featureId);
        return;
    }
    if (typeIter->second == nullptr) {
        FI_HILOGE("listener is nullptr.");
        return;
    }
    for (auto item : typeIter->second->onRefSets) {
        napi_value handler = nullptr;
        napi_status ret = napi_get_reference_value(env_, item, &handler);
        if (ret != napi_ok) {
            FI_HILOGE("napi_get_reference_value for %{public}d failed, status: %{public}d", featureId, ret);
            continue;
        }
        napi_value userData = ConvertToHoverHandEventData(env_, userStatusData);
        napi_value callResult = nullptr;
        if (napi_call_function(env_, nullptr, handler, 1, &userData, &callResult) != napi_ok) {
            FI_HILOGE("Report event to Js failed");
            continue;
        }
    }
}

bool UserStatusEventNapi::ParseHoverHandParams(napi_env env, napi_value *args, size_t argc, HoverHandOptions &options)
{
    // 2 means tow parameters at least, 3 means three parameters at most
    CHKRF_PARAM(env, (argc >= 2 && argc <= 3), "Wrong number of arguments");

    // 1 - parse callback, 0 means the first parameter
    CHKRF_PARAM(env, UtilNapi::TypeOf(env, args[0], napi_function), "The callback must be a function");
    // 2 - parse detectionArea, 1 means the second parameter
    CHKRF_PARAM(env, JsHoverHandDetectionArea::Read(env, args[1], options.area), "Invalid detectionArea");
    FI_HILOGD("area: %{public}s", options.area.ToString().c_str());
    // 3 - parse optional duration, default value is 5.
    if (argc == 3) {
        // 2 means the third parameter
        CHKRF_PARAM(env, UtilNapi::TypeOf(env, args[2], napi_number), "The duration must be a number");
        napi_status status = napi_get_value_uint32(env, args[2], &options.duration);
        if (status != napi_ok) {
            FI_HILOGW("Failed to get duration, using default 5");
        }
    }
    return true;
}

bool UserStatusEventNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
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
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen + 1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str = buf.data();
    return true;
}

int32_t UserStatusEventNapi::GetFeatureId(const std::string &eventName)
{
    FI_HILOGD("Enter");
    auto iter = FEATURE_ID_MAP.find(eventName);
    if (iter == FEATURE_ID_MAP.end()) {
        FI_HILOGE("Don't find this type: %{public}s", eventName.c_str());
        return -1;
    }
    FI_HILOGD("Exit");
    return iter->second;
}

napi_value UserStatusEventNapi::ConvertToHoverHandEventData(
    napi_env env, std::shared_ptr<UserStatusData> userStatusData)
{
    HoverHandEventData data = { .coordinateX = userStatusData->GetCoordinateX(),
        .coordinateY = userStatusData->GetCoordinateY() };
    if (userStatusData->GetPointerAction() == POINTER_ACTION_DOWN) {
        data.action = HoverHandAction::DOWN;
    } else if (userStatusData->GetPointerAction() == POINTER_ACTION_MOVE) {
        data.action = HoverHandAction::MOVE;
    } else if (userStatusData->GetPointerAction() == POINTER_ACTION_UP) {
        data.action = HoverHandAction::UP;
    }
    return JsHoverEventData::Write(env, data);
}

bool UserStatusEventNapi::InsertRef(std::shared_ptr<JsUserStatusEventCallback> listener, napi_value handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    bool hasHandler = false;
    for (auto item : listener->onRefSets) {
        napi_value onHandler = nullptr;
        napi_status status = napi_get_reference_value(env_, item, &onHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            status = napi_delete_reference(env_, item);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
                continue;
            }
            continue;
        }
        if (IsSameValue(env_, handler, onHandler)) {
            hasHandler = true;
            break;
        }
    }
    if (hasHandler) {
        FI_HILOGD("napi repeat subscribe");
        return true;
    }
    napi_ref onHandlerRef = nullptr;
    napi_status status = napi_create_reference(env_, handler, 1, &(onHandlerRef));
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }

    FI_HILOGD("Insert new ref");
    auto ret = listener->onRefSets.insert(onHandlerRef);
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
        status = napi_delete_reference(env_, onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        return false;
    }
    FI_HILOGD("ref size %{public}zu", listener->onRefSets.size());
    return true;
}

bool UserStatusEventNapi::IsSameValue(napi_env env, const napi_value &lhs, const napi_value &rhs)
{
    FI_HILOGD("Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
    }
    return result;
}
} // namespace Msdp
} // namespace OHOS