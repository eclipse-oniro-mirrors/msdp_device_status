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

#include "behavior_awareness_napi.h"

#include <accesstoken_kit.h>
#include <ipc_skeleton.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
namespace {
constexpr size_t ARG_0 = 0;
constexpr size_t ARG_1 = 1;
constexpr size_t ARG_2 = 2;
constexpr int32_t FEEDBACK_ACCEPT = 0;
constexpr int32_t FEEDBACK_IGNORE = 1;
constexpr int32_t FEEDBACK_REJECT = 2;
constexpr int32_t FEEDBACK_EDIT = 3;
constexpr int32_t FEEDBACK_NOT_PUSHED = 4;
constexpr size_t EVENT_TYPE_COUNT = 18;
constexpr size_t ACTION_TYPE_COUNT = 17;
constexpr size_t BT_TYPE_COUNT = 8;
constexpr size_t RECURRENCE_COUNT = 4;
constexpr size_t LOCATION_COUNT = 3;
constexpr size_t OPERATION_COUNT = 3;
constexpr size_t ADJUSTMENT_COUNT = 2;
constexpr size_t PATTERN_COUNT = 3;
constexpr size_t SOUND_MODE_COUNT = 3;
std::mutex g_mtx;
std::map<std::string, sptr<BehaviorAwarenessNapiCallback>> g_callbacks;

bool CheckCallerIsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return true;
    }
    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::AccessTokenKit::IsSystemAppByFullTokenID(fullTokenId);
}

bool IsMatchTypeImpl(napi_env env, napi_value value, napi_valuetype type);

void ClearAllCallbacks(napi_env env)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    for (auto &item : g_callbacks) {
        if (item.second != nullptr && item.second->callbackRef_ != nullptr) {
            napi_delete_reference(env, item.second->callbackRef_);
            item.second->callbackRef_ = nullptr;
        }
    }
    g_callbacks.clear();
}

void RejectPromise(napi_env env, napi_deferred deferred, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    auto msg = GetBehaviorAwarenessErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid, fallback to SERVICE_EXCEPTION", errCode);
        errCode = RET_SERVICE_EXCEPTION;
        msg = "Service exception.";
    }
    napi_value error = CreateBehaviorAwarenessNapiError(env, errCode, msg.value());
    napi_reject_deferred(env, deferred, error);
}

napi_value ResolvePromise(napi_env env, napi_deferred deferred)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_resolve_deferred(env, deferred, undefined);
    napi_value promise = nullptr;
    napi_create_object(env, &promise);
    return promise;
}

napi_value CreatePromise(napi_env env, napi_deferred *deferred)
{
    napi_value promise = nullptr;
    napi_create_promise(env, deferred, &promise);
    return promise;
}

struct StringEnumEntry {
    const char *key;
    const char *value;
};

struct IntEnumEntry {
    const char *key;
    int32_t value;
};

void RegisterStringEnum(napi_env env, napi_value exports, const char *name,
    const StringEnumEntry *entries, size_t count)
{
    napi_value napiEnum;
    napi_create_object(env, &napiEnum);
    napi_value val;
    for (size_t i = 0; i < count; ++i) {
        napi_create_string_utf8(env, entries[i].value, NAPI_AUTO_LENGTH, &val);
        napi_set_named_property(env, napiEnum, entries[i].key, val);
    }
    napi_set_named_property(env, exports, name, napiEnum);
}

void RegisterIntEnum(napi_env env, napi_value exports, const char *name,
    const IntEnumEntry *entries, size_t count)
{
    napi_value napiEnum;
    napi_create_object(env, &napiEnum);
    napi_value val;
    for (size_t i = 0; i < count; ++i) {
        napi_create_int32(env, entries[i].value, &val);
        napi_set_named_property(env, napiEnum, entries[i].key, val);
    }
    napi_set_named_property(env, exports, name, napiEnum);
}

void RegisterStringEnums(napi_env env, napi_value exports)
{
    StringEnumEntry domainE[] = { {"HABIT_AWARENESS", "habitAwareness"} };
    RegisterStringEnum(env, exports, "PerceptionDomain", domainE, ARG_1);

    StringEnumEntry patternE[] = {
        {"TIME_PATTERN", "timePattern"}, {"LOCATION_PATTERN", "locationPattern"},
        {"EVENT_PATTERN", "eventPattern"}
    };
    RegisterStringEnum(env, exports, "PatternType", patternE, PATTERN_COUNT);

    StringEnumEntry etE[] = {
        {"DAILY_TIME", "dailyTime"}, {"WEEKLY_TIME", "weeklyTime"},
        {"MONTHLY_TIME", "monthlyTime"}, {"WORKDAY_TIME", "workdayTime"},
        {"LOCATION_ARRIVE", "locationArrive"}, {"APP_LAUNCH", "appLaunch"},
        {"APP_EXIT", "appExit"}, {"APP_USAGE_SINGLE", "appUsageSingle"},
        {"APP_USAGE_DAILY", "appUsageDaily"}, {"ALARM_DISMISS", "alarmDismiss"},
        {"CHARGE_START", "chargeStart"}, {"CHARGE_END", "chargeEnd"},
        {"CHARGE_FULL", "chargeFull"}, {"BATTERY_ABOVE", "batteryAbove"},
        {"BATTERY_BELOW", "batteryBelow"}, {"BLUETOOTH_CONNECT", "bluetoothConnect"},
        {"BLUETOOTH_DISCONNECT", "bluetoothDisconnect"}, {"PHONE_RING", "phoneRing"}
    };
    RegisterStringEnum(env, exports, "EventType", etE, EVENT_TYPE_COUNT);

    StringEnumEntry actE[] = {
        {"APP_CLOSE", "appClose"}, {"APP_OPEN", "appOpen"},
        {"EYE_PROTECT_MODE", "eyeProtectMode"}, {"DARK_MODE", "darkMode"},
        {"PERSONAL_HOTSPOT", "personalHotspot"}, {"MOBILE_DATA", "mobileData"},
        {"WIFI", "wifi"}, {"AIRPLANE_MODE", "airplaneMode"},
        {"BLUETOOTH", "bluetooth"}, {"NFC", "nfc"},
        {"ROTATION_LOCK", "rotationLock"}, {"POWER_SAVING", "powerSaving"},
        {"SOUND_MODE", "soundMode"}, {"SCREEN_BRIGHTNESS", "screenBrightness"},
        {"VOLUME", "volume"}, {"SHUTDOWN", "shutdown"}, {"REBOOT", "reboot"}
    };
    RegisterStringEnum(env, exports, "ActionType", actE, ACTION_TYPE_COUNT);

    StringEnumEntry soundE[] = {
        {"VIBRATE", "vibrate"}, {"SILENT", "silent"}, {"RING", "ring"}
    };
    RegisterStringEnum(env, exports, "SoundMode", soundE, SOUND_MODE_COUNT);

    StringEnumEntry recE[] = {
        {"DAILY", "daily"}, {"WEEKLY", "weekly"},
        {"MONTHLY", "monthly"}, {"WORKDAY", "workday"}
    };
    RegisterStringEnum(env, exports, "RecurrenceType", recE, RECURRENCE_COUNT);

    StringEnumEntry locE[] = {
        {"HOME", "home"}, {"COMPANY", "company"}, {"CUSTOM", "custom"}
    };
    RegisterStringEnum(env, exports, "LocationType", locE, LOCATION_COUNT);

    StringEnumEntry opE[] = { {"ON", "on"}, {"OFF", "off"}, {"TOGGLE", "toggle"} };
    RegisterStringEnum(env, exports, "Operation", opE, OPERATION_COUNT);

    StringEnumEntry adjE[] = { {"UP", "up"}, {"DOWN", "down"} };
    RegisterStringEnum(env, exports, "AdjustmentDirection", adjE, ADJUSTMENT_COUNT);
}

void RegisterIntEnums(napi_env env, napi_value exports)
{
    IntEnumEntry feedbackE[] = {
        {"ACCEPT", FEEDBACK_ACCEPT}, {"IGNORE", FEEDBACK_IGNORE},
        {"REJECT", FEEDBACK_REJECT}, {"EDIT", FEEDBACK_EDIT},
        {"NOT_PUSHED", FEEDBACK_NOT_PUSHED}
    };
    RegisterIntEnum(env, exports, "FeedbackType", feedbackE, ARG_2 + ARG_1);

    IntEnumEntry btE[] = {
        {"DEFAULT", 0}, {"CAR", 1}, {"HEADSET", 2}, {"HEARING", 3},
        {"GLASSES", 4}, {"WATCH", 5}, {"SPEAKER", 6}, {"OTHERS", 7}
    };
    RegisterIntEnum(env, exports, "BluetoothDeviceType", btE, BT_TYPE_COUNT);
}

bool IsMatchTypeImpl(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype paramType = napi_undefined;
    napi_status ret = napi_typeof(env, value, &paramType);
    if ((ret != napi_ok) || (paramType != type)) {
        FI_HILOGE("Type mismatch");
        return false;
    }
    return true;
}

bool ParsePatternTypes(napi_env env, napi_value patternVal, SubscribeOptions &options)
{
    bool isArray = false;
    napi_is_array(env, patternVal, &isArray);
    if (!isArray) {
        return true;
    }
    uint32_t length = 0;
    napi_get_array_length(env, patternVal, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value elem = nullptr;
        napi_get_element(env, patternVal, i, &elem);
        if (!IsMatchTypeImpl(env, elem, napi_string)) {
            continue;
        }
        char pbuf[64] = {0};
        size_t plen = 0;
        napi_get_value_string_utf8(env, elem, pbuf, sizeof(pbuf), &plen);
        std::string ps(pbuf);
        if (ps == "timePattern") {
            options.patternTypes.push_back(static_cast<int32_t>(PatternType::TIME_PATTERN));
        } else if (ps == "locationPattern") {
            options.patternTypes.push_back(static_cast<int32_t>(PatternType::LOCATION_PATTERN));
        } else if (ps == "eventPattern") {
            options.patternTypes.push_back(static_cast<int32_t>(PatternType::EVENT_PATTERN));
        }
    }
    return true;
}

} // namespace

BehaviorAwarenessNapiCallback::~BehaviorAwarenessNapiCallback()
{
    if (env_ != nullptr && callbackRef_ != nullptr) {
        napi_delete_reference(env_, callbackRef_);
    }
}

void BehaviorAwarenessNapiCallback::OnBehaviorAwareness(const PerceptionEventData &event)
{
    sptr<BehaviorAwarenessNapiCallback> self(this);
    auto task = [self, event]() {
        napi_env env = self->env_;
        napi_ref ref = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            ref = self->callbackRef_;
        }
        if (ref == nullptr) {
            FI_HILOGE("OnBehaviorAwareness: callback ref is null");
            return;
        }
        napi_value handler = nullptr;
        if (napi_get_reference_value(env, ref, &handler) != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            return;
        }
        napi_value eventObj = BehaviorAwarenessNapi::ConstructPerceptionEvent(env, event);
        if (eventObj == nullptr) {
            FI_HILOGE("Failed to construct PerceptionEvent");
            return;
        }
        napi_value callResult = nullptr;
        napi_call_function(env, nullptr, handler, ARG_1, &eventObj, &callResult);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "behaviorAwareness.onPerception") != napi_ok) {
        FI_HILOGE("Failed to send event");
    }
}

napi_value BehaviorAwarenessNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("onPerception", OnPerception),
        DECLARE_NAPI_STATIC_FUNCTION("offPerception", OffPerception),
        DECLARE_NAPI_STATIC_FUNCTION("submitFeedback", SubmitFeedback),
    };
    napi_status status = napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    if (status != napi_ok) {
        FI_HILOGE("napi_define_properties failed");
        return nullptr;
    }
    RegisterStringEnums(env, exports);
    RegisterIntEnums(env, exports);
    FI_HILOGD("Exit");
    return exports;
}

bool BehaviorAwarenessNapi::IsMatchType(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype paramType = napi_undefined;
    napi_status ret = napi_typeof(env, value, &paramType);
    if ((ret != napi_ok) || (paramType != type)) {
        FI_HILOGE("Type mismatch");
        return false;
    }
    return true;
}

bool BehaviorAwarenessNapi::GetSubscribeOptions(napi_env env, napi_value jsOptions, SubscribeOptions &options)
{
    if (!IsMatchType(env, jsOptions, napi_object)) {
        return false;
    }
    napi_value domainVal = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, jsOptions, "domain", &hasProp);
    if (!hasProp) {
        FI_HILOGE("options.domain is missing");
        return false;
    }
    napi_get_named_property(env, jsOptions, "domain", &domainVal);
    if (!IsMatchType(env, domainVal, napi_string)) {
        FI_HILOGE("options.domain must be string");
        return false;
    }
    char buf[64] = {0};
    size_t len = 0;
    napi_get_value_string_utf8(env, domainVal, buf, sizeof(buf), &len);
    if (std::string(buf) == "habitAwareness") {
        options.domain = PerceptionDomain::HABIT_AWARENESS;
    } else {
        FI_HILOGE("options.domain value '%{public}s' is invalid", buf);
        return false;
    }
    napi_value patternVal = nullptr;
    napi_has_named_property(env, jsOptions, "patternTypes", &hasProp);
    if (hasProp) {
        napi_get_named_property(env, jsOptions, "patternTypes", &patternVal);
        ParsePatternTypes(env, patternVal, options);
    }
    return true;
}

bool BehaviorAwarenessNapi::GetFeedbackData(napi_env env, napi_value jsFeedback, FeedbackData &feedback)
{
    if (!IsMatchType(env, jsFeedback, napi_object)) {
        return false;
    }
    napi_value idVal = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, jsFeedback, "perceptionEventId", &hasProp);
    if (!hasProp) {
        FI_HILOGE("feedback.perceptionEventId is missing");
        return false;
    }
    napi_get_named_property(env, jsFeedback, "perceptionEventId", &idVal);
    if (!IsMatchType(env, idVal, napi_string)) {
        FI_HILOGE("feedback.perceptionEventId must be string");
        return false;
    }
    size_t len = 0;
    napi_get_value_string_utf8(env, idVal, nullptr, 0, &len);
    std::vector<char> buf(len + 1);
    napi_get_value_string_utf8(env, idVal, buf.data(), len + 1, &len);
    feedback.perceptionEventId = buf.data();

    napi_value typeVal = nullptr;
    napi_has_named_property(env, jsFeedback, "feedbackType", &hasProp);
    if (!hasProp) {
        FI_HILOGE("feedback.feedbackType is missing");
        return false;
    }
    napi_get_named_property(env, jsFeedback, "feedbackType", &typeVal);
    int32_t ft = 0;
    napi_get_value_int32(env, typeVal, &ft);
    feedback.feedbackType = static_cast<FeedbackType>(ft);

    napi_value timeVal = nullptr;
    napi_has_named_property(env, jsFeedback, "feedbackTime", &hasProp);
    if (!hasProp) {
        FI_HILOGE("feedback.feedbackTime is missing");
        return false;
    }
    napi_get_named_property(env, jsFeedback, "feedbackTime", &timeVal);
    napi_get_value_int64(env, timeVal, &feedback.feedbackTime);
    return true;
}

napi_value BehaviorAwarenessNapi::ConstructPerceptionEvent(napi_env env, const PerceptionEventData &event)
{
    napi_value eventObj = nullptr;
    napi_create_object(env, &eventObj);
    if (!SetStringProperty(env, eventObj, event.perceptionEventId, "perceptionEventId")) {
        return nullptr;
    }
    const char *domainStr = "habitAwareness";
    if (static_cast<int32_t>(event.domain) != 0) {
        FI_HILOGE("Unknown domain value: %{public}d", static_cast<int32_t>(event.domain));
        return nullptr;
    }
    if (!SetStringProperty(env, eventObj, domainStr, "domain")) {
        return nullptr;
    }
    if (!SetInt32Property(env, eventObj, event.confidence, "confidence")) {
        return nullptr;
    }
    if (!SetInt64Property(env, eventObj, event.generateTime, "generateTime")) {
        return nullptr;
    }
    napi_value payloadObj = nullptr;
    if (event.payload.empty()) {
        napi_create_object(env, &payloadObj);
    } else {
        napi_create_string_utf8(env, event.payload.c_str(), NAPI_AUTO_LENGTH, &payloadObj);
    }
    if (!SetPropertyName(env, eventObj, "payload", payloadObj)) {
        return nullptr;
    }
    return eventObj;
}

bool BehaviorAwarenessNapi::SetStringProperty(napi_env env, napi_value targetObj,
    const std::string &value, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &prop);
    return SetPropertyName(env, targetObj, propName, prop);
}

bool BehaviorAwarenessNapi::SetInt32Property(napi_env env, napi_value targetObj,
    int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, value, &prop);
    return SetPropertyName(env, targetObj, propName, prop);
}

bool BehaviorAwarenessNapi::SetInt64Property(napi_env env, napi_value targetObj,
    int64_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_int64(env, value, &prop);
    return SetPropertyName(env, targetObj, propName, prop);
}

bool BehaviorAwarenessNapi::SetPropertyName(napi_env env, napi_value targetObj,
    const char *propName, napi_value propValue)
{
    napi_status ret = napi_set_named_property(env, targetObj, propName, propValue);
    if (ret != napi_ok) {
        FI_HILOGE("napi_set_named_property(%{public}s) failed", propName);
        return false;
    }
    return true;
}

napi_value BehaviorAwarenessNapi::OnPerception(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OnPerception: enter");
    napi_deferred deferred = nullptr;
    napi_value promise = CreatePromise(env, &deferred);
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc < ARG_2) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "expected 2 args: options, callback");
        return promise;
    }
    SubscribeOptions options;
    if (!GetSubscribeOptions(env, args[ARG_0], options)) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "options is invalid");
        return promise;
    }
    if (!IsMatchType(env, args[ARG_1], napi_function)) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "callback must be function");
        return promise;
    }
    std::string key = BuildSubscriptionKey(options);
    bool isNewStub = false;
    sptr<BehaviorAwarenessNapiCallback> stub;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        auto iter = g_callbacks.find(key);
        if (iter != g_callbacks.end()) {
            stub = iter->second;
        } else {
            stub = new (std::nothrow) BehaviorAwarenessNapiCallback(env);
            if (stub == nullptr) {
                RejectPromise(env, deferred, RET_SERVICE_EXCEPTION, "failed to create callback");
                return promise;
            }
            g_callbacks[key] = stub;
            isNewStub = true;
        }
    }
    napi_ref newRef = nullptr;
    napi_create_reference(env, args[ARG_1], ARG_1, &newRef);
    int32_t errNum = BehaviorAwarenessManager::GetInstance().SubscribePerception(options, stub);
    if (errNum != RET_OK) {
        if (newRef != nullptr) {
            napi_delete_reference(env, newRef);
        }
        if (isNewStub) {
            std::lock_guard<std::mutex> lk(g_mtx);
            g_callbacks.erase(key);
        }
        RejectPromise(env, deferred, errNum, "subscribe failed");
        return promise;
    }
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (stub->callbackRef_ != nullptr) {
            napi_delete_reference(env, stub->callbackRef_);
        }
        stub->callbackRef_ = newRef;
    }
    FI_HILOGI("OnPerception: success, key:%{public}s, isNew:%{public}d", key.c_str(), isNewStub);
    return ResolvePromise(env, deferred);
}

napi_value BehaviorAwarenessNapi::OffPerception(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OffPerception: enter");
    napi_deferred deferred = nullptr;
    napi_value promise = CreatePromise(env, &deferred);
    if (!CheckCallerIsSystemApp()) {
        FI_HILOGE("OffPerception: non-system app");
        RejectPromise(env, deferred, RET_NO_SYSTEM_API, "non-system app");
        return promise;
    }
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        RejectPromise(env, deferred, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return promise;
    }
    if (argc >= ARG_1 && !IsMatchType(env, args[ARG_0], napi_function)) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "callback must be function or omitted");
        return promise;
    }
    bool hasCallback = (argc >= ARG_1) && IsMatchTypeImpl(env, args[ARG_0], napi_function);
    if (hasCallback) {
        std::vector<std::pair<std::string, sptr<BehaviorAwarenessNapiCallback>>> matches;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            for (auto &item : g_callbacks) {
                const sptr<BehaviorAwarenessNapiCallback> &cb = item.second;
                if (cb == nullptr || cb->callbackRef_ == nullptr) {
                    continue;
                }
                napi_value registeredCb = nullptr;
                napi_get_reference_value(env, cb->callbackRef_, &registeredCb);
                bool strictEqual = false;
                napi_strict_equals(env, args[ARG_0], registeredCb, &strictEqual);
                if (strictEqual) {
                    matches.emplace_back(item.first, cb);
                }
            }
        }
        if (matches.empty()) {
            RejectPromise(env, deferred, RET_UNSUBSCRIBE_EXCEPTION, "no active subscription");
            return promise;
        }
        int32_t lastErr = RET_OK;
        for (auto &m : matches) {
            int32_t err = BehaviorAwarenessManager::GetInstance().UnsubscribePerception(m.second);
            if (err != RET_OK) {
                lastErr = err;
            }
        }
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            for (auto &m : matches) {
                auto iter = g_callbacks.find(m.first);
                if (iter != g_callbacks.end() && iter->second != nullptr && iter->second->callbackRef_ != nullptr) {
                    napi_delete_reference(env, iter->second->callbackRef_);
                    iter->second->callbackRef_ = nullptr;
                }
                g_callbacks.erase(m.first);
            }
        }
        if (lastErr != RET_OK) {
            RejectPromise(env, deferred, lastErr, "unsubscribe failed");
            return promise;
        }
    } else {
        int32_t errNum = BehaviorAwarenessManager::GetInstance().UnsubscribePerception(nullptr);
        if (errNum != RET_OK) {
            RejectPromise(env, deferred, errNum, "unsubscribe failed");
            return promise;
        }
        ClearAllCallbacks(env);
    }
    FI_HILOGI("OffPerception: success");
    return ResolvePromise(env, deferred);
}

napi_value BehaviorAwarenessNapi::SubmitFeedback(napi_env env, napi_callback_info info)
{
    FI_HILOGI("SubmitFeedback: enter");
    napi_deferred deferred = nullptr;
    napi_value promise = CreatePromise(env, &deferred);
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc < ARG_1) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "expected 1 arg: feedback");
        return promise;
    }
    FeedbackData feedback;
    if (!GetFeedbackData(env, args[ARG_0], feedback)) {
        RejectPromise(env, deferred, RET_PARAM_EXCEPTION, "feedback is invalid");
        return promise;
    }
    int32_t errNum = BehaviorAwarenessManager::GetInstance().SubmitFeedback(feedback);
    if (errNum != RET_OK) {
        RejectPromise(env, deferred, errNum, "submitFeedback failed");
        return promise;
    }
    FI_HILOGI("SubmitFeedback: success");
    return ResolvePromise(env, deferred);
}

EXTERN_C_START
static napi_value BehaviorAwarenessNapiInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = BehaviorAwarenessNapi::Init(env, exports);
    if (ret == nullptr) {
        FI_HILOGE("Failed to init");
        return ret;
    }
    return ret;
}
EXTERN_C_END

static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.behaviorAwareness",
    .nm_register_func = BehaviorAwarenessNapiInit,
    .nm_modname = "multimodalAwareness.behaviorAwareness",
    .nm_priv = (static_cast<void *>(nullptr)),
    .reserved = { nullptr }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
