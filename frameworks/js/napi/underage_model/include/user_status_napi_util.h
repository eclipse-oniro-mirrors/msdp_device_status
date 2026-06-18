/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USER_STATUS_NAPI_UTIL_H
#define USER_STATUS_NAPI_UTIL_H

#include <chrono>
#include <functional>
#include <set>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"

#include "comfort_reminder_data.h"
#include "user_status_data.h"
#include "play_ability_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
constexpr uint32_t FEATURE_USER_PLAY_ABILITY_FATIGUE = 5;
constexpr uint32_t FEATURE_ANTI_MISTOUCH = 6;
constexpr uint32_t FEATURE_USER_GESTURE = 7;
constexpr uint32_t FEATURE_USER_FACE = 8;
constexpr uint32_t FEATURE_USER_PLAYING = 9;
constexpr uint32_t FEATURE_USER_FACE_ANGLE = 11;
constexpr uint32_t FEATURE_USER_BLOW = 12;
constexpr uint32_t FEATURE_USER_MOOD = 13;
constexpr uint32_t FEATURE_COMFORT_REMINDER = 15;
constexpr uint32_t FEATURE_ENV_SOUND = 17;
constexpr uint32_t FEATURE_LEM_EXT_SCREEN_ANTI_MISTOUCH = 19;
inline const std::set<uint32_t> SUPPORT_FEATURES  = {
    FEATURE_USER_PLAY_ABILITY_FATIGUE, FEATURE_ANTI_MISTOUCH, FEATURE_USER_GESTURE, FEATURE_USER_FACE,
    FEATURE_USER_PLAYING, FEATURE_USER_FACE_ANGLE, FEATURE_USER_BLOW, FEATURE_USER_MOOD, FEATURE_COMFORT_REMINDER,
    FEATURE_ENV_SOUND, FEATURE_LEM_EXT_SCREEN_ANTI_MISTOUCH };

constexpr int32_t PARAM_ERROR { 401 };
constexpr int32_t SERVICE_EXCEPTION { 801 };
inline const std::map <int32_t, std::string> ERROR_MESSAGES = {
    {SERVICE_EXCEPTION, "Service exception"},
    {PARAM_ERROR, "Param error"}
};

struct UserStatusNapiResult {
    uint32_t feature { 0 };
    std::string statusDescription;
    int32_t result { -1 };
    int32_t errCode { -1 };
};

class UserStatusNapiUtil {
public:
    static napi_value NapiGetNull(napi_env env);
    static void ParseIntArray(const napi_env& env, const napi_value& value, std::vector<std::int32_t>& result);
    static napi_status VerifyProperty(napi_env env, const napi_value object, const char *fieldStr);
    static napi_value JsObjectToString(napi_env env, const napi_value object,
        const char *fieldStr, int32_t bufLen, std::string &fieldRef);
    static napi_value JsObjectToInt(napi_env env, const napi_value object,
        const char *fieldStr, int32_t& fieldRef);
    static napi_value JsObjectToUint(napi_env env, const napi_value object,
        const char *fieldStr, uint32_t& fieldRef);
    static napi_value JsObjectToBool(napi_env env, const napi_value object,
        const char *fieldStr, bool& fieldRef);
    static napi_status SetValueUTF8String(napi_env env, const char *fieldStr,
        const char *str, napi_value result, size_t strLen = NAPI_AUTO_LENGTH);
    static napi_status SetValueInt32(napi_env env, const char *fieldStr, int32_t intValue,
        napi_value result);
    static napi_status SetValueFloat(napi_env env, const char *fieldStr, float floatValue,
        napi_value result);
    static napi_status SetValueUnsignedInt32(napi_env env, const char *fieldStr, uint32_t intValue,
        napi_value result);
    static napi_status SetValueInt64(napi_env env, const char *fieldStr, int64_t intValue, napi_value result);
    static napi_status SetValueBool(napi_env env, const char *fieldStr, bool boolValue, napi_value result);
    static napi_value UndefinedNapiValue(napi_env env);

    static napi_value GetNapiValueByInt32(napi_env env, int32_t number);
    static napi_value GetNapiUInt32(napi_env env, int32_t number);
    static void ReportUserDataToJs(napi_env env, std::shared_ptr<UserStatusData> data, napi_value userData);

    static void GetUserDataToJs(napi_env env, UserStatusNapiResult& statusResult, napi_value result);
    static void ExceptionProcess(napi_env);
    static void SetJsArrayProperty(napi_env env, const std::vector<float>& vec, const char* key,
        napi_value& jsData);
    static void SetComfortReminderData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData);
    static void SetBlowJsData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData);
    static void SetMoodJsData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData);
    static void SetJsGesturesData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData);
    static void SetPlayAbilityData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData);
    static napi_status VectorToJsArray(napi_env env, const std::vector<float>& vec, napi_value& arrayResult);
    static napi_status Int32VectorToJsArray(napi_env env, const std::vector<int32_t>& vec, napi_value& arrayResult);

    static napi_value CreateNapiError(napi_env env, int32_t errCode, const std::string &errMessage);
    static std::optional<std::string> GetErrMsg(int32_t errorCode);
    static void ThrowErr(napi_env env, int32_t errCode, const std::string &printMsg);
    static bool IsSupportedFeature(uint32_t feature);
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // USER_STATUS_NAPI_UTIL_H
