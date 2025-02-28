/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_DUMPER_H
#define DEVICESTATUS_DUMPER_H

#include <map>
#include <memory>
#include <queue>
#include <refbase.h>
#include <set>
#include <string>
#include <vector>

#include <singleton.h>

#include "accesstoken_kit.h"
#include "boomerang_callback.h"
#include "i_context.h"
#include "stationary_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
inline constexpr int32_t RET_NG { -1 };

struct AppInfo {
    std::string startTime;
    int32_t uid {};
    int32_t pid {};
    Security::AccessToken::AccessTokenID tokenId;
    std::string packageName;
    Type type { TYPE_INVALID };
    sptr<IRemoteDevStaCallback> callback { nullptr };
    sptr<IRemoteBoomerangCallback> boomerangCallback { nullptr };
};

struct BoomerangAppInfo {
    std::string startTime;
    int32_t uid {};
    int32_t pid {};
    Security::AccessToken::AccessTokenID tokenId;
    std::string packageName;
    BoomerangType type { BOOMERANG_TYPE_INVALID };
    sptr<IRemoteBoomerangCallback> boomerangCallback { nullptr };
};

struct DeviceStatusRecord {
    std::string startTime;
    Data data;
};

class DeviceStatusDumper final : public RefBase {
    DECLARE_DELAYED_SINGLETON(DeviceStatusDumper);
public:
    int32_t Init(IContext *context);
    void ParseCommand(int32_t fd, const std::vector<std::string> &args, const std::vector<Data> &datas);
    void DumpHelpInfo(int32_t fd) const;
    void SaveAppInfo(std::shared_ptr<AppInfo> appInfo);
    void RemoveAppInfo(std::shared_ptr<AppInfo> appInfo);
    void PushDeviceStatus(const Data &data);
    std::string GetPackageName(Security::AccessToken::AccessTokenID tokenId);

    void DumpDeviceStatusSubscriber(int32_t fd);
    void DumpDeviceStatusChanges(int32_t fd);
    void DumpDeviceStatusCurrentStatus(int32_t fd, const std::vector<Data> &datas) const;

    void SaveBoomerangAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo);
    void RemoveBoomerangAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo);
    void SetNotifyMetadatAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo);

private:
    DISALLOW_COPY_AND_MOVE(DeviceStatusDumper);
    std::string GetStatusType(Type type) const;
    std::string GetDeviceState(OnChangedValue type) const;
    void ExecutDump(int32_t fd, const std::vector<Data> &datas, int32_t opt);
    void DumpCheckDefine(int32_t fd);
    void ChkDefineOutput(int32_t fd);
    template<class ...Ts>
    void CheckDefineOutput(int32_t fd, const char* fmt, Ts... args);

private:
    std::map<Type, std::set<std::shared_ptr<AppInfo>>> appInfos_;
    std::map<BoomerangType, std::set<std::shared_ptr<BoomerangAppInfo>>> boomerangAppInfos_;
    std::shared_ptr<BoomerangAppInfo> notifyMetadatAppInfo_;
    std::queue<std::shared_ptr<DeviceStatusRecord>> deviceStatusQueue_;
    std::mutex mutex_;
    IContext *context_ { nullptr };
};

#define DS_DUMPER OHOS::DelayedSingleton<DeviceStatusDumper>::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_DUMPER_H
