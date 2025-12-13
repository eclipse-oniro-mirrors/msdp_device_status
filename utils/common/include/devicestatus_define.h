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

#ifndef DEVICESTATUS_DEFINE_H
#define DEVICESTATUS_DEFINE_H

#include <chrono>

#include "devicestatus_errors.h"
#include "fi_log.h"
#include "include/util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#define FI_PKG_NAME "ohos.msdp.fusioninteraction"
#define COOPERATE_PERMISSION "ohos.permission.COOPERATE_MANAGER"

using TimeStamp = std::chrono::high_resolution_clock::time_point;

#ifndef RET_OK
    #define RET_OK (0)
#endif

#ifndef RET_ERR
    #define RET_ERR (-1)
#endif

#define CHKEF(errCode, desc) \
    do { \
        if ((errCode) != RET_OK) { \
            FI_HILOGE("%{public}s", desc); \
            return false; \
        } \
    } while (0)

#define CHKPL(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGW("CHKPL(%{public}s) is null, do nothing", #cond); \
        } \
    } while (0)

#define CHKPV(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGE("CHKPV(%{public}s) is null", #cond); \
            return; \
        } \
    } while (0)

#define CHKPF(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGE("CHKPF(%{public}s) is null", #cond); \
            return false; \
        } \
    } while (0)

#define CHKPS(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGE("CHKPS(%{public}s) is null", #cond); \
            return {}; \
        } \
    } while (0)

#define CHKPC(cond) \
    { \
        if ((cond) == nullptr) { \
            FI_HILOGW("CHKPC(%{public}s) is null, skip then continue", #cond); \
            continue; \
        } \
    }

#define CHKPB(cond) \
    { \
        if ((cond) == nullptr) { \
            FI_HILOGW("CHKPB(%{public}s) is null, skip then break", #cond); \
            break; \
        } \
    }

#define CHKPR(cond, r) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGE("CHKPR(%{public}s) is null, return value is %{public}d", #cond, r); \
            return r; \
        } \
    } while (0)

#define CHKPP(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGE("CHKPP(%{public}s) is null, return value is null", #cond); \
            return nullptr; \
        } \
    } while (0)

#define CHKPO(cond) \
    do { \
        if ((cond) == nullptr) { \
            FI_HILOGW("%{public}s, (%{public}d), CHKPO(%{public}s) is null, return object is null", \
                __FILE__, __LINE__, #cond); \
            return {}; \
        } \
    } while (0)

#define CHK_PID_AND_TID() \
    do { \
        FI_HILOGD("%{public}s, (%{public}d), pid:%{public}d, threadId:%{public}" PRIu64, \
            __FILE__, __LINE__, GetPid(), GetThisThreadId()); \
    } while (0)

#define CHKCF(cond, errDesc) \
    do { \
        if (!(cond)) { \
            FI_HILOGE("%{public}s", errDesc); \
            return false; \
        } \
    } while (0)
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_DEFINE_H
