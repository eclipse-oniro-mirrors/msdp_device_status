/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "utility.h"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <limits>
#include <map>
#include <regex>
#include <sstream>

#include <sys/stat.h>
#include <sys/types.h>

#include "parcel.h"
#include "securec.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "Utility"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t SUBSTR_ID_LENGTH { 5 };
constexpr int32_t MULTIPLES { 2 };
constexpr size_t DFX_RADAR_MASK_SIZE { 2 };
} // namespace

size_t Utility::CopyNulstr(char *dest, size_t size, const char *src)
{
    CHKPR(dest, 0);
    CHKPR(src, 0);

    size_t len = strlen(src);
    if (len >= size) {
        if (size > 1) {
            len = size - 1;
        } else {
            len = 0;
        }
    }
    if (len > 0) {
        errno_t ret = memcpy_s(dest, size, src, len);
        if (ret != EOK) {
            FI_HILOGW("memcpy_s:bounds checking failed");
        }
    }
    if (size > 0) {
        dest[len] = '\0';
    }
    return len;
}

bool Utility::StartWith(const char *str, const char *prefix)
{
    size_t prefixlen = strlen(prefix);
    return (prefixlen > 0 ? (strncmp(str, prefix, strlen(prefix)) == 0) : false);
}

bool Utility::StartWith(const std::string &str, const std::string &prefix)
{
    if (str.size() < prefix.size()) {
        return false;
    }
    return (str.compare(0, prefix.size(), prefix) == 0);
}

void Utility::RemoveTrailingChars(char c, char *path)
{
    CHKPV(path);
    size_t len = strlen(path);
    while (len > 0 && path[len-1] == c) {
        path[--len] = '\0';
    }
}

void Utility::RemoveTrailingChars(const std::string &toRemoved, std::string &path)
{
    while (!path.empty() && (toRemoved.find(path.back()) != std::string::npos)) {
        path.pop_back();
    }
}

void Utility::RemoveSpace(std::string &str)
{
    str.erase(remove_if(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c);}), str.end());
}

bool Utility::IsInteger(const std::string &target)
{
    std::regex pattern("^\\s*-?(0|([1-9]\\d*))\\s*$");
    return std::regex_match(target, pattern);
}

std::string Utility::Anonymize(const char* id)
{
    if (id == nullptr) {
        return std::string(MULTIPLES * SUBSTR_ID_LENGTH, '*');
    }
    std::string idStr(id);
    if (idStr.empty() || idStr.length() < SUBSTR_ID_LENGTH) {
        return std::string(MULTIPLES * SUBSTR_ID_LENGTH, '*');
    }
    return idStr.substr(0, SUBSTR_ID_LENGTH) + std::string(SUBSTR_ID_LENGTH, '*') +
        idStr.substr(idStr.length() - SUBSTR_ID_LENGTH);
}

std::string Utility::DFXRadarAnonymize(const char* id)
{
    if (id == nullptr) {
        return std::string(MULTIPLES * SUBSTR_ID_LENGTH, '*');
    }
    std::string idStr(id);
    if (idStr.empty() || idStr.length() < SUBSTR_ID_LENGTH) {
        return std::string(MULTIPLES * SUBSTR_ID_LENGTH, '*');
    }
    return idStr.substr(0, SUBSTR_ID_LENGTH) + std::string(DFX_RADAR_MASK_SIZE, '*') +
        idStr.substr(idStr.length() - SUBSTR_ID_LENGTH);
}

bool Utility::DoesFileExist(const char *path)
{
    return (access(path, F_OK) == 0);
}

ssize_t Utility::GetFileSize(const std::string &filePath)
{
    return GetFileSize(filePath.c_str());
}

ssize_t Utility::GetFileSize(const char *path)
{
    struct stat buf {};
    ssize_t sz { 0 };

    if (stat(path, &buf) == 0) {
        if (S_ISREG(buf.st_mode)) {
            sz = buf.st_size;
        } else {
            FI_HILOGE("Not regular file:\'%{public}s\'", path);
        }
    } else {
        FI_HILOGE("stat(\'%{public}s\') failed:%{public}s", path, strerror(errno));
    }
    return sz;
}

void Utility::ShowFileAttributes(const char *path)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("======================= File Attributes ========================");
    FI_HILOGD("%{public}20s:%{public}s", "FILE NAME", path);

    struct stat buf {};
    if (stat(path, &buf) != 0) {
        FI_HILOGE("stat(\'%{public}s\') failed:%{public}s", path, strerror(errno));
        return;
    }
    if (S_ISDIR(buf.st_mode)) {
        FI_HILOGD("%{public}20s: directory", "TYPE");
    } else if (S_ISCHR(buf.st_mode)) {
        FI_HILOGD("%{public}20s: character special file", "TYPE");
    } else if (S_ISREG(buf.st_mode)) {
        FI_HILOGD("%{public}20s: regular file", "TYPE");
    }

    std::ostringstream ss;
    std::map<mode_t, std::string> modes {{S_IRUSR, "U+R "}, {S_IWUSR, "U+W "}, {S_IXUSR, "U+X "}, {S_IRGRP, "G+R "},
        {S_IWGRP, "G+W "}, {S_IXGRP, "G+X "}, {S_IROTH, "O+R "}, {S_IWOTH, "O+W "}, {S_IXOTH, "O+X "}};
    for (const auto &element : modes) {
        if (buf.st_mode & element.first) {
            ss << element.second;
            break;
        }
    }

    FI_HILOGD("%{public}20s:%{public}s", "PERMISSIONS", ss.str().c_str());
}

void Utility::ShowUserAndGroup()
{
    CALL_DEBUG_ENTER;
    static constexpr size_t BUFSIZE { 1024 };
    char buffer[BUFSIZE];
    struct passwd buf;
    struct passwd *pbuf = nullptr;
    struct group grp;
    struct group *pgrp = nullptr;

    FI_HILOGD("======================= Users and Groups =======================");
    uid_t uid = getuid();
    if (getpwuid_r(uid, &buf, buffer, sizeof(buffer), &pbuf) != 0) {
        FI_HILOGE("getpwuid_r failed:%{public}s", strerror(errno));
    } else {
        FI_HILOGD("%{public}20s:%{public}10u%{public}20s", "USER", uid, buf.pw_name);
    }

    gid_t gid = getgid();
    if (getgrgid_r(gid, &grp, buffer, sizeof(buffer), &pgrp) != 0) {
        FI_HILOGE("getgrgid_r failed:%{public}s", strerror(errno));
    } else {
        FI_HILOGD("%{public}20s:%{public}10u%{public}20s", "GROUP", gid, grp.gr_name);
    }

    uid = geteuid();
    if (getpwuid_r(uid, &buf, buffer, sizeof(buffer), &pbuf) != 0) {
        FI_HILOGE("getpwuid_r failed:%{public}s", strerror(errno));
    } else {
        FI_HILOGD("%{public}20s:%{public}10u%{public}20s", "EFFECTIVE USER", uid, buf.pw_name);
    }

    gid = getegid();
    if (getgrgid_r(gid, &grp, buffer, sizeof(buffer), &pgrp) != 0) {
        FI_HILOGE("getgrgid_r failed:%{public}s", strerror(errno));
    } else {
        FI_HILOGD("%{public}20s:%{public}10u%{public}20s", "EFFECTIVE GROUP", gid, grp.gr_name);
    }

    gid_t groups[NGROUPS_MAX + 1];
    int32_t ngrps = getgroups(sizeof(groups), groups);
    for (int32_t i = 0; i < ngrps; ++i) {
        if (getgrgid_r(groups[i], &grp, buffer, sizeof(buffer), &pgrp) != 0) {
            FI_HILOGE("getgrgid_r failed:%{public}s", strerror(errno));
        } else {
            FI_HILOGD("%{public}20s:%{public}10u%{public}20s", "SUPPLEMENTARY GROUP", groups[i], grp.gr_name);
        }
    }
}

int64_t Utility::GetSysClockTime()
{
    return std::chrono::time_point_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now()).time_since_epoch().count();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
