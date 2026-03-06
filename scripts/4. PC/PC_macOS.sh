#!/bin/bash
#================================================================
# macOS PC 보안 진단 스크립트
# KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준
#================================================================
# 버전  : 2603070
# 대상  : macOS 12+
# 항목  : PC-01 ~ PC-18 (18개)
# 제작  : Seedgen
#================================================================
META_STD="KISA"

#================================================================
# INIT
#================================================================
META_VER="1.0"
META_PLAT="macOS"
META_TYPE="PC"

# 권한 체크
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한으로 실행하세요. (sudo $0)"
    exit 1
fi

# XML 특수문자 이스케이프
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    echo "$s"
}

# 결과 출력 함수
output_checkpoint() {
    local CODE="$1"
    local CAT="$2"
    local NAME="$3"
    local IMP="$4"
    local STD="$5"
    local RES="$6"
    local DESC="$7"
    local DT="$8"

    case "$RES" in
        "Y")   echo -e "    [\033[32mY\033[0m] $CODE $NAME" ;;
        "N")   echo -e "    [\033[31mN\033[0m] $CODE $NAME" ;;
        "M")   echo -e "    [\033[33mM\033[0m] $CODE $NAME" ;;
        "N/A") echo -e "    [\033[90m-\033[0m] $CODE $NAME" ;;
        *)     echo -e "    [-] $CODE $NAME" ;;
    esac

    local E_NAME; E_NAME=$(xml_escape "$NAME")
    local E_DESC; E_DESC=$(xml_escape "$DESC")
    cat >> "$OUTPUT_FILE" << CPEOF
        <cp>
            <code>$CODE</code>
            <cat>$CAT</cat>
            <n>$E_NAME</n>
            <imp>$IMP</imp>
            <std>$STD</std>
            <res>$RES</res>
            <desc>$E_DESC</desc>
            <dt><![CDATA[$DT]]></dt>
        </cp>
CPEOF
}

#================================================================
# UI — 사용자 정보 입력
#================================================================
echo ""
echo "  $META_PLAT PC Security Assessment v$META_VER [$META_STD]"
echo "  ─────────────────────────────────────────────────────────"
echo ""
read -r -p "  부서명: " USER_DEPT
read -r -p "  사용자명: " USER_NAME
echo ""

if [ -z "$USER_DEPT" ]; then USER_DEPT="Unknown"; fi
if [ -z "$USER_NAME" ]; then USER_NAME=$(whoami); fi

USER_DEPT=$(echo "$USER_DEPT" | tr -d '\\/:*?"<>|')
USER_NAME=$(echo "$USER_NAME" | tr -d '\\/:*?"<>|')

#================================================================
# COLLECT
#================================================================
META_DATE=$(date +%Y-%m-%dT%H:%M:%S%z | sed 's/\([+-][0-9][0-9]\)\([0-9][0-9]\)$/\1:\2/')
SYS_HOST=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || hostname)
SYS_DOM=$(hostname -f 2>/dev/null || echo "N/A")

SYS_OS_NAME="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
SYS_OS_FN="macOS $(sw_vers -productVersion 2>/dev/null)"
SYS_KN=$(sw_vers -buildVersion 2>/dev/null)
SYS_ARCH=$(uname -m)

SYS_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "N/A")
SYS_NET_ALL=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}')

# 출력 파일 경로
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/${META_PLAT}_${SYS_HOST}_$(date +%Y%m%d_%H%M%S).xml"

#================================================================
# CHECK FUNCTIONS
#================================================================

check01() {
    local CODE="PC-01"
    local CAT="계정관리"
    local NAME="비밀번호의 주기적 변경"
    local IMP="상"
    local STD="비밀번호 만료 정책이 90일 이하로 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 비밀번호 만료 정책 확인 (pwpolicy)
    PW_POLICY=$(pwpolicy -getaccountpolicies 2>/dev/null | tail -n +2)

    if [ -z "$PW_POLICY" ]; then
        RES="N"
        DESC="비밀번호 만료 정책이 설정되지 않음"
        DT="pwpolicy 출력: 정책 없음"
    else
        # policyAttributeExpiresEveryN 또는 maxMinutesUntilChangePassword 파싱
        EXPIRE_MINS=""

        # policyAttributeExpiresEveryN 검색
        EXPIRE_VAL=$(echo "$PW_POLICY" | grep -A1 "policyAttributeExpiresEveryN" | grep "<integer>" | sed 's/[^0-9]//g')
        if [ -n "$EXPIRE_VAL" ]; then
            EXPIRE_MINS="$EXPIRE_VAL"
        fi

        # maxMinutesUntilChangePassword 검색 (대체 키)
        if [ -z "$EXPIRE_MINS" ]; then
            EXPIRE_VAL=$(echo "$PW_POLICY" | grep -A1 "maxMinutesUntilChangePassword" | grep "<integer>" | sed 's/[^0-9]//g')
            if [ -n "$EXPIRE_VAL" ]; then
                EXPIRE_MINS="$EXPIRE_VAL"
            fi
        fi

        if [ -z "$EXPIRE_MINS" ]; then
            RES="N"
            DESC="비밀번호 만료 정책이 설정되지 않음 (정책 존재하나 만료 기간 미설정)"
        elif [ "$EXPIRE_MINS" -le 129600 ] 2>/dev/null; then
            EXPIRE_DAYS=$((EXPIRE_MINS / 1440))
            RES="Y"
            DESC="비밀번호 만료 정책 설정됨 (${EXPIRE_DAYS}일)"
        else
            EXPIRE_DAYS=$((EXPIRE_MINS / 1440))
            RES="N"
            DESC="비밀번호 만료 기간 초과 (현재: ${EXPIRE_DAYS}일, 기준: 90일 이하)"
        fi

        DT="pwpolicy 출력:\n${PW_POLICY}\n\n만료 설정(분): ${EXPIRE_MINS:-미설정}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check02() {
    local CODE="PC-02"
    local CAT="계정관리"
    local NAME="비밀번호 관리정책 설정"
    local IMP="상"
    local STD="복잡성을 만족하는 비밀번호 정책이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 비밀번호 복잡성 정책 확인 (pwpolicy)
    PW_POLICY=$(pwpolicy -getaccountpolicies 2>/dev/null | tail -n +2)

    if [ -z "$PW_POLICY" ]; then
        RES="N"
        DESC="비밀번호 복잡성 정책이 설정되지 않음"
        DT="pwpolicy 출력: 정책 없음"
    else
        HAS_COMPLEXITY=0
        DETAILS=""

        # minChars 확인 (8자 이상)
        MIN_CHARS=$(echo "$PW_POLICY" | grep -A1 "minChars" | grep "<integer>" | sed 's/[^0-9]//g')
        if [ -n "$MIN_CHARS" ]; then
            DETAILS="${DETAILS}최소 길이: ${MIN_CHARS}자\n"
            if [ "$MIN_CHARS" -ge 8 ] 2>/dev/null; then
                HAS_COMPLEXITY=1
            fi
        fi

        # policyAttributePassword (복잡성 정규식) 확인
        COMPLEXITY_REGEX=$(echo "$PW_POLICY" | grep -c "policyAttributePassword")
        if [ "$COMPLEXITY_REGEX" -gt 0 ]; then
            DETAILS="${DETAILS}비밀번호 복잡성 정규식 정책 존재\n"
            HAS_COMPLEXITY=1
        fi

        # requiresAlpha 확인
        REQUIRES_ALPHA=$(echo "$PW_POLICY" | grep -c "requiresAlpha")
        if [ "$REQUIRES_ALPHA" -gt 0 ]; then
            DETAILS="${DETAILS}영문자 포함 요구\n"
            HAS_COMPLEXITY=1
        fi

        # requiresNumeric 확인
        REQUIRES_NUMERIC=$(echo "$PW_POLICY" | grep -c "requiresNumeric")
        if [ "$REQUIRES_NUMERIC" -gt 0 ]; then
            DETAILS="${DETAILS}숫자 포함 요구\n"
            HAS_COMPLEXITY=1
        fi

        if [ "$HAS_COMPLEXITY" -eq 1 ]; then
            RES="Y"
            DESC="비밀번호 복잡성 정책이 설정됨"
        else
            RES="N"
            DESC="비밀번호 복잡성 정책이 설정되지 않음"
        fi

        DT="pwpolicy 출력:\n${PW_POLICY}\n\n확인된 정책:\n${DETAILS:-없음}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check03() {
    local CODE="PC-03"
    local CAT="계정관리"
    local NAME="복구 콘솔에서 자동 로그온을 금지하도록 설정"
    local IMP="중"
    local STD="N/A - macOS에 해당 개념 없음 (Recovery Mode는 별도 인증 체계)"
    local RES=""
    local DESC=""
    local DT=""

    # 복구 콘솔 자동 로그온 - macOS 해당 없음
    RES="N/A"
    DESC="macOS 해당 없음 - Recovery Mode는 별도 인증 체계(Startup Security Utility, FileVault)로 관리"
    DT="macOS는 복구 콘솔 자동 로그온 개념 없음 — Startup Security Utility, FileVault로 대체"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check04() {
    local CODE="PC-04"
    local CAT="서비스관리"
    local NAME="공유 폴더 제거"
    local IMP="상"
    local STD="불필요한 공유 폴더가 존재하지 않거나 공유 폴더에 접근 권한이 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 공유 폴더 확인
    SHARE_LIST=$(sharing -l 2>/dev/null)

    if [ -z "$SHARE_LIST" ] || echo "$SHARE_LIST" | grep -q "no shared"; then
        RES="Y"
        DESC="공유 폴더가 존재하지 않음"
        DT="sharing -l 결과:\n${SHARE_LIST:-공유 없음}"
    else
        SHARE_COUNT=$(echo "$SHARE_LIST" | grep -c "name:")
        if [ "$SHARE_COUNT" -eq 0 ]; then
            RES="Y"
            DESC="공유 폴더가 존재하지 않음"
        else
            RES="N"
            DESC="공유 폴더 ${SHARE_COUNT}개 존재"
        fi
        DT="sharing -l 결과:\n${SHARE_LIST}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check05() {
    local CODE="PC-05"
    local CAT="서비스관리"
    local NAME="항목의 불필요한 서비스 제거"
    local IMP="상"
    local STD="일반적으로 불필요한 서비스(CIS Benchmark 기준)가 중지된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 불필요한 서비스 확인 (CIS Benchmark 기준)
    CIS_SERVICES="com.apple.screensharing com.apple.smbd com.apple.RemoteDesktop com.apple.AEServer com.apple.locate"

    ACTIVE_SERVICES=""
    for SVC in $CIS_SERVICES; do
        SVC_STATUS=$(launchctl print "system/${SVC}" 2>&1)
        SVC_EXIT=$?
        if [ $SVC_EXIT -eq 0 ]; then
            ACTIVE_SERVICES="${ACTIVE_SERVICES}${SVC} (활성)\n"
        fi
    done

    if [ -z "$ACTIVE_SERVICES" ]; then
        RES="Y"
        DESC="CIS 기준 불필요 서비스가 모두 비활성화 상태"
    else
        RES="N"
        DESC="CIS 기준 불필요 서비스가 활성화되어 있음"
    fi

    DT="CIS 기준 점검 서비스:\n${CIS_SERVICES}\n\n활성 서비스:\n${ACTIVE_SERVICES:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check06() {
    local CODE="PC-06"
    local CAT="서비스관리"
    local NAME="비인가 상용 메신저 사용 금지"
    local IMP="상"
    local STD="비인가 상용 메신저가 설치되지 않은 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 비인가 상용 메신저 설치 확인
    MSGR_PATTERN="(kakao|line|telegram|discord|slack|wechat|messenger|whatsapp|signal|skype)"

    MSGR_LIST=""
    if [ -d "/Applications" ]; then
        MSGR_LIST=$(ls /Applications/ 2>/dev/null | grep -iE "$MSGR_PATTERN")
    fi

    MSGR_USER=""
    for USER_HOME in /Users/*/Applications; do
        if [ -d "$USER_HOME" ]; then
            FOUND=$(ls "$USER_HOME/" 2>/dev/null | grep -iE "$MSGR_PATTERN")
            if [ -n "$FOUND" ]; then
                MSGR_USER="${MSGR_USER}${USER_HOME}:\n${FOUND}\n"
            fi
        fi
    done

    ALL_MSGR=""
    if [ -n "$MSGR_LIST" ]; then
        ALL_MSGR="/Applications:\n${MSGR_LIST}"
    fi
    if [ -n "$MSGR_USER" ]; then
        ALL_MSGR="${ALL_MSGR}\n${MSGR_USER}"
    fi

    RES="M"
    DESC="설치된 메신저 목록 수동 확인 필요"
    DT="발견된 메신저:\n${ALL_MSGR:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check07() {
    local CODE="PC-07"
    local CAT="서비스관리"
    local NAME="파일 시스템이 NTFS 포맷으로 설정"
    local IMP="중"
    local STD="모든 디스크 볼륨의 파일 시스템이 보안 기능을 지원하는 포맷(APFS/HFS+)인 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 파일 시스템 보안 포맷 확인 (APFS/HFS+)
    DISK_INFO=$(diskutil info -all 2>/dev/null | grep -E "(File System Personality|Volume Name|Mount Point)")

    UNSAFE_FS=""
    while IFS= read -r line; do
        if echo "$line" | grep -qi "File System Personality"; then
            FS_TYPE=$(echo "$line" | awk -F: '{print $2}' | xargs)
            if echo "$FS_TYPE" | grep -qiE "(FAT|exFAT)"; then
                UNSAFE_FS="${UNSAFE_FS}${FS_TYPE}\n"
            fi
        fi
    done <<< "$DISK_INFO"

    if [ -z "$UNSAFE_FS" ]; then
        RES="Y"
        DESC="모든 볼륨이 보안 파일 시스템(APFS/HFS+) 사용"
    else
        RES="N"
        DESC="보안 미지원 파일 시스템(FAT32/exFAT) 볼륨 존재"
    fi

    DT="디스크 정보:\n${DISK_INFO}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check08() {
    local CODE="PC-08"
    local CAT="서비스관리"
    local NAME="대상 시스템이 Windows 서버를 제외한 다른 OS로 멀티 부팅이 가능하지 않도록 설정"
    local IMP="중"
    local STD="N/A - Apple Silicon(M1+)은 Boot Camp 미지원으로 멀티부팅 불가"
    local RES=""
    local DESC=""
    local DT=""

    # 멀티 부팅 방지 - Apple Silicon은 Boot Camp 미지원
    RES="N/A"
    DESC="macOS 해당 없음 - Apple Silicon(M1+)은 Boot Camp 미지원으로 네이티브 멀티부팅 불가"
    DT="Apple Silicon(M1+)은 Boot Camp 미지원, 네이티브 멀티부팅 불가"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check09() {
    local CODE="PC-09"
    local CAT="서비스관리"
    local NAME="브라우저 종료 시 임시 인터넷 파일 폴더의 내용을 삭제하도록 설정"
    local IMP="하"
    local STD="N/A - macOS는 브라우저별 개별 설정으로 통합 점검 불가"
    local RES=""
    local DESC=""
    local DT=""

    # 브라우저 임시파일 삭제 - macOS 해당 없음
    RES="N/A"
    DESC="macOS 해당 없음 - 브라우저별 개별 설정으로 통합 점검 불가"
    DT="macOS Safari는 브라우저 종료 시 임시파일 자동 삭제 설정 없음"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check10() {
    local CODE="PC-10"
    local CAT="패치관리"
    local NAME="주기적 보안 패치 및 벤더 권고사항 적용"
    local IMP="상"
    local STD="소프트웨어 업데이트가 적용되어 있고 자동 업데이트가 설정된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 보안 패치 적용 및 자동 업데이트 확인

    # softwareupdate with timeout (macOS에 timeout 명령 없으므로 백그라운드 처리)
    UPDATE_LIST=""
    UPDATE_EXIT=0
    softwareupdate -l > /tmp/.seedgen_swupdate 2>&1 &
    SW_PID=$!
    SW_WAIT=0
    while kill -0 "$SW_PID" 2>/dev/null; do
        sleep 1
        SW_WAIT=$((SW_WAIT + 1))
        if [ $SW_WAIT -ge 30 ]; then
            kill "$SW_PID" 2>/dev/null
            wait "$SW_PID" 2>/dev/null
            UPDATE_EXIT=124
            break
        fi
    done
    if [ $UPDATE_EXIT -ne 124 ]; then
        wait "$SW_PID" 2>/dev/null
    fi
    UPDATE_LIST=$(cat /tmp/.seedgen_swupdate 2>/dev/null)
    rm -f /tmp/.seedgen_swupdate

    AUTO_CHECK=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
    AUTO_DOWNLOAD=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
    AUTO_INSTALL=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
    AUTO_APP=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)

    # softwareupdate 타임아웃 처리
    if [ $UPDATE_EXIT -eq 124 ]; then
        RES="M"
        DESC="소프트웨어 업데이트 확인 시간 초과 (네트워크 확인 필요)"
        DT="softwareupdate 타임아웃 (30초)\nAutomaticCheckEnabled: ${AUTO_CHECK:-미설정}\nAutomaticDownload: ${AUTO_DOWNLOAD:-미설정}\nAutomaticallyInstallMacOSUpdates: ${AUTO_INSTALL:-미설정}\nAutoUpdate(App Store): ${AUTO_APP:-미설정}"
    else
        NO_UPDATE=0
        if echo "$UPDATE_LIST" | grep -qi "No new software available"; then
            NO_UPDATE=1
        fi

        AUTO_OK=0
        if [ "$AUTO_CHECK" = "1" ]; then
            AUTO_OK=1
        fi

        if [ $NO_UPDATE -eq 1 ] && [ $AUTO_OK -eq 1 ]; then
            RES="Y"
            DESC="보안 패치 적용 완료 및 자동 업데이트 활성화"
        elif [ $NO_UPDATE -eq 0 ]; then
            RES="N"
            DESC="미적용 소프트웨어 업데이트 존재"
        else
            RES="N"
            DESC="자동 업데이트가 비활성화되어 있음"
        fi

        DT="softwareupdate -l:\n${UPDATE_LIST}\n\nAutomaticCheckEnabled: ${AUTO_CHECK:-미설정}\nAutomaticDownload: ${AUTO_DOWNLOAD:-미설정}\nAutomaticallyInstallMacOSUpdates: ${AUTO_INSTALL:-미설정}\nAutoUpdate(App Store): ${AUTO_APP:-미설정}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check11() {
    local CODE="PC-11"
    local CAT="패치관리"
    local NAME="지원이 종료되지 않은 Windows OS Build 적용"
    local IMP="상"
    local STD="적용 가능한 시스템 업데이트가 없고 최신 상태인 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 지원 OS 빌드 확인 (sw_vers + softwareupdate)
    OS_PRODUCT=$(sw_vers -productName 2>/dev/null)
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null)
    OS_BUILD=$(sw_vers -buildVersion 2>/dev/null)

    # softwareupdate with timeout (macOS에 timeout 명령 없으므로 백그라운드 처리)
    UPDATE_LIST=""
    UPDATE_EXIT=0
    softwareupdate -l > /tmp/.seedgen_swupdate11 2>&1 &
    SW_PID=$!
    SW_WAIT=0
    while kill -0 "$SW_PID" 2>/dev/null; do
        sleep 1
        SW_WAIT=$((SW_WAIT + 1))
        if [ $SW_WAIT -ge 30 ]; then
            kill "$SW_PID" 2>/dev/null
            wait "$SW_PID" 2>/dev/null
            UPDATE_EXIT=124
            break
        fi
    done
    if [ $UPDATE_EXIT -ne 124 ]; then
        wait "$SW_PID" 2>/dev/null
    fi
    UPDATE_LIST=$(cat /tmp/.seedgen_swupdate11 2>/dev/null)
    rm -f /tmp/.seedgen_swupdate11

    if [ $UPDATE_EXIT -eq 124 ]; then
        RES="M"
        DESC="소프트웨어 업데이트 확인 시간 초과 (네트워크 확인 필요)"
        DT="${OS_PRODUCT} ${OS_VERSION} (${OS_BUILD})\nsoftwareupdate 타임아웃 (30초)"
    else
        # macOS 시스템 업데이트 존재 여부 확인
        MACOS_UPDATE=$(echo "$UPDATE_LIST" | grep -i "macOS")

        if [ -z "$MACOS_UPDATE" ] || echo "$UPDATE_LIST" | grep -qi "No new software available"; then
            RES="Y"
            DESC="최신 macOS 빌드 적용 상태 (${OS_VERSION})"
        else
            RES="N"
            DESC="적용 가능한 macOS 업데이트 존재"
        fi

        DT="${OS_PRODUCT} ${OS_VERSION} (Build: ${OS_BUILD})\n\nsoftwareupdate -l:\n${UPDATE_LIST}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check12() {
    local CODE="PC-12"
    local CAT="보안관리"
    local NAME="Windows 자동 로그인 점검"
    local IMP="중"
    local STD="자동 로그인이 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 자동 로그인 설정 점검
    AUTO_LOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1)
    AUTO_LOGIN_EXIT=$?

    if [ $AUTO_LOGIN_EXIT -ne 0 ] || echo "$AUTO_LOGIN" | grep -q "does not exist"; then
        RES="Y"
        DESC="자동 로그인 비활성화 상태"
        DT="autoLoginUser: 설정되지 않음"
    else
        RES="N"
        DESC="자동 로그인이 활성화되어 있음"
        DT="autoLoginUser: ${AUTO_LOGIN}"
    fi

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check13() {
    local CODE="PC-13"
    local CAT="보안관리"
    local NAME="바이러스 백신 프로그램 설치 및 주기적 업데이트"
    local IMP="상"
    local STD="XProtect/Gatekeeper가 활성화되어 있고, 3rd party 백신 설치 시 최신 업데이트가 적용된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 멀웨어 차단 기능 확인 (XProtect, Gatekeeper, 3rd party)

    # Gatekeeper 상태
    GK_STATUS=$(spctl --status 2>&1)

    # XProtect 버전
    XPROTECT_VER=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)
    XPROTECT_EXISTS=0
    if [ -d "/Library/Apple/System/Library/CoreServices/XProtect.bundle" ]; then
        XPROTECT_EXISTS=1
    fi

    # MRT 버전
    MRT_VER=$(defaults read /Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)

    # XProtect 업데이트 이력
    XPROTECT_HISTORY=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A3 "XProtect" | head -20)

    # 3rd party 백신
    AV_PATTERN="(norton|kaspersky|avast|avg|bitdefender|crowdstrike|sophos|malwarebytes|eset|mcafee|trend)"
    AV_LIST=$(ls /Applications/ 2>/dev/null | grep -iE "$AV_PATTERN")

    GK_ENABLED=0
    if echo "$GK_STATUS" | grep -qi "assessments enabled"; then
        GK_ENABLED=1
    fi

    if [ $GK_ENABLED -eq 1 ] && [ $XPROTECT_EXISTS -eq 1 ]; then
        RES="Y"
        DESC="Gatekeeper 활성 및 XProtect 설치 확인"
    elif [ $GK_ENABLED -eq 0 ]; then
        RES="N"
        DESC="Gatekeeper가 비활성화되어 있음"
    elif [ $XPROTECT_EXISTS -eq 0 ] && [ -n "$AV_LIST" ]; then
        RES="M"
        DESC="XProtect 미확인, 3rd party 백신 존재 - 수동 확인 필요"
    else
        RES="N"
        DESC="멀웨어 차단 기능 미확인"
    fi

    DT="Gatekeeper: ${GK_STATUS}\nXProtect 버전: ${XPROTECT_VER:-미확인}\nXProtect 존재: ${XPROTECT_EXISTS}\nMRT 버전: ${MRT_VER:-미확인}\nXProtect 이력:\n${XPROTECT_HISTORY:-없음}\n3rd party 백신:\n${AV_LIST:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check14() {
    local CODE="PC-14"
    local CAT="보안관리"
    local NAME="바이러스 백신 프로그램에서 제공하는 실시간 감시 기능 활성화"
    local IMP="상"
    local STD="Gatekeeper 및 XProtect가 활성화되어 실시간 보호가 동작하는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 멀웨어 실시간 감시 기능 확인 (Gatekeeper, XProtect)

    # Gatekeeper 상태 (실시간 코드 서명 검증)
    GK_STATUS=$(spctl --status 2>&1)

    # XProtect 번들 존재 확인 (상시 동작, 별도 on/off 없음)
    XPROTECT_EXISTS=0
    if [ -d "/Library/Apple/System/Library/CoreServices/XProtect.bundle" ]; then
        XPROTECT_EXISTS=1
    fi

    # 3rd party 백신 (참고용)
    AV_PATTERN="(norton|kaspersky|avast|avg|bitdefender|crowdstrike|sophos|malwarebytes|eset|mcafee|trend)"
    AV_LIST=$(ls /Applications/ 2>/dev/null | grep -iE "$AV_PATTERN")

    GK_ENABLED=0
    if echo "$GK_STATUS" | grep -qi "assessments enabled"; then
        GK_ENABLED=1
    fi

    if [ $GK_ENABLED -eq 1 ] && [ $XPROTECT_EXISTS -eq 1 ]; then
        RES="Y"
        DESC="Gatekeeper 활성 및 XProtect 실시간 보호 동작 중"
    elif [ $GK_ENABLED -eq 0 ] && [ -n "$AV_LIST" ]; then
        RES="M"
        DESC="macOS 기본 보호 비활성, 3rd party 백신 존재 - 수동 확인 필요"
    elif [ $GK_ENABLED -eq 0 ]; then
        RES="N"
        DESC="Gatekeeper가 비활성화되어 실시간 보호 미동작"
    else
        RES="N"
        DESC="실시간 멀웨어 감시 기능 미확인"
    fi

    DT="Gatekeeper: ${GK_STATUS}\nXProtect 번들 존재: ${XPROTECT_EXISTS}\n3rd party 백신:\n${AV_LIST:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check15() {
    local CODE="PC-15"
    local CAT="보안관리"
    local NAME="OS에서 제공하는 침입차단 기능 활성화"
    local IMP="상"
    local STD="macOS 방화벽이 활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # macOS 방화벽 활성화 확인
    FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1)
    FW_STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1)

    if echo "$FW_STATE" | grep -qi "enabled"; then
        RES="Y"
        DESC="macOS 방화벽 활성화 상태"
    else
        RES="N"
        DESC="macOS 방화벽이 비활성화되어 있음"
    fi

    DT="방화벽 상태: ${FW_STATE}\n스텔스 모드: ${FW_STEALTH}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check16() {
    local CODE="PC-16"
    local CAT="보안관리"
    local NAME="화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설정"
    local IMP="상"
    local STD="화면 잠금 대기 시간이 10분 이하이고 잠금 해제 시 암호가 요구되는 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 화면 잠금 대기 시간 및 암호 보호 확인

    # sudo 실행 시 실제 로그인 사용자의 도메인을 읽기 위해 SUDO_USER 활용
    REAL_USER="${SUDO_USER:-$(whoami)}"

    IDLE_TIME=$(sudo -u "$REAL_USER" defaults read com.apple.screensaver idleTime 2>/dev/null)
    IDLE_TIME_SYS=$(defaults read /Library/Preferences/com.apple.screensaver idleTime 2>/dev/null)
    ASK_PWD=$(sudo -u "$REAL_USER" defaults read com.apple.screensaver askForPassword 2>/dev/null)
    ASK_DELAY=$(sudo -u "$REAL_USER" defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)

    # 사용자 레벨 우선, 없으면 시스템 레벨
    EFFECTIVE_IDLE=""
    if [ -n "$IDLE_TIME" ]; then
        EFFECTIVE_IDLE="$IDLE_TIME"
    elif [ -n "$IDLE_TIME_SYS" ]; then
        EFFECTIVE_IDLE="$IDLE_TIME_SYS"
    fi

    ISSUES=""

    # 대기 시간 확인 (600초 = 10분 이하)
    if [ -z "$EFFECTIVE_IDLE" ]; then
        ISSUES="${ISSUES}화면보호기 대기 시간 미설정\n"
    elif [ "$EFFECTIVE_IDLE" -gt 600 ] 2>/dev/null; then
        ISSUES="${ISSUES}화면보호기 대기 시간 초과 (현재: ${EFFECTIVE_IDLE}초, 기준: 600초 이하)\n"
    fi

    # 암호 보호 확인
    if [ "$ASK_PWD" != "1" ]; then
        ISSUES="${ISSUES}화면 잠금 해제 시 암호 요구 비활성화\n"
    fi

    # 암호 요구 지연 확인 (0이어야 즉시 잠금)
    if [ -n "$ASK_DELAY" ] && [ "$ASK_DELAY" != "0" ]; then
        ISSUES="${ISSUES}암호 요구 지연 시간 존재 (현재: ${ASK_DELAY}초, 기준: 0초)\n"
    fi

    if [ -z "$ISSUES" ]; then
        RES="Y"
        DESC="화면 잠금 대기 시간 및 암호 보호가 적절히 설정됨"
    else
        RES="N"
        DESC="화면 잠금 설정이 기준에 미달"
    fi

    DT="대상 사용자: ${REAL_USER}\nidleTime(사용자): ${IDLE_TIME:-미설정}\nidleTime(시스템): ${IDLE_TIME_SYS:-미설정}\naskForPassword: ${ASK_PWD:-미설정}\naskForPasswordDelay: ${ASK_DELAY:-미설정}\n문제:\n${ISSUES:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check17() {
    local CODE="PC-17"
    local CAT="보안관리"
    local NAME="CD, DVD, USB 메모리 등과 같은 미디어의 자동 실행 방지 등 이동식 미디어에 대한 보안대책 수립"
    local IMP="상"
    local STD="N/A - macOS는 이동식 미디어 자동 실행 기능이 없음 (기본 양호)"
    local RES=""
    local DESC=""
    local DT=""

    # 이동식 미디어 자동 실행 방지 - macOS 해당 없음
    RES="N/A"
    DESC="macOS 해당 없음 - macOS는 이동식 미디어 자동 실행(AutoRun) 기능이 OS 레벨에서 존재하지 않음"
    DT="macOS는 이동식 미디어 자동 실행(AutoRun) 기능이 OS 수준에서 존재하지 않음"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}

check18() {
    local CODE="PC-18"
    local CAT="보안관리"
    local NAME="원격 지원을 금지하도록 정책이 설정"
    local IMP="중"
    local STD="SSH, Apple Remote Desktop, 화면 공유가 모두 비활성화된 경우"
    local RES=""
    local DESC=""
    local DT=""

    # 원격 지원 금지 확인 (SSH, ARD, 화면 공유)
    REMOTE_ISSUES=""

    # SSH (Remote Login)
    SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null)
    if echo "$SSH_STATUS" | grep -qi "on"; then
        REMOTE_ISSUES="${REMOTE_ISSUES}SSH(Remote Login) 활성화\n"
    fi

    # 화면 공유 / Apple Remote Desktop
    SCREEN_SHARING=$(launchctl print system/com.apple.screensharing 2>&1)
    SCREEN_EXIT=$?
    if [ $SCREEN_EXIT -eq 0 ]; then
        REMOTE_ISSUES="${REMOTE_ISSUES}화면 공유(Screen Sharing) 활성화\n"
    fi

    # ARD 추가 확인
    ARD_STATUS=$(defaults read /Library/Preferences/com.apple.RemoteDesktop.plist 2>&1)
    ARD_EXIT=$?
    if [ $ARD_EXIT -eq 0 ] && ! echo "$ARD_STATUS" | grep -q "does not exist"; then
        REMOTE_ISSUES="${REMOTE_ISSUES}Apple Remote Desktop 설정 존재\n"
    fi

    if [ -z "$REMOTE_ISSUES" ]; then
        RES="Y"
        DESC="원격 접속 서비스(SSH, ARD, 화면 공유) 모두 비활성화 상태"
    else
        RES="N"
        DESC="원격 접속 서비스가 활성화되어 있음"
    fi

    DT="SSH: ${SSH_STATUS:-확인 불가}\n화면 공유 launchctl: 종료코드=${SCREEN_EXIT}\nARD: 종료코드=${ARD_EXIT}\n활성 항목:\n${REMOTE_ISSUES:-없음}"

    output_checkpoint "$CODE" "$CAT" "$NAME" "$IMP" "$STD" "$RES" "$DESC" "$DT"
}


#================================================================
# EXECUTE
#================================================================

echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  부서: $USER_DEPT"
echo "  │  사용자: $USER_NAME"
echo "  │  호스트: $SYS_HOST"
echo "  │  OS: $SYS_OS_FN"
echo "  │  아키텍처: $SYS_ARCH"
echo "  │  기준: $META_STD"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
echo "  [진단 시작]"
echo "  ─────────────────────────────────────────────────────────"
echo ""

# XML 헤더
cat > "$OUTPUT_FILE" << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<seedgen>
    <meta>
        <date>$META_DATE</date>
        <ver>$META_VER</ver>
        <plat>$META_PLAT</plat>
        <type>$META_TYPE</type>
        <std>$META_STD</std>
        <user>
            <dept>$USER_DEPT</dept>
            <name>$USER_NAME</name>
        </user>
    </meta>
    <sys>
        <host>$SYS_HOST</host>
        <dom>$SYS_DOM</dom>
        <os>
            <n>$SYS_OS_NAME</n>
            <fn>$SYS_OS_FN</fn>
        </os>
        <kn>$SYS_KN</kn>
        <arch>$SYS_ARCH</arch>
        <net>
            <ip>$SYS_IP</ip>
            <all><![CDATA[$SYS_NET_ALL]]></all>
        </net>
    </sys>
    <results>
XMLEOF

# 진단 실행
    check01
    check02
    check03
    check04
    check05
    check06
    check07
    check08
    check09
    check10
    check11
    check12
    check13
    check14
    check15
    check16
    check17
    check18

# XML 종료
cat >> "$OUTPUT_FILE" << XMLEOF
    </results>
</seedgen>
XMLEOF

#================================================================
# CLEANUP
#================================================================
echo ""
echo "  ─────────────────────────────────────────────────────────"
echo ""
echo "  점검이 완료되었습니다!"
echo "  호스트: $SYS_HOST"
echo "  결과 파일: $OUTPUT_FILE"
echo ""
